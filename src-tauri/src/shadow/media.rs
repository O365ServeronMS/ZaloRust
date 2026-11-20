//! P1b media auto-download (D8/D11, rebuild 2026-11-19).
//!
//! Rules (handoff + audit H3/T3, M1/B3/B4 batch 2):
//! - Only NEW media (attachments rows with status='ref' created by the
//!   writer from live traffic) — never a backfill scan of history.
//! - M1 SSRF guard: every url must pass [`host_allowed`] BEFORE any
//!   request (https + CDN host allowlist, no userinfo/IP/non-default
//!   ports). Automatic redirects are DISABLED (`max_redirects(0)`);
//!   each hop is resolved and re-checked manually, at most 3.
//! - B4 hygiene: the temp file is guarded (removed on EVERY error
//!   path); image/video bytes are magic-sniffed — a mismatch stores
//!   NOTHING and flips the row to `ref-encrypted` (KQ1: E2EE CDN
//!   bytes may be ciphertext).
//! - KQ9: `local_path` is stored RELATIVE to the media root
//!   (`ab/cd/<sha>`, forward slashes) so moving the root never breaks
//!   a row; [`resolve_local_path`] maps it back.
//! - Rate-limited: one download at a time, a pause between files.
//! - Content-addressed store: `<root>/ab/cd/<sha256>`; the file lands
//!   via a .tmp + rename so a partial download never masquerades as a
//!   good one.
//! - A5 single writer (T3): this thread opens a READ-ONLY connection to
//!   pick pending refs and reports every outcome back to the flusher
//!   through the job queue (`Job::MediaDone`); it never writes the DB
//!   itself.
//! - Rows whose outcome is still with the flusher are tracked in an
//!   in-memory set and stay in it until the flusher's transaction
//!   actually lands (F1): a slow flusher cannot cause a duplicate
//!   download, because the set is only pruned — by checking the DB —
//!   at the START of each cycle, never right after the send.
//! - Root resolution order: `settings.shadow.media_store`, else
//!   `D:\ZaloRust Data` when it exists (D11 decision for this install),
//!   else `<LOCALAPPDATA>\com.o365serveronms.zalors\ZaloRust Data`.
//! - Logs: counts/kinds only — never urls, file names or error text
//!   (H-rule; transport errors embed the request url).

use std::collections::HashSet;
use std::path::{Path, PathBuf};
use std::sync::mpsc::Sender;
use std::time::Duration;

use rusqlite::Connection;
use sha2::{Digest, Sha256};

use super::pipeline;
use super::runtime::Job;
use super::writer::MediaOutcome;
use crate::migrate::sqlcipher;
use crate::settings::ShadowSettings;

/// Why a download cycle ended early (beyond per-file outcomes).
#[derive(Debug)]
enum CycleError {
    Db(rusqlite::Error),
    /// The flusher receiver is gone (app shutdown): stop the thread.
    FlusherGone,
}

/// One cycle's outcome counts. These are DISJOINT categories (each
/// reported row lands in exactly one) and the only thing that ever
/// reaches a log line (H-rule: counts/kinds only — never urls, file
/// names or error text).
#[derive(Default)]
struct CycleCounts {
    ok: usize,
    failed: usize,
    /// M1: url rejected by the host allowlist BEFORE any request.
    blocked_host: usize,
    /// M1: redirect Location outside the allowlist (or over the hop cap).
    blocked_redirect: usize,
    /// B4/KQ1: bytes failed the magic sniff (kept nothing).
    ref_encrypted: usize,
}

impl CycleCounts {
    fn total(&self) -> usize {
        self.ok + self.failed + self.blocked_host + self.blocked_redirect + self.ref_encrypted
    }
}

/// Start the downloader thread (call once per process, after the DB
/// exists). `done` is the flusher's job queue: every download outcome is
/// reported through it. Best-effort: failures are retried next cycle.
/// Crate-internal: only `runtime::start` wires this up.
pub(crate) fn start(dir: PathBuf, cfg: ShadowSettings, done: Sender<Job>) {
    std::thread::Builder::new()
        .name("shadow-media".into())
        .spawn(move || {
            let root = media_store_root(&cfg);
            let _ = std::fs::create_dir_all(&root);
            crate::dlog::log(&format!("shadow media: store at {}", root.display()));
            // READ-ONLY connection (T3); reopen if it dies.
            let mut conn = open(&dir, &cfg);
            // Rows whose outcome is still in the flusher's queue/hands.
            let mut in_flight: HashSet<i64> = HashSet::new();
            let mut backoff = 30u64;
            // H3/D13 (batch 8): the last space verdict this thread
            // logged a transition for. `Ok` is the quiet initial state.
            let mut disk_state = super::disk_space::SpaceVerdict::Ok;
            loop {
                std::thread::sleep(Duration::from_secs(backoff.max(5)));
                if conn.is_none() {
                    conn = open(&dir, &cfg);
                    continue;
                }
                // H3/D13: check the store volume BEFORE each cycle. An
                // unmeasurable volume (API failure, non-Windows) maps to
                // Ok — downloads are never paused on missing data. The
                // bytes themselves never enter a log line.
                let verdict = super::disk_space::disk_free_space(&root)
                    .map(|(free, total)| {
                        super::disk_space::space_verdict(
                            free,
                            total,
                            cfg.disk_warn_pct,
                            cfg.disk_stop_pct,
                        )
                    })
                    .unwrap_or(super::disk_space::SpaceVerdict::Ok);
                if let Some(line) = super::disk_space::transition_log(disk_state, verdict) {
                    crate::dlog::log(line);
                }
                disk_state = verdict;
                if verdict == super::disk_space::SpaceVerdict::Stop {
                    // 4.3 AC: skip the cycle — rows stay 'ref', nothing
                    // is marked failed, text capture (the flusher) is
                    // never affected. Re-checked every cycle.
                    continue;
                }
                let c = conn.as_ref().unwrap();
                match download_one_cycle(c, &root, &done, &mut in_flight) {
                    Ok(counts) if counts.total() == 0 => backoff = 30,
                    Ok(counts) => {
                        backoff = 10;
                        // Counts only (H-rule): no urls, no error text.
                        crate::dlog::log(&format!(
                            "shadow media: cycle reported ok={} failed={} blocked_host={} blocked_redirect={} ref_encrypted={}",
                            counts.ok,
                            counts.failed,
                            counts.blocked_host,
                            counts.blocked_redirect,
                            counts.ref_encrypted
                        ));
                    }
                    Err(CycleError::Db(e)) => {
                        // Log the error KIND only: sqlite messages can
                        // quote SQL/params.
                        crate::dlog::log(&format!(
                            "shadow media: DB error ({}), reopening",
                            pipeline::sqlite_kind(&e)
                        ));
                        conn = None;
                    }
                    Err(CycleError::FlusherGone) => {
                        // Flusher exited (shutdown): stop. Pending rows
                        // keep status='ref' and resume on the next launch.
                        crate::dlog::log("shadow media: flusher gone, stopping");
                        break;
                    }
                }
            }
        })
        .ok();
}

/// READ-ONLY open (T3: the media thread never writes; the flusher owns
/// every write). Both paths set the H3 busy timeout.
fn open(dir: &Path, cfg: &ShadowSettings) -> Option<Connection> {
    // KQ10: the account helpers name the store files.
    let db_path = super::db_file(dir);
    let key_path = super::key_file(dir);
    if !cfg.encrypt {
        let conn = rusqlite::Connection::open_with_flags(
            &db_path,
            rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY,
        )
        .ok()?;
        conn.busy_timeout(Duration::from_millis(sqlcipher::BUSY_TIMEOUT_MS)).ok()?;
        return Some(conn);
    }
    let Ok(key) = sqlcipher::load_key(&key_path) else {
        return None;
    };
    // L4/D4: the loaded key bytes are wiped once the connection holds
    // them (SQLCipher keeps its own copy; this Vec must not linger).
    let key = zeroize::Zeroizing::new(key);
    // Sets busy_timeout (T1) and query_only.
    sqlcipher::open_with_key_readonly(&db_path, &key).ok()
}

/// Cap for the in-flight set (F1): a flusher stuck for hours must not
/// grow the set without bound. Past the cap the set is dropped
/// wholesale — those rows still read `status='ref'` and are simply
/// re-picked (at worst re-downloaded) by a later cycle.
const IN_FLIGHT_CAP: usize = 1024;

/// F1: drop ids whose row is no longer `status='ref'` — the flusher has
/// applied their outcome (or the row is gone), so they are safe to
/// select again. Ids still `ref` STAY in flight: their outcome is
/// queued but has not landed yet, so re-selecting one would download
/// the same url a second time.
///
/// One query; the `IN (...)` list is built from `i64::to_string()`
/// (pure digits), so there is no quoting or injection surface.
fn prune_in_flight(conn: &Connection, in_flight: &mut HashSet<i64>) -> rusqlite::Result<()> {
    if in_flight.is_empty() {
        return Ok(());
    }
    if in_flight.len() > IN_FLIGHT_CAP {
        in_flight.clear();
        return Ok(());
    }
    let ids = in_flight
        .iter()
        .map(|id| id.to_string())
        .collect::<Vec<_>>()
        .join(",");
    let mut still_ref = HashSet::with_capacity(in_flight.len());
    {
        let mut st = conn.prepare(&format!(
            "SELECT rowid FROM attachments WHERE status = 'ref' AND rowid IN ({ids})"
        ))?;
        let rows = st.query_map([], |r| r.get::<_, i64>(0))?;
        for id in rows {
            still_ref.insert(id?);
        }
    }
    in_flight.retain(|id| still_ref.contains(id));
    Ok(())
}

/// Resolve the media store root (documented order, see module docs).
pub fn media_store_root(cfg: &ShadowSettings) -> PathBuf {
    if let Some(p) = &cfg.media_store {
        return PathBuf::from(p);
    }
    let d = PathBuf::from("D:\\ZaloRust Data");
    if d.is_dir() {
        return d;
    }
    let local = std::env::var_os("LOCALAPPDATA").unwrap_or_default();
    PathBuf::from(local)
        .join("com.o365serveronms.zalors")
        .join("ZaloRust Data")
}

/// One cycle: pick pending refs (oldest first, skipping rows whose
/// outcome is still in flight), download up to a small cap, report each
/// outcome to the flusher. The counts are disjoint categories (see
/// [`CycleCounts`]).
///
/// F1: an id stays in `in_flight` after its outcome is sent — the
/// flusher applies it up to `batch_ms` later, in a different
/// connection's transaction, and until then the row still reads
/// `status='ref'`. Only `prune_in_flight` (start of the next cycle)
/// drops ids whose outcome has actually landed.
fn download_one_cycle(
    conn: &Connection,
    root: &Path,
    done: &Sender<Job>,
    in_flight: &mut HashSet<i64>,
) -> Result<CycleCounts, CycleError> {
    let cap = 8usize;
    // F1: first drop the ids the flusher has already applied (row no
    // longer 'ref'); the rest must not be re-picked this cycle.
    prune_in_flight(conn, in_flight).map_err(CycleError::Db)?;
    let mut st = conn
        .prepare(
            "SELECT rowid, kind, url FROM attachments \
             WHERE status = 'ref' AND url IS NOT NULL AND url LIKE 'https://%' \
             ORDER BY rowid LIMIT ?1",
        )
        .map_err(CycleError::Db)?;
    let rows: Vec<(i64, Option<String>, String)> = st
        .query_map([cap as i64], |r| {
            Ok((r.get(0)?, r.get(1)?, r.get(2)?))
        })
        .map_err(CycleError::Db)?
        .filter_map(Result::ok)
        // Never re-select a row whose outcome the flusher has not
        // applied yet (it still reads status='ref' until then).
        .filter(|(rowid, _, _)| !in_flight.contains(rowid))
        .collect();
    drop(st);
    let mut counts = CycleCounts::default();
    for (rowid, kind, url) in rows {
        in_flight.insert(rowid);
        // M1: allowlist BEFORE any request — a rejected url costs no
        // network I/O at all and is reported Failed to the flusher.
        let outcome = if !host_allowed(&url) {
            counts.blocked_host += 1;
            MediaOutcome::Failed
        } else {
            match fetch_to_store(&url, root, kind.as_deref()) {
                FetchOutcome::Downloaded { rel, sha, size } => {
                    counts.ok += 1;
                    MediaOutcome::Downloaded { path: rel, sha256: sha, size: size as i64 }
                }
                FetchOutcome::RefEncrypted => {
                    counts.ref_encrypted += 1;
                    MediaOutcome::RefEncrypted
                }
                FetchOutcome::BlockedHost => {
                    counts.blocked_host += 1;
                    MediaOutcome::Failed
                }
                FetchOutcome::BlockedRedirect => {
                    counts.blocked_redirect += 1;
                    MediaOutcome::Failed
                }
                FetchOutcome::Failed => {
                    counts.failed += 1;
                    MediaOutcome::Failed
                }
            }
        };
        if done.send(Job::MediaDone { rowid, outcome }).is_err() {
            // Receiver dropped (shutdown): stop the thread. The row
            // stays 'ref' — it is retried on the next launch.
            return Err(CycleError::FlusherGone);
        }
        // F1: the id STAYS in `in_flight` — the flusher applies this
        // outcome in its own transaction up to `batch_ms` later, and
        // until that lands the row still reads 'ref'. Removing it here
        // would let the next cycle SELECT the same row and download it
        // twice; `prune_in_flight` drops it once the outcome landed.
        std::thread::sleep(Duration::from_millis(700));
    }
    Ok(counts)
}

/// M1 allowlist: the media hosts this build may ever contact (audit
/// §2-H1 hosts + audit M1 confirmation). A host qualifies only when it
/// ENDS with one of these on a dot boundary.
const ALLOWED_HOST_SUFFIXES: &[&str] = &[".zdn.vn", ".zadn.vn", ".dlmd.me", ".dlfl.vn"];

/// M1 SSRF guard, checked BEFORE any request (the `url` crate is not
/// a direct dependency — careful manual parsing instead):
/// - the scheme must be `https`;
/// - the whole url must carry NO backslash, ASCII control char or
///   whitespace (R1, batch 3: a WHATWG-style parser treats `\` as `/`,
///   so `https://evil.com\.zdn.vn/x` is really host `evil.com`; the
///   others are the same class of delimiter smuggle);
/// - the host must end with an allowed suffix on a dot boundary
///   (`evil-zdn.vn`, `zdn.vn.evil.com`, `.zdnn.vn` all fail; an apex
///   `zdn.vn` fails too — every real CDN host is a subdomain);
/// - after lowercasing, the host must be plain DNS labels only —
///   `^[a-z0-9.-]+$`, no empty label (`..`), no leading/trailing `-`
///   per label (R1: `%`-encoded or `_`-bearing hosts are parser-
///   confusion vectors, and no real CDN host looks like that);
/// - the authority must carry NO userinfo (`@`), NO IP literal (dotted
///   digits, `[`/`]`, `:`) and NO port other than the https default.
pub fn host_allowed(raw: &str) -> bool {
    // R1: reject delimiter smuggles anywhere in the url, not just in
    // the authority — the host boundary must be unambiguous.
    if raw
        .bytes()
        .any(|b| b == b'\\' || b.is_ascii_control() || b.is_ascii_whitespace())
    {
        return false;
    }
    let Some(rest) = raw.strip_prefix("https://") else {
        return false;
    };
    // The authority ends at the first path/query/fragment separator.
    let auth_end = rest.find(['/', '?', '#']).unwrap_or(rest.len());
    let authority = &rest[..auth_end];
    if authority.contains('@') {
        return false; // userinfo: https://user:pass@host/
    }
    // Split a trailing :port (digits only; anything else — e.g. an
    // IPv6 literal — fails the port shape and hits the bracket/colon
    // rejection below via the unsplit host).
    let (host, port) = match authority.rsplit_once(':') {
        Some((h, p)) if !p.is_empty() && p.bytes().all(|b| b.is_ascii_digit()) => (h, Some(p)),
        _ => (authority, None),
    };
    if port.is_some_and(|p| p != "443") {
        return false; // non-default port
    }
    if host.is_empty()
        || host.contains(':')
        || host.contains('[')
        || host.contains(']')
        // Every byte a digit or a dot => IPv4-style literal (a bare
        // number would be one too). Allowlisted CDN hosts are never IPs.
        || host.bytes().all(|b| b.is_ascii_digit() || b == b'.')
    {
        return false;
    }
    let host = host.to_ascii_lowercase();
    // R1: plain DNS shape only. `..` (empty label) is caught by the
    // split below together with leading/trailing dots (`a..zdn.vn`,
    // `.zdn.vn`, `zdn.vn.`), and a label may not start or end with
    // `-` (`-x.zdn.vn`, `x-.zdn.vn`). Anything outside
    // `[a-z0-9.-]` (`%`, `_`, unicode, …) is refused outright.
    if !host
        .bytes()
        .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'.' || b == b'-')
        || host
            .split('.')
            .any(|label| label.is_empty() || label.starts_with('-') || label.ends_with('-'))
    {
        return false;
    }
    ALLOWED_HOST_SUFFIXES.iter().any(|s| host.ends_with(s))
}

/// One manual redirect hop (M1, pure — no network):
/// - `None`: the status is not a 3xx, the response is final;
/// - `Some(Follow(url))`: the resolved Location stays inside the
///   allowlist (an absolute next url);
/// - `Some(Blocked)`: no Location, an unresolvable one, or a target
///   outside the allowlist.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RedirectHop {
    Follow(String),
    Blocked,
}

pub fn redirect_hop(status: u16, location: Option<&str>, base: &str) -> Option<RedirectHop> {
    if !(300..400).contains(&status) {
        return None;
    }
    let Some(next) = location.and_then(|l| resolve_location(base, l)) else {
        return Some(RedirectHop::Blocked);
    };
    if host_allowed(&next) {
        Some(RedirectHop::Follow(next))
    } else {
        Some(RedirectHop::Blocked)
    }
}

/// Resolve a redirect `Location` against the base url (manual, pure).
/// Absolute (`https://…` / `http://…`), scheme-relative (`//host/…`),
/// root-relative (`/path`) and path-relative forms are handled;
/// `http://` results are produced as-is so [`host_allowed`] rejects
/// the scheme hop explicitly. An empty or fragment-only location
/// resolves to nothing (blocked).
fn resolve_location(base: &str, loc: &str) -> Option<String> {
    let l = loc.trim();
    if l.is_empty() || l.starts_with('#') {
        return None;
    }
    if l.starts_with("https://") || l.starts_with("http://") {
        return Some(l.to_string());
    }
    if let Some(rest) = l.strip_prefix("//") {
        return Some(format!("https://{rest}"));
    }
    // The caller's base is allowlisted (https); reject anything else.
    let after = base.strip_prefix("https://")?;
    let auth_end = after.find(['/', '?', '#']).unwrap_or(after.len());
    let authority = &after[..auth_end];
    if let Some(path) = l.strip_prefix('/') {
        return Some(format!("https://{authority}/{path}"));
    }
    // Path-relative: resolve against the base's "directory".
    let base_path = &after[auth_end..];
    let dir = match base_path.rfind('/') {
        Some(i) => &base_path[..=i],
        None => "/",
    };
    Some(format!("https://{authority}{dir}{l}"))
}

/// Why a fetch ended without a downloaded file. The variants map 1:1
/// onto the cycle's disjoint counts (kinds only — never urls).
enum FetchOutcome {
    /// Stored: RELATIVE path `ab/cd/<sha>` (KQ9), sha hex, size.
    Downloaded { rel: String, sha: String, size: u64 },
    /// B4/KQ1: magic-byte mismatch — nothing kept, row flips to
    /// `ref-encrypted`.
    RefEncrypted,
    /// M1: outside the allowlist (defense in depth; the cycle
    /// pre-checks so this normally never fires).
    BlockedHost,
    /// M1: redirect outside the allowlist or past the hop cap.
    BlockedRedirect,
    /// Transport/IO failure (expired CDN urls are normal).
    Failed,
}

/// Follow at most this many redirect hops manually (B3/M1).
const MAX_REDIRECT_HOPS: u32 = 3;

/// GET the url into the content-addressed store (B3/B4). Redirects
/// are followed MANUALLY (the agent has them disabled,
/// `max_redirects(0)`, verified against the ureq 3.5.1 API): each
/// Location is resolved and re-checked against the allowlist, at most
/// [`MAX_REDIRECT_HOPS`] hops. Returns the RELATIVE store path
/// (`ab/cd/<sha>`), the sha and the size.
fn fetch_to_store(url: &str, root: &Path, kind: Option<&str>) -> FetchOutcome {
    // Defense in depth (the cycle already pre-checks): never open a
    // socket to a host outside the allowlist.
    if !host_allowed(url) {
        return FetchOutcome::BlockedHost;
    }
    let agent: ureq::Agent = ureq::Agent::config_builder()
        .timeout_connect(Some(Duration::from_secs(20)))
        .timeout_recv_response(Some(Duration::from_secs(30)))
        .timeout_recv_body(Some(Duration::from_secs(60)))
        // M1: no automatic redirects — every hop is a manual,
        // allowlist-checked decision.
        .max_redirects(0)
        .build()
        .into();
    let mut current = url.to_string();
    let mut hops = 0u32;
    loop {
        // Transport errors are reported as Failed; the error text is
        // deliberately NOT logged: it embeds the request URL (H-rule).
        let resp = match agent.get(&current).call() {
            Ok(r) => r,
            Err(_) => return FetchOutcome::Failed,
        };
        let status = resp.status().as_u16();
        let location = resp
            .headers()
            .get("location")
            .and_then(|v| v.to_str().ok());
        match redirect_hop(status, location, &current) {
            None => {
                // Final response: stream to the store (B4 hygiene,
                // KQ1 sniff).
                let reader = resp.into_body().into_reader();
                return match store_stream(reader, root, kind) {
                    Ok((rel, sha, size)) => {
                        FetchOutcome::Downloaded { rel, sha, size }
                    }
                    Err(StoreError::Sniff) => FetchOutcome::RefEncrypted,
                    Err(_) => FetchOutcome::Failed,
                };
            }
            // Follow the hop — unless the cap is spent (then it is a
            // Blocked outcome, same as an off-allowlist hop).
            Some(RedirectHop::Follow(next)) if hops < MAX_REDIRECT_HOPS => {
                hops += 1;
                current = next;
            }
            Some(_) => return FetchOutcome::BlockedRedirect,
        }
    }
}

/// B4/KQ1: why `store_stream` refused the bytes. `Sniff` maps to the
/// `ref-encrypted` outcome; the rest are plain failures.
#[derive(Debug)]
enum StoreError {
    /// Magic-byte mismatch on an image/video (B4): E2EE CDN bytes may
    /// be ciphertext — keep nothing.
    Sniff,
    Io(std::io::Error),
    Other(String),
}

impl std::fmt::Display for StoreError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            // Kind only — no file paths or urls in error text.
            StoreError::Sniff => write!(f, "sniff mismatch"),
            StoreError::Io(_) => write!(f, "io error"),
            StoreError::Other(m) => write!(f, "{m}"),
        }
    }
}

impl std::error::Error for StoreError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            StoreError::Io(e) => Some(e),
            _ => None,
        }
    }
}

/// B4: the `.dl-<pid>.tmp` file is ALWAYS removed on error paths —
/// `?`/`return` unwind through `Drop`. `disarm()` after a successful
/// rename (the path no longer exists).
struct TempGuard(PathBuf);

impl TempGuard {
    fn path(&self) -> &Path {
        &self.0
    }
    fn disarm(&mut self) {
        self.0 = PathBuf::new();
    }
}

impl Drop for TempGuard {
    fn drop(&mut self) {
        if !self.0.as_os_str().is_empty() {
            let _ = std::fs::remove_file(&self.0);
        }
    }
}

/// B4/KQ1: magic bytes of the first bytes. `image` must be JPEG
/// (`FF D8 FF`), PNG (`89 50 4E 47`), GIF (`47 49 46 38`) or WEBP
/// (`RIFF`…`WEBP` at offset 8); `video` must be MP4/MOV (`ftyp` at
/// offset 4) or WEBM (`1A 45 DF A3`). Files/voice and unknown kinds
/// are not sniffed (a mismatch there means nothing).
///
/// `pub(crate)`: the attachments probe (probe_attach, batch 5 E2)
/// reuses the SAME sniff to verify what the store already holds.
pub(crate) fn magic_ok(kind: Option<&str>, head: &[u8]) -> bool {
    match kind {
        Some("image") => {
            head.starts_with(&[0xFF, 0xD8, 0xFF])
                || head.starts_with(&[0x89, 0x50, 0x4E, 0x47])
                || head.starts_with(b"GIF8")
                || (head.starts_with(b"RIFF") && head.len() >= 12 && &head[8..12] == b"WEBP")
        }
        Some("video") => {
            (head.len() >= 8 && &head[4..8] == b"ftyp")
                || head.starts_with(&[0x1A, 0x45, 0xDF, 0xA3])
        }
        // file | voice | sticker | anything else: no sniff.
        _ => true,
    }
}

/// B4: stream `reader` into the content-addressed store. The temp
/// file is guarded (removed on EVERY error path), the 512 MB cap
/// holds mid-stream, and image/video bytes are magic-sniffed (KQ1) —
/// a mismatch stores nothing. Returns (RELATIVE path `ab/cd/<sha>` —
/// KQ9, forward slashes — sha hex, size). Pure w.r.t. the network:
/// any `impl Read` works, which is what the tests use.
fn store_stream(
    mut reader: impl std::io::Read,
    root: &Path,
    kind: Option<&str>,
) -> Result<(String, String, u64), StoreError> {
    let tmp = root.join(format!(".dl-{}.tmp", std::process::id()));
    let mut file = std::fs::File::create(&tmp).map_err(StoreError::Io)?;
    let mut guard = TempGuard(tmp);
    let mut hasher = Sha256::new();
    // Capture the first bytes for the magic sniff while streaming.
    let mut head = [0u8; 16];
    let mut head_len = 0usize;
    let mut buf = [0u8; 64 * 1024];
    let mut size: u64 = 0;
    loop {
        let n = reader.read(&mut buf).map_err(StoreError::Io)?;
        if n == 0 {
            break;
        }
        if head_len < head.len() {
            let take = (head.len() - head_len).min(n);
            head[head_len..head_len + take].copy_from_slice(&buf[..take]);
            head_len += take;
        }
        hasher.update(&buf[..n]);
        std::io::Write::write_all(&mut file, &buf[..n]).map_err(StoreError::Io)?;
        size += n as u64;
        if size > 512 * 1024 * 1024 {
            return Err(StoreError::Other("file exceeds 512 MB cap".into()));
        }
    }
    if !magic_ok(kind, &head[..head_len]) {
        // KQ1 fallback: E2EE CDN bytes may be ciphertext — do NOT keep
        // the file (the guard removes the temp).
        return Err(StoreError::Sniff);
    }
    drop(file); // close before the rename
    let sha = format!("{:x}", hasher.finalize());
    let rel = format!("{}/{}/{}", &sha[0..2], &sha[2..4], sha);
    let final_path = root.join(&rel);
    if let Some(dir) = final_path.parent() {
        std::fs::create_dir_all(dir).map_err(StoreError::Io)?;
    }
    match std::fs::rename(guard.path(), &final_path) {
        Ok(()) => guard.disarm(),
        Err(_) => {
            // Windows rename-over-existing: fine if the target exists
            // (same content hash — the guard drops the temp); a real
            // failure removes the temp and reports.
            if !final_path.exists() {
                return Err(StoreError::Other("store rename failed".into()));
            }
        }
    }
    Ok((rel, sha, size))
}

/// KQ9: `attachments.local_path` is stored RELATIVE to the media root
/// (`ab/cd/<sha>`, forward slashes) so moving the root never breaks a
/// row. This maps such a rel back to an absolute path. The writer only
/// ever stores that exact shape; anything carrying a traversal, an
/// empty segment, a drive/prefix (`C:`) or backslash tricks maps to
/// the root itself (fail-closed — it can never point OUTSIDE the
/// store).
pub fn resolve_local_path(cfg: &ShadowSettings, rel: &str) -> PathBuf {
    let clean = rel.replace('\\', "/");
    let parts: Vec<&str> = clean.split('/').collect();
    let safe = !parts.iter().any(|&p| {
        p.is_empty() || p == ".." || p == "." || p.contains(':')
    });
    let root = media_store_root(cfg);
    if safe {
        root.join(parts.join("/"))
    } else {
        root
    }
}

#[cfg(test)]
mod tests {
    use super::super::schema;
    use super::*;

    fn db() -> Connection {
        let key = sqlcipher::generate_key().unwrap();
        let conn = sqlcipher::open_in_memory(&key).unwrap();
        schema::apply(&conn).unwrap();
        conn
    }

    fn ref_row(conn: &Connection, msg_id: &str) -> i64 {
        conn.execute(
            "INSERT INTO attachments (msg_id, idx, kind, url, status)
             VALUES (?1, 0, 'image', 'https://h/x', 'ref')",
            [msg_id],
        )
        .unwrap();
        conn.query_row("SELECT max(rowid) FROM attachments", [], |r| r.get(0))
            .unwrap()
    }

    #[test]
    fn prune_keeps_ref_rows_and_drops_applied_ones() {
        // F1: an id leaves the in-flight set only when its row stopped
        // reading 'ref' — i.e. the flusher's transaction landed.
        let conn = db();
        let r_still = ref_row(&conn, "m_still");
        let r_downloaded = ref_row(&conn, "m_dl");
        let r_failed = ref_row(&conn, "m_fail");
        let r_deleted = ref_row(&conn, "m_del");
        conn.execute(
            "UPDATE attachments SET status='downloaded' WHERE rowid = ?1",
            [r_downloaded],
        )
        .unwrap();
        conn.execute(
            "UPDATE attachments SET status='failed' WHERE rowid = ?1",
            [r_failed],
        )
        .unwrap();
        conn.execute("DELETE FROM attachments WHERE rowid = ?1", [r_deleted])
            .unwrap();

        let mut in_flight = HashSet::from([r_still, r_downloaded, r_failed, r_deleted]);
        prune_in_flight(&conn, &mut in_flight).unwrap();
        assert_eq!(in_flight, HashSet::from([r_still]));
    }

    #[test]
    fn prune_empty_set_is_a_noop() {
        let conn = db();
        let mut in_flight = HashSet::new();
        prune_in_flight(&conn, &mut in_flight).unwrap();
        assert!(in_flight.is_empty());
    }

    #[test]
    fn prune_clears_the_set_past_the_cap() {
        // F1: a stuck flusher must not grow the set unbounded — past
        // IN_FLIGHT_CAP the whole set is dropped instead of one giant
        // query (the rows are still 'ref' and get re-picked later).
        let conn = db();
        let mut in_flight: HashSet<i64> = (0..=IN_FLIGHT_CAP as i64).collect();
        assert!(in_flight.len() > IN_FLIGHT_CAP);
        prune_in_flight(&conn, &mut in_flight).unwrap();
        assert!(in_flight.is_empty());
    }

    // --- B3/M1: host allowlist + redirect decisions (pure, no network) ---

    /// Yields the first chunk once, then errors forever (a connection
    /// that dies mid-body — B4's temp-cleanup trigger).
    struct DieMidway {
        first: Option<Vec<u8>>,
    }

    impl std::io::Read for DieMidway {
        fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
            match self.first.take() {
                Some(v) => {
                    let n = v.len().min(buf.len());
                    buf[..n].copy_from_slice(&v[..n]);
                    Ok(n)
                }
                None => Err(std::io::Error::new(
                    std::io::ErrorKind::ConnectionAborted,
                    "crafted",
                )),
            }
        }
    }

    /// Count leftover `.dl-*.tmp` files in a store root (B4).
    fn tmp_count(root: &Path) -> usize {
        std::fs::read_dir(root)
            .map(|it| {
                it.filter_map(Result::ok)
                    .filter(|e| {
                        let n = e.file_name();
                        let n = n.to_string_lossy();
                        n.starts_with(".dl-") && n.ends_with(".tmp")
                    })
                    .count()
            })
            .unwrap_or(0)
    }

    /// A unique scratch dir under the OS temp dir — never the live
    /// media root, and no test ever touches the network.
    fn scratch() -> PathBuf {
        let uniq = format!(
            "zr-media-test-{}-{}",
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
    fn host_allowlist_good_and_evil() {
        // Good: subdomains of the four CDN suffixes (fake host labels on
        // the real suffixes), default port, host case-insensitive.
        for ok in [
            "https://photo-stal-fake.zdn.vn/a.jpg",
            "https://f6x-fake.zdn.vn/b.jpg",
            "https://fake.zadn.vn/c.png",
            "https://video-stal-fake.dlmd.me/v.mp4",
            "https://file-stal-fake.dlfl.vn/doc.pdf",
            "https://video-stal-fake.dlmd.me:443/v.mp4",
            "https://FAKE.ZDN.VN/x.jpg",
            "https://fake.zdn.vn/a.jpg?sig=1#frag",
        ] {
            assert!(host_allowed(ok), "{ok}");
        }
        // Scheme, dot-boundary and authority shape.
        for bad in [
            "http://fake.zdn.vn/a.jpg",        // not https
            "ftp://fake.zdn.vn/a.jpg",
            "https://evil-zdn.vn/a.jpg",       // dash, not a dot boundary
            "https://fake.zdnn.vn/a.jpg",      // suffix must match exactly
            "https://zdn.vn.evil.com/a.jpg",    // host is the whole authority
            "https://x.zdn.vn.evil.com/a.jpg",
            "https://zdn.vn/",                 // apex: must be a subdomain
            "https://user@fake.zdn.vn/a.jpg",   // userinfo
            "https://user:pw@fake.zdn.vn/a.jpg",
            "https://fake.zdn.vn:8443/a.jpg",   // non-default port
            "https://fake.zdn.vn:/a.jpg",       // degenerate empty port
            "https://1.2.3.4/x",                // IPv4 literal
            "https://12345/x",                  // bare-number host
            "https://[::1]/x",                  // IPv6 literal
            "https://[2001:db8::1]:443/x",
            "https:///x",                       // empty host
            "https://fake.zdn.vn\\@evil.com/x", // backslash trick (caught by the @ check)
            // R1 (batch 3): charset/label holes — a WHATWG-style parser
            // treats `\` as `/`, so the real host of the first case is
            // `evil.com`; `%`, whitespace, control chars and `_` are the
            // same class of parser-confusion vector.
            "https://evil.com\\.zdn.vn/x",      // backslash: real host is evil.com
            "https://evil.com%2f.zdn.vn/x",     // percent sign in the host
            "https://a..zdn.vn/x",              // empty label
            "https://fa ke.zdn.vn/x",           // whitespace anywhere in the url
            "https://fake.zdn.vn/a\\b",         // backslash anywhere in the url
            "https://-x.zdn.vn/x",              // label with leading '-'
            "https://x-.zdn.vn/x",              // label with trailing '-'
            "https://x_y.zdn.vn/a.jpg",         // '_' is not a DNS char
            "https://fake.zdn.vn\tx/a.jpg",     // control char (tab escape)
            "fake.zdn.vn",                      // not a url at all
            "",
        ] {
            assert!(!host_allowed(bad), "{bad}");
        }
    }

    #[test]
    fn redirect_hop_stays_inside_the_allowlist() {
        let base = "https://video-stal-fake.dlmd.me/v.mp4";
        // An allowed absolute Location is followed as-is.
        assert_eq!(
            redirect_hop(302, Some("https://file-stal-fake.dlfl.vn/doc.pdf"), base),
            Some(RedirectHop::Follow("https://file-stal-fake.dlfl.vn/doc.pdf".into()))
        );
        // Root-, path- and scheme-relative Locations resolve against
        // the (already allowlisted) base.
        assert_eq!(
            redirect_hop(301, Some("/next.mp4"), base),
            Some(RedirectHop::Follow("https://video-stal-fake.dlmd.me/next.mp4".into()))
        );
        assert_eq!(
            redirect_hop(301, Some("next.mp4"), "https://video-stal-fake.dlmd.me/dir/v.mp4"),
            Some(RedirectHop::Follow("https://video-stal-fake.dlmd.me/dir/next.mp4".into()))
        );
        assert_eq!(
            redirect_hop(302, Some("//photo-stal-fake.zdn.vn/a.jpg"), base),
            Some(RedirectHop::Follow("https://photo-stal-fake.zdn.vn/a.jpg".into()))
        );
        // Missing/unresolvable/off-allowlist Locations are Blocked
        // (http scheme hops included — host_allowed demands https).
        for bad in [
            None,
            Some(""),
            Some("#frag"),
            Some("https://evil.com/x"),
            Some("http://video-stal-fake.dlmd.me/x"),
            Some("//evil-zdn.vn/x"),
            Some("https://1.2.3.4/x"),
            Some("https://user@video-stal-fake.dlmd.me/x"),
        ] {
            assert_eq!(redirect_hop(302, bad, base), Some(RedirectHop::Blocked), "{bad:?}");
        }
        // Non-3xx statuses are final responses, not redirect decisions
        // (ureq's is_redirection() range is 300..400 — a 304 counts as
        // a hop decision, i.e. Blocked without a usable Location).
        for status in [200u16, 201, 404, 500] {
            assert_eq!(redirect_hop(status, Some("https://file-stal-fake.dlfl.vn/x"), base), None);
        }
        assert_eq!(redirect_hop(304, None, base), Some(RedirectHop::Blocked));
    }

    #[test]
    fn location_resolution_shapes() {
        let b = "https://file-stal-fake.dlfl.vn/dir/doc.pdf";
        assert_eq!(resolve_location(b, "https://x.y.zdn.vn/a"), Some("https://x.y.zdn.vn/a".into()));
        assert_eq!(resolve_location(b, "http://x.zdn.vn/a"), Some("http://x.zdn.vn/a".into()));
        assert_eq!(resolve_location(b, "//x.zadn.vn/a"), Some("https://x.zadn.vn/a".into()));
        assert_eq!(resolve_location(b, "/root.pdf"), Some("https://file-stal-fake.dlfl.vn/root.pdf".into()));
        assert_eq!(resolve_location(b, "sibling.pdf"), Some("https://file-stal-fake.dlfl.vn/dir/sibling.pdf".into()));
        assert_eq!(
            resolve_location("https://file-stal-fake.dlfl.vn", "rel.pdf"),
            Some("https://file-stal-fake.dlfl.vn/rel.pdf".into())
        );
        assert_eq!(resolve_location(b, ""), None);
        assert_eq!(resolve_location(b, "#f"), None);
        assert_eq!(resolve_location(b, "   "), None);
        // A non-https base is never a valid redirect origin.
        assert_eq!(resolve_location("http://base/x", "/y"), None);
    }

    // --- B4: sniff + temp hygiene + KQ9 relative paths ---------------------

    #[test]
    fn magic_sniff_table() {
        let jpeg = [0xFF, 0xD8, 0xFF, 0xE0, 0, 0, 0, 0];
        let png = [0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A];
        let gif = b"GIF89a".to_vec();
        let webp = [b'R', b'I', b'F', b'F', 0, 0, 0, 0, b'W', b'E', b'B', b'P'];
        let mp4 = [0, 0, 0, 0, b'f', b't', b'y', b'p', b'i', b's', b'o', b'm'];
        let webm = [0x1A, 0x45, 0xDF, 0xA3, 0, 0, 0, 0];
        // E2EE-ciphertext-ish bytes (KQ1: never a container header).
        let cipher = [0x37, 0x9E, 0x2C, 0xF1, 0, 0, 0, 0];
        assert!(magic_ok(Some("image"), &jpeg));
        assert!(magic_ok(Some("image"), &png));
        assert!(magic_ok(Some("image"), &gif));
        assert!(magic_ok(Some("image"), &webp));
        assert!(magic_ok(Some("video"), &mp4));
        assert!(magic_ok(Some("video"), &webm));
        // Mismatches are refused…
        assert!(!magic_ok(Some("image"), &cipher));
        assert!(!magic_ok(Some("video"), &cipher));
        assert!(!magic_ok(Some("video"), &jpeg));
        assert!(!magic_ok(Some("image"), &mp4));
        assert!(!magic_ok(Some("video"), &[0, 0, 0, 0]), "short head can't match");
        // …but file/voice/unknown kinds are never sniffed.
        assert!(magic_ok(Some("file"), &cipher));
        assert!(magic_ok(Some("voice"), &cipher));
        assert!(magic_ok(None, &cipher));
        assert!(magic_ok(Some("sticker"), &cipher));
    }

    #[test]
    fn store_stream_writes_relative_path_and_cleans_tmp() {
        let root = scratch();
        let jpeg = [0xFF, 0xD8, 0xFF, 0xE0, 1, 2, 3, 4, 5, 6, 7, 8];
        let (rel, sha, size) = store_stream(std::io::Cursor::new(jpeg), &root, Some("image")).unwrap();
        // KQ9: `ab/cd/<sha>` with forward slashes; the sha IS the file name.
        let parts: Vec<&str> = rel.split('/').collect();
        assert_eq!(parts.len(), 3, "{rel}");
        assert_eq!(parts[0].len(), 2);
        assert_eq!(parts[1].len(), 2);
        assert_eq!(parts[2], sha);
        assert_eq!(sha.len(), 64);
        assert_eq!(size, jpeg.len() as u64);
        let mut h = Sha256::new();
        h.update(jpeg);
        assert_eq!(sha, format!("{:x}", h.finalize()));
        assert!(root.join(&rel).is_file());
        assert_eq!(tmp_count(&root), 0, "no .dl-*.tmp left after success");
        // Same bytes again: content-addressed dedupe keeps one file and
        // still leaves no temp behind.
        store_stream(std::io::Cursor::new(jpeg), &root, Some("image")).unwrap();
        assert_eq!(tmp_count(&root), 0);
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn store_stream_error_midway_removes_the_temp() {
        let root = scratch();
        let reader = DieMidway { first: Some(vec![0xFF, 0xD8, 0xFF, 1, 2, 3]) };
        assert!(matches!(
            store_stream(reader, &root, Some("image")),
            Err(StoreError::Io(_))
        ));
        assert_eq!(tmp_count(&root), 0, "temp removed on the mid-stream error path");
        let stored = std::fs::read_dir(&root).map(|it| it.count()).unwrap_or(0);
        assert_eq!(stored, 0, "nothing entered the store");
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn store_stream_sniff_mismatch_keeps_nothing() {
        let root = scratch();
        // Image kind, bytes with no image container header: the KQ1
        // fallback (E2EE CDN ciphertext) — nothing may be kept.
        let cipher = [0x37, 0x9E, 0x2C, 0xF1, 8, 9, 10, 11];
        assert!(matches!(
            store_stream(std::io::Cursor::new(cipher), &root, Some("image")),
            Err(StoreError::Sniff)
        ));
        assert_eq!(tmp_count(&root), 0, "temp removed on the sniff path");
        let stored = std::fs::read_dir(&root).map(|it| it.count()).unwrap_or(0);
        assert_eq!(stored, 0, "nothing entered the store");
        // file/voice are not sniffed — the same bytes store fine.
        let (rel, _sha, _size) = store_stream(std::io::Cursor::new(cipher), &root, Some("voice")).unwrap();
        assert!(root.join(&rel).is_file());
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn resolve_local_path_maps_rel_and_fails_closed() {
        let mut cfg = ShadowSettings::default();
        cfg.media_store = Some("D:\\ZaloRust Data".into());
        assert_eq!(
            resolve_local_path(&cfg, "ab/cd/0123abc"),
            PathBuf::from("D:\\ZaloRust Data\\ab\\cd\\0123abc")
        );
        // Backslash input normalizes to forward slashes.
        assert_eq!(
            resolve_local_path(&cfg, "ab\\cd\\0123abc"),
            PathBuf::from("D:\\ZaloRust Data\\ab\\cd\\0123abc")
        );
        // Traversal/drive/absolute tricks fail closed to the root
        // (never OUTSIDE the store).
        for bad in ["../outside", "ab/../cd", "D:\\other", "ab//cd", "/abs", ""] {
            assert_eq!(resolve_local_path(&cfg, bad), PathBuf::from("D:\\ZaloRust Data"), "{bad}");
        }
    }

    #[test]
    fn cycle_blocks_disallowed_hosts_without_network() {
        // M1: a row whose url is https but NOT on the allowlist must be
        // failed BEFORE any request — this test deliberately never
        // touches the network (an allowed url would).
        let conn = db();
        conn.execute(
            "INSERT INTO attachments (msg_id, idx, kind, url, status)
             VALUES ('mb', 0, 'image', 'https://evil-zdn.vn/x.jpg', 'ref')",
            [],
        )
        .unwrap();
        let (tx, rx) = std::sync::mpsc::channel();
        let mut in_flight = HashSet::new();
        let counts =
            download_one_cycle(&conn, &PathBuf::from("unused-root"), &tx, &mut in_flight).unwrap();
        assert_eq!(counts.blocked_host, 1);
        assert_eq!(counts.total(), 1);
        match rx.recv() {
            Ok(Job::MediaDone { rowid, outcome }) => {
                assert_eq!(outcome, MediaOutcome::Failed);
                assert!(in_flight.contains(&rowid), "F1: stays in flight until the flusher lands");
            }
            _ => panic!("expected one MediaDone"),
        }
        // A second cycle re-picks nothing: the outcome is still in the
        // flusher's hands (row still reads 'ref').
        let counts =
            download_one_cycle(&conn, &PathBuf::from("unused-root"), &tx, &mut in_flight).unwrap();
        assert_eq!(counts.total(), 0, "in-flight row must not be re-picked");
    }
}
