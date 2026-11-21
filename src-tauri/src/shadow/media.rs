//! P1b media auto-download (D8/D11, rebuild 2026-11-19).
//!
//! Rules (handoff + audit H3/T3, M1/B3/B4 batch 2):
//! - Only NEW media (attachments rows with status='ref' created by the
//!   writer from live traffic) — never a backfill scan of history.
//! - Batch 26 M3: rows created for IMPORT-sourced messages carry
//!   `status='ref-import'` and are never picked by default — picking
//!   them would turn the import into exactly the history backfill the
//!   first rule forbids. The opt-in
//!   `settings.shadow.media_backfill_import` (default false) may pick
//!   them: at most 2 per cycle, only once the live `ref` queue produced
//!   no rows that cycle, and a circuit breaker pauses the picks for
//!   the rest of the session after 20 consecutive gone/http_other
//!   outcomes on import rows.
//! - Batch 26 M2: a failed GET is classified into kinds (gone /
//!   http_other / timeout / net / store — kinds only, the ureq error
//!   text embeds the request url). A GONE link (403/404/410) lands as
//!   `status='expired'`, not `failed`: expired CDN history is not a
//!   broken row.
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
//!   itself. F2 (batch-18 review): the connection lives for ONE cycle
//!   only — opened with the shared key cell's CURRENT value at the start
//!   and dropped at the end — so a key-mode conversion (which holds the
//!   store gate's WRITE guard) never sees it, and the next cycle opens
//!   with the new key without an app restart.
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
    /// M2: the `failed` total split by kind. Kinds only — the ureq
    /// error text embeds the request url, so it never reaches a log.
    failed_gone: usize,
    failed_http_other: usize,
    failed_timeout: usize,
    failed_net: usize,
    failed_store: usize,
}

impl CycleCounts {
    fn total(&self) -> usize {
        self.ok + self.failed + self.blocked_host + self.blocked_redirect + self.ref_encrypted
    }

    /// M2: the appended `failed_kinds=(…)` field — kinds and counts
    /// only, in the brief's fixed order.
    fn failed_kinds_field(&self) -> String {
        format!(
            "failed_kinds=(gone {} http_other {} timeout {} net {} store {})",
            self.failed_gone, self.failed_http_other, self.failed_timeout, self.failed_net,
            self.failed_store
        )
    }
}

/// Start the downloader thread (call once per process, after the DB
/// exists). `done` is the flusher's job queue: every download outcome is
/// reported through it. Best-effort: failures are retried next cycle.
///
/// F2 (batch-18 review): there is NO long-lived connection anymore. Each
/// cycle opens one with the key the shared key cell holds RIGHT THEN
/// (raw: `default.key`; passphrase: the cell's value, else the remember
/// file) and drops it at the end of the cycle, holding the store gate's
/// READ guard for exactly that span — so a conversion's WRITE guard
/// never competes with this connection, and a set/change/remove is
/// picked up on the very next cycle.
/// Crate-internal: only `runtime::start` wires this up.
pub(crate) fn start(dir: PathBuf, cfg: ShadowSettings, done: Sender<Job>) {
    std::thread::Builder::new()
        .name("shadow-media".into())
        .spawn(move || {
            let root = media_store_root(&cfg);
            let _ = std::fs::create_dir_all(&root);
            crate::dlog::log(&format!("shadow media: store at {}", root.display()));
            // Rows whose outcome is still in the flusher's queue/hands.
            let mut in_flight: HashSet<i64> = HashSet::new();
            // M3: the opt-in import-history backfill state (session
            // scoped — the breaker pause lasts until restart).
            let mut import = ImportBackfill::new(cfg.media_backfill_import);
            let mut backoff = 30u64;
            // H3/D13 (batch 8): the last space verdict this thread
            // logged a transition for. `Ok` is the quiet initial state.
            let mut disk_state = super::disk_space::SpaceVerdict::Ok;
            loop {
                std::thread::sleep(Duration::from_secs(backoff.max(5)));
                // F2: the store gate's READ guard spans exactly this
                // cycle's DB use — the connection's whole life. A
                // conversion waiting on the WRITE guard finishes before
                // this open runs, and the open below then uses the
                // cell's CURRENT key.
                let _gate = super::passphrase::store_gate_read();
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
                // F2: open per cycle with the CURRENT key; a locked
                // store (no cell value, no remember file) simply idles.
                let Some(conn) = open(&dir, &cfg) else {
                    continue;
                };
                match download_one_cycle(&conn, &root, &done, &mut in_flight, &mut import) {
                    Ok(counts) if counts.total() == 0 => backoff = 30,
                    Ok(counts) => {
                        backoff = 10;
                        // Counts only (H-rule): no urls, no error text.
                        // M2 appends the failed-kinds split — every
                        // existing field keeps its name and position.
                        crate::dlog::log(&format!(
                            "shadow media: cycle reported ok={} failed={} blocked_host={} blocked_redirect={} ref_encrypted={} {}",
                            counts.ok,
                            counts.failed,
                            counts.blocked_host,
                            counts.blocked_redirect,
                            counts.ref_encrypted,
                            counts.failed_kinds_field(),
                        ));
                    }
                    Err(CycleError::Db(e)) => {
                        // Log the error KIND only: sqlite messages can
                        // quote SQL/params. The connection is dropped at
                        // the end of this cycle anyway (F2) — the next
                        // cycle opens a fresh one.
                        crate::dlog::log(&format!(
                            "shadow media: DB error ({}), retrying next cycle",
                            pipeline::sqlite_kind(&e)
                        ));
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

/// READ-ONLY open for one media cycle (T3: the media thread never
/// writes; the flusher owns every write). Both paths set the H3 busy
/// timeout.
///
/// F2 (batch-18 review): in passphrase mode the key is the shared key
/// cell's CURRENT value first (the flusher's RAM passphrase, bumped on
/// every successful set/change/remove and on unlock), else the
/// remember file (a restarted process, or a store locked pending
/// unlock). With neither, the cycle stays idle rather than opening
/// with a wrong key; no password input ever happens here.
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
    match super::passphrase::read_mode(dir) {
        super::passphrase::StoreKeyMode::Raw => {
            let key = sqlcipher::load_key(&key_path).ok()?;
            // L4/D4: the loaded key bytes are wiped once the connection
            // holds them (SQLCipher keeps its own copy; this Vec must
            // not linger).
            let key = zeroize::Zeroizing::new(key);
            // Sets busy_timeout (T1) and query_only.
            sqlcipher::open_with_key_readonly(&db_path, &key).ok()
        }
        super::passphrase::StoreKeyMode::Passphrase => {
            // F2: the shared key cell first (a value the flusher
            // published for THIS mode), the remember file second.
            let pw = super::passphrase::cell_passphrase()
                .or_else(|| super::passphrase::load_remembered(dir).ok())?;
            sqlcipher::open_with_passphrase_readonly(&db_path, &pw).ok()
        }
        // An unreadable/future marker: never open with a guessed key.
        super::passphrase::StoreKeyMode::Unknown => None,
    }
}

/// Cap for the in-flight set (F1): a flusher stuck for hours must not
/// grow the set without bound. Past the cap the set is dropped
/// wholesale — those rows still read `status='ref'` and are simply
/// re-picked (at worst re-downloaded) by a later cycle.
const IN_FLIGHT_CAP: usize = 1024;

/// F1: drop ids whose row is no longer live-queued — the flusher has
/// applied their outcome (or the row is gone), so they are safe to
/// select again. Ids still `ref` STAY in flight: their outcome is
/// queued but has not landed yet, so re-selecting one would download
/// the same url a second time. M3: with the import backfill on, a
/// picked `ref-import` row obeys exactly the same rule while its
/// outcome is pending.
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
            "SELECT rowid FROM attachments WHERE status IN ('ref','ref-import') AND rowid IN ({ids})"
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

/// M3 opt-in import backfill state (settings key
/// `shadow.media_backfill_import`, default false). The history queue
/// (`ref-import`) is picked only when `enabled`, at most
/// [`MAX_PER_CYCLE`](Self::MAX_PER_CYCLE) rows per cycle, and only once
/// the live `ref` queue produced no rows that cycle. The circuit
/// breaker pauses the picks for the rest of the session after 20
/// consecutive `gone`/`http_other` outcomes on import rows — expired or
/// signed CDN history is the normal case there, and the thread must not
/// spend every cycle on it. Pure: the unit tests drive the fold
/// directly, no network.
#[derive(Debug)]
struct ImportBackfill {
    enabled: bool,
    consecutive_fail: u32,
    paused: bool,
}

impl ImportBackfill {
    /// Backfill rows per cycle (the batch's cap).
    const MAX_PER_CYCLE: usize = 2;
    /// Consecutive gone/http_other import outcomes that trip the
    /// breaker (the batch's limit).
    const BREAKER_LIMIT: u32 = 20;

    fn new(enabled: bool) -> Self {
        Self {
            enabled,
            consecutive_fail: 0,
            paused: false,
        }
    }

    /// Pure breaker fold over one import-row outcome. A `gone`/
    /// `http_other` failure extends the streak; ANY other outcome
    /// resets it (one servable row proves the history is not uniformly
    /// dead). Returns `true` exactly ONCE — on the transition to
    /// paused — so the caller logs one line, never one per row.
    fn record_import_outcome(&mut self, gone_or_http_other: bool) -> bool {
        if self.paused {
            return false;
        }
        if !gone_or_http_other {
            self.consecutive_fail = 0;
            return false;
        }
        self.consecutive_fail += 1;
        if self.consecutive_fail >= Self::BREAKER_LIMIT {
            self.paused = true;
            return true;
        }
        false
    }
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
///
/// M3: the selection stays `status='ref'` ONLY. The `ref-import`
/// history queue is a separate, opt-in second pick (`import`), which
/// runs when the backfill setting is on, the live queue produced no
/// rows this cycle, and the breaker has not paused it.
fn download_one_cycle(
    conn: &Connection,
    root: &Path,
    done: &Sender<Job>,
    in_flight: &mut HashSet<i64>,
    import: &mut ImportBackfill,
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
    // M3: the import history queue — only when the backfill is on, the
    // breaker has not paused it, and the live `ref` queue produced no
    // rows this cycle (the history must never preempt live media).
    // In-flight ids are excluded IN THE QUERY: unlike the live pick
    // (whose cap is just a candidate window), a backfill cycle must
    // not spend its 2-row budget on rows whose outcome is already
    // pending with the flusher. Pure digits from `i64::to_string()` —
    // the same no-injection surface `prune_in_flight` uses.
    let import_rows: Vec<(i64, Option<String>, String)> =
        if rows.is_empty() && import.enabled && !import.paused {
            let skip = if in_flight.is_empty() {
                String::new()
            } else {
                format!(
                    " AND rowid NOT IN ({})",
                    in_flight
                        .iter()
                        .map(|id| id.to_string())
                        .collect::<Vec<_>>()
                        .join(",")
                )
            };
            let mut st = conn
                .prepare(&format!(
                    "SELECT rowid, kind, url FROM attachments \
                     WHERE status = 'ref-import' AND url IS NOT NULL AND url LIKE 'https://%'\
                     {skip} \
                     ORDER BY rowid LIMIT ?1"
                ))
                .map_err(CycleError::Db)?;
            // Bound to a local FIRST: the iterator chain holds a
            // borrow of `st`, and a temporary at the end of the block
            // would outlive it.
            let picked = st
                .query_map([ImportBackfill::MAX_PER_CYCLE as i64], |r| {
                    Ok((r.get(0)?, r.get(1)?, r.get(2)?))
                })
                .map_err(CycleError::Db)?
                .filter_map(Result::ok)
                .filter(|(rowid, _, _)| !in_flight.contains(rowid))
                .collect();
            picked
        } else {
            Vec::new()
        };
    let mut counts = CycleCounts::default();
    for (rowid, kind, url) in rows {
        download_one(rowid, kind, url, root, done, in_flight, &mut counts)?;
    }
    for (rowid, kind, url) in import_rows {
        let gone_or_http_other =
            download_one(rowid, kind, url, root, done, in_flight, &mut counts)?;
        if import.record_import_outcome(gone_or_http_other) {
            // One line per session — the transition itself, never a
            // per-row log (counts/kinds only, H-rule).
            crate::dlog::log(&format!(
                "shadow media: import backfill paused (consecutive_fail={})",
                ImportBackfill::BREAKER_LIMIT
            ));
        }
    }
    Ok(counts)
}

/// Download one picked row and report its outcome (shared by the live
/// `ref` queue and the M3 import backfill). Bumps exactly one
/// [`CycleCounts`] category, sends the `Job::MediaDone`, keeps the F1
/// in-flight rule, and returns whether the outcome was a
/// `gone`/`http_other` failure — the import breaker's input.
fn download_one(
    rowid: i64,
    kind: Option<String>,
    url: String,
    root: &Path,
    done: &Sender<Job>,
    in_flight: &mut HashSet<i64>,
    counts: &mut CycleCounts,
) -> Result<bool, CycleError> {
    in_flight.insert(rowid);
    // M1: allowlist BEFORE any request — a rejected url costs no
    // network I/O at all and is reported Failed to the flusher.
    let (outcome, gone_or_http_other) = if !host_allowed(&url) {
        counts.blocked_host += 1;
        (MediaOutcome::Failed, false)
    } else {
        match fetch_to_store(&url, root, kind.as_deref()) {
            FetchOutcome::Downloaded { rel, sha, size } => {
                counts.ok += 1;
                (
                    MediaOutcome::Downloaded { path: rel, sha256: sha, size: size as i64 },
                    false,
                )
            }
            FetchOutcome::RefEncrypted => {
                counts.ref_encrypted += 1;
                (MediaOutcome::RefEncrypted, false)
            }
            FetchOutcome::BlockedHost => {
                counts.blocked_host += 1;
                (MediaOutcome::Failed, false)
            }
            FetchOutcome::BlockedRedirect => {
                counts.blocked_redirect += 1;
                (MediaOutcome::Failed, false)
            }
            // M2: a gone link is EXPIRED, not failed.
            FetchOutcome::Gone => {
                counts.failed += 1;
                counts.failed_gone += 1;
                (MediaOutcome::Expired, true)
            }
            FetchOutcome::HttpOther => {
                counts.failed += 1;
                counts.failed_http_other += 1;
                (MediaOutcome::Failed, true)
            }
            FetchOutcome::Timeout => {
                counts.failed += 1;
                counts.failed_timeout += 1;
                (MediaOutcome::Failed, false)
            }
            FetchOutcome::Net => {
                counts.failed += 1;
                counts.failed_net += 1;
                (MediaOutcome::Failed, false)
            }
            FetchOutcome::Store => {
                counts.failed += 1;
                counts.failed_store += 1;
                (MediaOutcome::Failed, false)
            }
        }
    };
    if done.send(Job::MediaDone { rowid, outcome }).is_err() {
        // Receiver dropped (shutdown): stop the thread. The row keeps
        // its status — it is retried on the next launch.
        return Err(CycleError::FlusherGone);
    }
    // F1: the id STAYS in `in_flight` — the flusher applies this
    // outcome in its own transaction up to `batch_ms` later, and
    // until that lands the row still reads its queued status.
    // Removing it here would let the next cycle SELECT the same row
    // and download it twice; `prune_in_flight` drops it once the
    // outcome landed.
    std::thread::sleep(Duration::from_millis(700));
    Ok(gone_or_http_other)
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

/// Batch 26 M1 (shape tool): for a url that passes [`host_allowed`],
/// the ONE allowlist suffix its host ends with (`.zdn.vn`, …);
/// `None` for any other url (non-https included). The shape CLI prints
/// the SUFFIX — never the host itself or the url.
pub fn allowed_suffix(raw: &str) -> Option<&'static str> {
    if !host_allowed(raw) {
        return None;
    }
    // host_allowed guarantees the https prefix, no userinfo and a
    // default-or-absent port, so this re-parse cannot fail the same
    // way; the `?` arms are unreachable belt.
    let rest = raw.strip_prefix("https://")?;
    let auth_end = rest.find(['/', '?', '#']).unwrap_or(rest.len());
    let authority = &rest[..auth_end];
    let host = match authority.rsplit_once(':') {
        Some((h, p)) if !p.is_empty() && p.bytes().all(|b| b.is_ascii_digit()) => h,
        _ => authority,
    };
    let host = host.to_ascii_lowercase();
    ALLOWED_HOST_SUFFIXES.iter().copied().find(|s| host.ends_with(s))
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
    /// M2: the link is GONE (403/404/410) — expired CDN history; the
    /// row lands as `status='expired'`, never retried.
    Gone,
    /// M2: any other HTTP status error (4xx/5xx beyond the gone trio).
    HttpOther,
    /// M2: a configured timeout fired (either ureq timeout form).
    Timeout,
    /// M2: dns/tls/io/protocol transport failure.
    Net,
    /// M2: the local store write failed (the network was fine).
    Store,
}

/// Follow at most this many redirect hops manually (B3/M1).
const MAX_REDIRECT_HOPS: u32 = 3;

/// The ONE place the download agent's config lives (B3/M1): no
/// automatic redirects (every hop is a manual, allowlist-checked
/// decision) and the connect/response/body timeouts. Batch 26 M1: the
/// media shape CLI's `--probe-http` builds the SAME agent so its
/// status classes match what the live thread would see.
pub(crate) fn download_agent() -> ureq::Agent {
    ureq::Agent::config_builder()
        .timeout_connect(Some(Duration::from_secs(20)))
        .timeout_recv_response(Some(Duration::from_secs(30)))
        .timeout_recv_body(Some(Duration::from_secs(60)))
        // M1: no automatic redirects — every hop is a manual,
        // allowlist-checked decision.
        .max_redirects(0)
        .build()
        .into()
}

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
    let agent: ureq::Agent = download_agent();
    let mut current = url.to_string();
    let mut hops = 0u32;
    loop {
        // M2: transport errors are classified by KIND. The error text
        // is deliberately NOT logged: it embeds the request URL
        // (H-rule).
        let resp = match agent.get(&current).call() {
            Ok(r) => r,
            Err(e) => return classify_ureq_error(&e),
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
                    // M2: a local write failure is its own kind.
                    Err(_) => FetchOutcome::Store,
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

/// M2: classify one transport error into the cycle's failure kinds
/// (pure; kinds only — the ureq error text embeds the request url and
/// never reaches a log). 403/404/410 are GONE links — expired CDN
/// history is not a broken row; every other status error is
/// `http_other`; a configured timeout in either ureq form is
/// `timeout`; everything else (dns/tls/io/protocol) is `net`.
fn classify_ureq_error(e: &ureq::Error) -> FetchOutcome {
    match e {
        ureq::Error::StatusCode(403 | 404 | 410) => FetchOutcome::Gone,
        ureq::Error::StatusCode(_) => FetchOutcome::HttpOther,
        ureq::Error::Timeout(_) => FetchOutcome::Timeout,
        ureq::Error::Io(io) if io.kind() == std::io::ErrorKind::TimedOut => FetchOutcome::Timeout,
        _ => FetchOutcome::Net,
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
/// (`FF D8 FF`), PNG (`89 50 4E 47`), GIF (`47 49 46 38`), WEBP
/// (`RIFF`…`WEBP` at offset 8) or JPEG XL (batch 27 M4: the bare
/// codestream `FF 0A` and the ISO-BMFF container
/// `00 00 00 0C 4A 58 4C 20 0D 0A 87 0A` — the Desktop's local
/// picture cache is mostly JXL, and a CDN serving JXL is serving a
/// real image, not ciphertext); `video` must be MP4/MOV (`ftyp` at
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
                // Batch 27 M4: JPEG XL, both on-disk forms.
                || head.starts_with(&[0xFF, 0x0A])
                || head.starts_with(&[0x00, 0x00, 0x00, 0x0C, 0x4A, 0x58, 0x4C, 0x20, 0x0D, 0x0A, 0x87, 0x0A])
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
        // Batch 27 M4: JPEG XL is an image — the bare codestream and
        // the container signature both pass the image sniff.
        let jxl_bare = [0xFF, 0x0A, 0xE0, 0x0D, 0x00, 0x00, 0x00, 0x00];
        let jxl_box = [
            0x00, 0x00, 0x00, 0x0C, 0x4A, 0x58, 0x4C, 0x20, 0x0D, 0x0A, 0x87, 0x0A, 0, 0, 0, 0,
        ];
        assert!(magic_ok(Some("image"), &jxl_bare));
        assert!(magic_ok(Some("image"), &jxl_box));
        // Both forms are IMAGE-only: a video row carrying them still
        // fails its own sniff, and an image row carrying video bytes
        // still fails.
        assert!(!magic_ok(Some("video"), &jxl_bare));
        assert!(!magic_ok(Some("video"), &jxl_box));
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
    fn store_stream_accepts_jpeg_xl_in_both_forms() {
        // Batch 27 M4: the live download path stores JXL images —
        // `store_stream` has no file-name/extension assumption (the
        // store is content-addressed, the name IS the sha), so the
        // only thing that could refuse JXL was the sniff. Both forms
        // must land in the store, never `ref-encrypted`.
        let root = scratch();
        let jxl_bare = [0xFF, 0x0A, 0xE0, 0x0D, 0x00, 0x00, 0x14, 0x66, 0x24, 0x11, 0x0A, 0x4D];
        let (rel, _sha, size) =
            store_stream(std::io::Cursor::new(jxl_bare), &root, Some("image")).unwrap();
        assert_eq!(size, jxl_bare.len() as u64);
        assert!(root.join(&rel).is_file());
        let jxl_box = [
            0x00, 0x00, 0x00, 0x0C, 0x4A, 0x58, 0x4C, 0x20, 0x0D, 0x0A, 0x87, 0x0A, 0x00, 0x00,
            0x00, 0x01,
        ];
        let (rel2, _sha2, size2) =
            store_stream(std::io::Cursor::new(jxl_box), &root, Some("image")).unwrap();
        assert_eq!(size2, jxl_box.len() as u64);
        assert!(root.join(&rel2).is_file());
        assert_eq!(tmp_count(&root), 0);
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
        let counts = download_one_cycle(
            &conn,
            &PathBuf::from("unused-root"),
            &tx,
            &mut in_flight,
            &mut ImportBackfill::new(false),
        )
        .unwrap();
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
        let counts = download_one_cycle(
            &conn,
            &PathBuf::from("unused-root"),
            &tx,
            &mut in_flight,
            &mut ImportBackfill::new(false),
        )
        .unwrap();
        assert_eq!(counts.total(), 0, "in-flight row must not be re-picked");
    }

    // --- batch 26 M2/M3: gone links, the import queue, the breaker -------

    #[test]
    fn prune_keeps_ref_import_rows_in_flight_too() {
        // M3: with the backfill on, a picked import row's outcome is
        // queued with the flusher; until it lands the row still reads
        // 'ref-import' and must not be re-picked.
        let conn = db();
        let r_still = ref_row(&conn, "m_still");
        conn.execute(
            "INSERT INTO attachments (msg_id, idx, kind, url, status)
             VALUES ('m_imp', 0, 'image', 'https://h/x', 'ref-import')",
            [],
        )
        .unwrap();
        let r_imp: i64 = conn
            .query_row("SELECT max(rowid) FROM attachments", [], |r| r.get(0))
            .unwrap();
        let mut in_flight = HashSet::from([r_still, r_imp]);
        prune_in_flight(&conn, &mut in_flight).unwrap();
        assert_eq!(in_flight, HashSet::from([r_still, r_imp]));
        // Once the outcome lands (status moves), the id is dropped —
        // exactly like a live row.
        conn.execute(
            "UPDATE attachments SET status='expired' WHERE rowid = ?1",
            [r_imp],
        )
        .unwrap();
        prune_in_flight(&conn, &mut in_flight).unwrap();
        assert_eq!(in_flight, HashSet::from([r_still]));
    }

    #[test]
    fn cycle_never_picks_ref_import_rows_by_default() {
        // M3: one 'ref' and one 'ref-import' row — only the 'ref' row
        // is picked. Both urls are off-allowlist so the test never
        // touches the network.
        let conn = db();
        conn.execute(
            "INSERT INTO attachments (msg_id, idx, kind, url, status)
             VALUES ('m-live', 0, 'image', 'https://evil-zdn.vn/live.jpg', 'ref')",
            [],
        )
        .unwrap();
        let live_id: i64 = conn
            .query_row(
                "SELECT rowid FROM attachments WHERE msg_id='m-live'",
                [],
                |r| r.get(0),
            )
            .unwrap();
        conn.execute(
            "INSERT INTO attachments (msg_id, idx, kind, url, status)
             VALUES ('m-imp', 0, 'image', 'https://evil-zdn.vn/imp.jpg', 'ref-import')",
            [],
        )
        .unwrap();
        let (tx, rx) = std::sync::mpsc::channel();
        let mut in_flight = HashSet::new();
        let counts = download_one_cycle(
            &conn,
            &PathBuf::from("unused-root"),
            &tx,
            &mut in_flight,
            &mut ImportBackfill::new(false),
        )
        .unwrap();
        assert_eq!(counts.total(), 1, "only the live row");
        assert_eq!(counts.blocked_host, 1);
        match rx.try_recv() {
            Ok(Job::MediaDone { rowid, outcome }) => {
                assert_eq!(rowid, live_id, "the import row was never picked");
                assert_eq!(outcome, MediaOutcome::Failed);
            }
            _ => panic!("expected exactly one MediaDone"),
        }
        assert!(rx.try_recv().is_err(), "no second outcome");
    }

    #[test]
    fn backfill_picks_ref_import_only_after_the_ref_queue_empties() {
        // M3 opt-in: with the backfill on, `ref-import` rows are picked
        // only once the live queue produced no rows that cycle, and at
        // most 2 per cycle. All urls are off-allowlist (no network).
        let conn = db();
        for (msg, status) in [
            ("m-live", "ref"),
            ("m-i1", "ref-import"),
            ("m-i2", "ref-import"),
            ("m-i3", "ref-import"),
        ] {
            conn.execute(
                "INSERT INTO attachments (msg_id, idx, kind, url, status)
                 VALUES (?1, 0, 'image', 'https://evil-zdn.vn/x.jpg', ?2)",
                [msg, status],
            )
            .unwrap();
        }
        let (tx, rx) = std::sync::mpsc::channel();
        let mut in_flight = HashSet::new();
        let mut import = ImportBackfill::new(true);
        // Cycle 1: the live row wins; the history queue is invisible.
        let counts = download_one_cycle(&conn, &PathBuf::from("unused-root"), &tx, &mut in_flight, &mut import).unwrap();
        assert_eq!((counts.total(), counts.blocked_host), (1, 1), "live media preempts history");
        assert!(matches!(rx.try_recv(), Ok(Job::MediaDone { .. })));
        // Cycle 2: the live row is still in flight (queue empty this
        // cycle) -> the backfill picks at most TWO history rows.
        let counts = download_one_cycle(&conn, &PathBuf::from("unused-root"), &tx, &mut in_flight, &mut import).unwrap();
        assert_eq!((counts.total(), counts.blocked_host), (2, 2), "at most 2 per cycle");
        assert!(matches!(rx.try_recv(), Ok(Job::MediaDone { .. })));
        assert!(matches!(rx.try_recv(), Ok(Job::MediaDone { .. })));
        // Cycle 3: the two picked rows are in flight; only the third
        // history row remains eligible.
        let counts = download_one_cycle(&conn, &PathBuf::from("unused-root"), &tx, &mut in_flight, &mut import).unwrap();
        assert_eq!((counts.total(), counts.blocked_host), (1, 1));
        assert!(matches!(rx.try_recv(), Ok(Job::MediaDone { .. })));
        // Cycle 4: everything is in flight -> an idle cycle.
        let counts = download_one_cycle(&conn, &PathBuf::from("unused-root"), &tx, &mut in_flight, &mut import).unwrap();
        assert_eq!(counts.total(), 0);
    }

    #[test]
    fn import_backfill_breaker_pauses_after_20_consecutive_failures() {
        // The pure breaker fold (the brief's unit test).
        let mut b = ImportBackfill::new(true);
        for i in 1..ImportBackfill::BREAKER_LIMIT {
            assert!(
                !b.record_import_outcome(true),
                "no pause before the limit (step {i})"
            );
        }
        assert!(
            b.record_import_outcome(true),
            "the 20th consecutive gone/http_other pauses exactly once"
        );
        assert!(b.paused);
        // Paused is a session state: further outcomes never re-pause.
        assert!(!b.record_import_outcome(true));
        assert!(!b.record_import_outcome(false));
        assert!(b.paused);
        // Any non-gone/http_other outcome resets the streak BEFORE the
        // limit.
        let mut b2 = ImportBackfill::new(true);
        for _ in 1..ImportBackfill::BREAKER_LIMIT {
            b2.record_import_outcome(true);
        }
        assert!(!b2.record_import_outcome(false), "one servable row resets the streak");
        assert!(!b2.paused);
        for _ in 1..ImportBackfill::BREAKER_LIMIT {
            assert!(!b2.record_import_outcome(true));
        }
        assert!(b2.record_import_outcome(true), "20 in a row after the reset still trips");
        // A disabled backfill still folds (it is simply never picked).
        let mut b3 = ImportBackfill::new(false);
        for _ in 0..100 {
            b3.record_import_outcome(true);
        }
        assert!(b3.paused, "the counter itself is independent of `enabled`");
    }

    #[test]
    fn ureq_errors_classify_into_failure_kinds() {
        // M2: the pure classifier. 403/404/410 are gone links; other
        // statuses are http_other; both timeout forms are timeout;
        // dns/tls/io are net. Constructed errors only — no network.
        use ureq::Error;
        assert!(matches!(
            classify_ureq_error(&Error::StatusCode(403)),
            FetchOutcome::Gone
        ));
        assert!(matches!(
            classify_ureq_error(&Error::StatusCode(404)),
            FetchOutcome::Gone
        ));
        assert!(matches!(
            classify_ureq_error(&Error::StatusCode(410)),
            FetchOutcome::Gone
        ));
        assert!(matches!(
            classify_ureq_error(&Error::StatusCode(401)),
            FetchOutcome::HttpOther
        ));
        assert!(matches!(
            classify_ureq_error(&Error::StatusCode(429)),
            FetchOutcome::HttpOther
        ));
        assert!(matches!(
            classify_ureq_error(&Error::StatusCode(500)),
            FetchOutcome::HttpOther
        ));
        assert!(matches!(
            classify_ureq_error(&Error::Timeout(ureq::Timeout::Global)),
            FetchOutcome::Timeout
        ));
        assert!(matches!(
            classify_ureq_error(&Error::Io(std::io::Error::new(
                std::io::ErrorKind::TimedOut,
                "crafted"
            ))),
            FetchOutcome::Timeout
        ));
        assert!(matches!(
            classify_ureq_error(&Error::HostNotFound),
            FetchOutcome::Net
        ));
        assert!(matches!(
            classify_ureq_error(&Error::Tls("crafted")),
            FetchOutcome::Net
        ));
        assert!(matches!(
            classify_ureq_error(&Error::Io(std::io::Error::new(
                std::io::ErrorKind::ConnectionAborted,
                "crafted"
            ))),
            FetchOutcome::Net
        ));
        // The log line's shape: the kinds field in the brief's order.
        let c = CycleCounts {
            failed_gone: 3,
            failed_http_other: 2,
            failed_timeout: 1,
            failed_net: 4,
            failed_store: 0,
            ..CycleCounts::default()
        };
        assert_eq!(
            c.failed_kinds_field(),
            "failed_kinds=(gone 3 http_other 2 timeout 1 net 4 store 0)"
        );
    }

    // --- F2 (batch-18 review): the per-cycle open follows the key cell ----

    /// OBVIOUSLY FAKE passphrases (H-rule: never anything resembling a
    /// real secret; both >= the 12-char minimum).
    const FAKE_PASS: &str = "fake-pass-phrase-0123456789";
    const FAKE_PASS_2: &str = "fake-other-pass-abcdefghij";

    #[test]
    fn the_media_open_picks_up_a_changed_key_from_the_cell() {
        // The media-style open helper must consult the shared key cell
        // FRESH on every cycle — after a set/change the flusher
        // publishes the new key and the very next cycle opens with it,
        // no restart needed. Serialized with the other cell tests.
        let _g = crate::shadow::passphrase::CELL_TEST_LOCK
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let dir = scratch();
        let cfg = ShadowSettings::default(); // encrypt = true
        let key = sqlcipher::generate_key().unwrap();
        sqlcipher::save_key(&key, &super::super::key_file(&dir)).unwrap();
        {
            let conn = sqlcipher::open_with_key(&super::super::db_file(&dir), &key).unwrap();
            schema::apply(&conn).unwrap();
        }
        // raw mode: the open goes through default.key.
        crate::shadow::passphrase::publish_key(None);
        assert!(open(&dir, &cfg).is_some(), "raw mode opens via default.key");
        // convert (remember=false → no remember file, so ONLY the cell
        // can open it): the cell's value must open it.
        {
            let conn = sqlcipher::open_with_key(&super::super::db_file(&dir), &key).unwrap();
            crate::shadow::passphrase::set_passphrase(&conn, &dir, FAKE_PASS, false, 1).unwrap();
        }
        crate::shadow::passphrase::publish_key(Some(zeroize::Zeroizing::new(
            FAKE_PASS.to_string(),
        )));
        assert!(open(&dir, &cfg).is_some(), "the cell's passphrase opens it");
        // change: publishing the new password is ALL the thread needs.
        {
            let conn = sqlcipher::open_with_passphrase(&super::super::db_file(&dir), FAKE_PASS)
                .unwrap();
            crate::shadow::passphrase::change_passphrase(
                &conn,
                &dir,
                Some(FAKE_PASS),
                FAKE_PASS_2,
                false,
            )
            .unwrap();
        }
        crate::shadow::passphrase::publish_key(Some(zeroize::Zeroizing::new(
            FAKE_PASS_2.to_string(),
        )));
        assert!(
            open(&dir, &cfg).is_some(),
            "a changed key is picked up via the cell"
        );
        // an OUTDATED cell value idles the cycle instead of erroring.
        crate::shadow::passphrase::publish_key(Some(zeroize::Zeroizing::new(
            FAKE_PASS.to_string(),
        )));
        assert!(
            open(&dir, &cfg).is_none(),
            "a stale cell value must not open the store"
        );
        // no cell value + no remember file: the locked-store idle.
        crate::shadow::passphrase::publish_key(None);
        assert!(open(&dir, &cfg).is_none());
        // remember file fallback (a restarted process).
        crate::shadow::passphrase::save_remembered(&dir, FAKE_PASS_2).unwrap();
        assert!(
            open(&dir, &cfg).is_some(),
            "the remember file opens it without a cell value"
        );
        // leave the cell neutral for whichever test runs next.
        crate::shadow::passphrase::publish_key(None);
        std::fs::remove_dir_all(&dir).unwrap();
    }
}
