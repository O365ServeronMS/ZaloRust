//! Encrypted DB backup + media backup + retention (audit §4 Phase 4,
//! items 4.1/4.2, KQ6; batch 8 H1/H2/H4).
//!
//! DB backup ([`backup_db`]): the SQLCipher-documented
//! `ATTACH … AS b KEY … ; SELECT sqlcipher_export('b'); DETACH` flow
//! (KQ6 — no assumption about `VACUUM INTO` keeping encryption), into
//! a `.db.tmp` that is fsynced and atomically renamed to
//! `shadow-<yyyyMMdd-HHmmss>.db`, with a sibling manifest JSON
//! `{ts, schema_version, counts per user table, sha256, size}`.
//! Any error removes the tmp file and returns a KIND-ONLY error
//! string (no paths, no sqlite text, no values — H-rule).
//!
//! The flusher owns the only RW connection (A5), so the export runs
//! on the flusher via `Job::Backup` ([`run_db_backup`]); the media copy
//! ([`backup_media`]) runs on the backup thread itself, read-only on
//! the store. Everything is OFF by default — the thread only starts
//! when `backup_enabled && backup_dir` are set (H4).
//!
//! Retention (4.1): [`prune_backups`] keeps the newest backup of each
//! of the 7 newest calendar days plus the newest of each of the 4
//! newest ISO weeks (pure selection: [`select_to_keep`]); files that
//! do not match `shadow-<stamp>.db|.json` are never touched.
//!
//! Media backup (4.2): incremental by content name — every store file
//! `ab/cd/<sha256>` missing in the dest is copied via tmp+rename;
//! NOTHING in the dest is ever deleted; a random 1 % sample (at least
//! one file when any were copied) is sha256-verified against its name.
//! Counts only.
//!
//! Stamps render `ts` in UTC (`yyyyMMdd-HHmmss`); the daily/weekly
//! retention buckets derive from the same rendering, so the schedule
//! is self-consistent without a timezone database.
//!
//! No on-exit backup in this batch — follow-up noted for the next
//! one (the flusher's shutdown path would own it).

use std::collections::{BTreeMap, HashSet};
use std::io::Read as _;
use std::path::{Path, PathBuf};
use std::sync::mpsc::Sender;
use std::time::Duration;

use rusqlite::Connection;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use zeroize::{Zeroize, Zeroizing};

use super::pipeline::sqlite_kind;
use super::runtime::Job;
use super::schema;
use crate::migrate::sqlcipher;
use crate::settings::ShadowSettings;

/// Retention (audit 4.1): the newest backup of each of the 7 newest
/// calendar days, plus the newest of each of the 4 newest ISO weeks.
pub const DAILY_KEEP: usize = 7;
pub const WEEKLY_KEEP: usize = 4;

/// The first backup runs ~2 minutes after start (H4), then every
/// `backup_interval_hours`.
const FIRST_RUN_SECS: u64 = 120;

// --- stamps: yyyyMMdd-HHmmss (UTC) -----------------------------------------

/// Render epoch milliseconds as the backup stamp `yyyyMMdd-HHmmss`
/// (UTC). Fixed width, so lexicographic order == chronological order
/// — the retention selection relies on that.
pub fn stamp_of(now_ms: i64) -> String {
    let secs = now_ms.div_euclid(1000);
    let days = secs.div_euclid(86_400);
    let sod = secs.rem_euclid(86_400);
    let (y, m, d) = civil_from_days(days);
    format!(
        "{y:04}{m:02}{d:02}-{:02}{:02}{:02}",
        sod / 3600,
        (sod % 3600) / 60,
        sod % 60
    )
}

/// The backup DB file for `now_ms` in `dest_dir`.
pub fn backup_db_path(dest_dir: &Path, now_ms: i64) -> PathBuf {
    dest_dir.join(format!("shadow-{}.db", stamp_of(now_ms)))
}

/// One parsed stamp: enough to bucket it for retention and to place it
/// in time (ms since epoch) for the future-stamp guard.
struct ParsedStamp {
    /// `yyyyMMdd` — the calendar-day bucket.
    day_key: String,
    /// `<isoYear>W<nn>` — the ISO-week bucket.
    week_key: String,
    /// Epoch ms the stamp encodes.
    ms: i64,
}

/// Parse and validate a `yyyyMMdd-HHmmss` stamp (digits, ranges). A
/// stamp that does not parse is never a retention candidate and a file
/// carrying it is never deleted (fail-closed on anything unjudgeable).
fn parse_stamp(s: &str) -> Option<ParsedStamp> {
    let b = s.as_bytes();
    if b.len() != 15 || b[8] != b'-' {
        return None;
    }
    let digits = |r: std::ops::Range<usize>| b[r].iter().all(|c| c.is_ascii_digit());
    if !digits(0..8) || !digits(9..15) {
        return None;
    }
    let num = |r: std::ops::Range<usize>| -> Option<i64> { s[r].parse().ok() };
    let (y, mo, d) = (num(0..4)?, num(4..6)?, num(6..8)?);
    let (h, mi, sec) = (num(9..11)?, num(11..13)?, num(13..15)?);
    if !(1970..=9999).contains(&y)
        || !(1..=12).contains(&mo)
        || !(1..=31).contains(&d)
        || h > 23
        || mi > 59
        || sec > 59
    {
        return None;
    }
    let days = days_from_civil(y, mo as u32, d as u32);
    Some(ParsedStamp {
        day_key: s[0..8].to_string(),
        week_key: iso_week_key(days),
        ms: days * 86_400_000 + (h * 3600 + mi * 60 + sec) * 1000,
    })
}

// Howard Hinnant's civil-date algorithms (public domain): exact
// integer math, no timezone database, no crates.

/// Days since 1970-01-01 for a civil date.
fn days_from_civil(y: i64, m: u32, d: u32) -> i64 {
    let y = if m <= 2 { y - 1 } else { y };
    let era = if y >= 0 { y } else { y - 399 } / 400;
    let yoe = (y - era * 400) as u64;
    let mp = u64::from(if m > 2 { m - 3 } else { m + 9 });
    let doy = (153 * mp + 2) / 5 + u64::from(d) - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    era * 146_097 - 719_468 + doe as i64
}

/// Civil date for days since 1970-01-01.
fn civil_from_days(z: i64) -> (i64, u32, u32) {
    let z = z + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = (z - era * 146_097) as u64;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
    let y = yoe as i64 + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = (doy - (153 * mp + 2) / 5 + 1) as u32;
    let m = if mp < 10 { mp + 3 } else { mp - 9 } as u32;
    (if m <= 2 { y + 1 } else { y }, m, d)
}

/// Weeks in the ISO year `y` (52, or 53 when the year owns a Thursday
/// that late / starts that early).
fn weeks_in_iso_year(y: i64) -> u32 {
    fn p(y: i64) -> i64 {
        (y + y / 4 - y / 100 + y / 400).rem_euclid(7)
    }
    52 + u32::from(p(y) == 4 || p(y - 1) == 3)
}

/// ISO (year, week) for days since epoch (weeks are Monday-based,
/// week 1 owns the year's first Thursday).
fn iso_week_of(days: i64) -> (i64, u32) {
    // 1970-01-01 (day 0) was a Thursday: Mon=1..Sun=7 is (days+3)%7+1.
    let dow = (days + 3).rem_euclid(7) + 1;
    let (y, _, _) = civil_from_days(days);
    let doy = days - days_from_civil(y, 1, 1) + 1;
    let w = (doy - dow + 10) / 7;
    if w < 1 {
        (y - 1, weeks_in_iso_year(y - 1))
    } else if w > i64::from(weeks_in_iso_year(y)) {
        (y + 1, 1)
    } else {
        (y, w as u32)
    }
}

fn iso_week_key(days: i64) -> String {
    let (y, w) = iso_week_of(days);
    format!("{y}W{w:02}")
}

// --- manifest ---------------------------------------------------------------

/// The sibling manifest of one DB backup (4.1). Row counts for EVERY
/// user table, the file's sha256 and size — exactly what
/// [`verify_backup`] re-checks after a restore.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct BackupManifest {
    /// Epoch ms the backup was taken (renders the file stamp).
    pub ts: i64,
    /// `schema_meta.version` of the source DB.
    pub schema_version: i64,
    /// Row count per user table (`sqlite_master` minus `sqlite_%`).
    pub counts: BTreeMap<String, i64>,
    /// sha256 (lowercase hex) of the `.db` file.
    pub sha256: String,
    /// Size of the `.db` file in bytes.
    pub size: u64,
}

/// Log-safe io error kind (H-rule: never the path, never the raw text).
fn io_kind(e: &std::io::Error) -> String {
    format!("{:?}", e.kind())
}

/// sha256 hex of a file, streamed.
fn file_sha256(path: &Path) -> Result<String, std::io::Error> {
    let mut f = std::fs::File::open(path)?;
    let mut hasher = Sha256::new();
    let mut buf = [0u8; 64 * 1024];
    loop {
        let n = f.read(&mut buf)?;
        if n == 0 {
            break;
        }
        hasher.update(&buf[..n]);
    }
    Ok(format!("{:x}", hasher.finalize()))
}

/// Row count per user table, name-sorted (stable manifest + logs).
/// Identifiers are validated before interpolation — a `sqlite_master`
/// name is schema, not data, but the query is still assembled, so only
/// `[A-Za-z0-9_]` names are ever counted.
fn user_table_counts(conn: &Connection) -> rusqlite::Result<BTreeMap<String, i64>> {
    let mut st = conn.prepare(
        "SELECT name FROM sqlite_master \
         WHERE type='table' AND name NOT LIKE 'sqlite_%' ORDER BY name",
    )?;
    let names: Vec<String> = st
        .query_map([], |r| r.get(0))?
        .filter_map(Result::ok)
        .collect();
    drop(st);
    let mut out = BTreeMap::new();
    for name in names {
        if !safe_ident(&name) {
            continue;
        }
        let n: i64 = conn.query_row(&format!("SELECT COUNT(*) FROM \"{name}\""), [], |r| r.get(0))?;
        out.insert(name, n);
    }
    Ok(out)
}

fn safe_ident(s: &str) -> bool {
    !s.is_empty() && s.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_')
}

/// `schema_meta.version` of the DB (0 when the table is missing —
/// every shadow DB has it; verify compares equality so a 0 is caught).
fn schema_version(conn: &Connection) -> i64 {
    conn.query_row("SELECT MAX(version) FROM schema_meta", [], |r| r.get(0))
        .unwrap_or(0)
}

/// Leftover `*.db.tmp` files from a killed run (4.1 AC): removed at
/// the start of the next [`backup_db`] so a partial export never
/// lingers. Anything else in the folder is untouched.
fn cleanup_leftover_tmp(dest_dir: &Path) -> usize {
    let Ok(entries) = std::fs::read_dir(dest_dir) else {
        return 0;
    };
    let mut removed = 0usize;
    for e in entries.flatten() {
        let name = e.file_name().to_string_lossy().into_owned();
        if name.ends_with(".db.tmp") && std::fs::remove_file(e.path()).is_ok() {
            removed += 1;
        }
    }
    removed
}

// --- H1: the export ---------------------------------------------------------

/// The SQLCipher-documented export (KQ6): ATTACH the dest (raw-key
/// hex form — the same shape [`crate::migrate::sqlcipher`] uses for
/// `PRAGMA key`; that statement itself stays untouched), run
/// `sqlcipher_export('b')`, DETACH. The hex and the assembled statement
/// carry raw key material — both zeroized after use (L4/D4). An empty
/// `key` attaches a plaintext dest (the `encrypt=false` store).
fn export_to(src: &Connection, key: &[u8], tmp: &Path) -> Result<(), String> {
    use std::fmt::Write as _;
    // A single quote in the path is escaped the SQLite way.
    let path_sql = tmp.to_string_lossy().replace('\'', "''");
    let attach = if key.is_empty() {
        Zeroizing::new(format!("ATTACH DATABASE '{path_sql}' AS b;"))
    } else {
        let mut hex = Zeroizing::new(String::with_capacity(key.len() * 2));
        for b in key {
            let _ = write!(&mut *hex, "{b:02x}");
        }
        let stmt = Zeroizing::new(format!(
            "ATTACH DATABASE '{path_sql}' AS b KEY \"x'{}'\";",
            hex.as_str()
        ));
        hex.zeroize();
        stmt
    };
    let detach = |src: &Connection| {
        // Best-effort: a failed ATTACH never left the schema attached.
        let _ = src.execute_batch("DETACH DATABASE b;");
    };
    if let Err(e) = src.execute_batch(attach.as_str()) {
        detach(src);
        return Err(format!("attach:{}", sqlite_kind(&e)));
    }
    if let Err(e) = src.query_row("SELECT sqlcipher_export('b');", [], |_| Ok(())) {
        detach(src);
        return Err(format!("export:{}", sqlite_kind(&e)));
    }
    if let Err(e) = src.execute_batch("DETACH DATABASE b;") {
        return Err(format!("detach:{}", sqlite_kind(&e)));
    }
    Ok(())
}

/// DB backup (4.1/KQ6). `src` is the flusher's RW connection (A5 — the
/// only one); the export is serialized with every other DB write.
///
/// Steps: clean leftover `*.db.tmp`; ATTACH+export+DETACH into
/// `shadow-<stamp>.db.tmp`; fsync; rename to `shadow-<stamp>.db`
/// (atomic — same directory); write the manifest
/// `shadow-<stamp>.json`. On ANY error the tmp file is removed (and a
/// `.db` this run just renamed — a half-done run never masquerades as
/// a complete one) and a kind-only error string is returned.
pub fn backup_db(
    src: &Connection,
    key: &[u8],
    dest_dir: &Path,
    now_ms: i64,
) -> Result<BackupManifest, String> {
    std::fs::create_dir_all(dest_dir).map_err(|e| format!("mkdir:{}", io_kind(&e)))?;
    cleanup_leftover_tmp(dest_dir);
    let stamp = stamp_of(now_ms);
    let tmp = dest_dir.join(format!("shadow-{stamp}.db.tmp"));
    let final_path = dest_dir.join(format!("shadow-{stamp}.db"));
    let manifest_path = dest_dir.join(format!("shadow-{stamp}.json"));
    // Set after a successful rename: only then may an error path
    // remove the `.db` (a pre-existing one belongs to an earlier run).
    let mut renamed = false;
    let result = (|| -> Result<BackupManifest, String> {
        export_to(src, key, &tmp)?;
        // fsync before the rename: the file must survive a crash right
        // after it stops being "tmp". Windows needs a WRITE handle for
        // FlushFileBuffers — a read-only open yields PermissionDenied
        // there, so open read+write.
        std::fs::File::options()
            .read(true)
            .write(true)
            .open(&tmp)
            .and_then(|f| f.sync_all())
            .map_err(|e| format!("fsync:{}", io_kind(&e)))?;
        std::fs::rename(&tmp, &final_path).map_err(|e| format!("rename:{}", io_kind(&e)))?;
        renamed = true;
        // Manifest from the FINAL file.
        let counts = user_table_counts(src).map_err(|e| format!("counts:{}", sqlite_kind(&e)))?;
        let sha256 = file_sha256(&final_path).map_err(|e| format!("sha:{}", io_kind(&e)))?;
        let size = std::fs::metadata(&final_path)
            .map_err(|e| format!("size:{}", io_kind(&e)))?
            .len();
        let manifest = BackupManifest {
            ts: now_ms,
            schema_version: schema_version(src),
            counts,
            sha256,
            size,
        };
        let json = serde_json::to_vec(&manifest).map_err(|_| "manifest:json".to_string())?;
        std::fs::write(&manifest_path, json).map_err(|e| format!("write-manifest:{}", io_kind(&e)))?;
        Ok(manifest)
    })();
    if result.is_err() {
        let _ = std::fs::remove_file(&tmp);
        if renamed {
            let _ = std::fs::remove_file(&final_path);
        }
    }
    result
}

// --- H1: verification -------------------------------------------------------

/// Open a backup read-only: keyed (SQLCipher) or plaintext.
fn open_ro(path: &Path, key: &[u8]) -> Result<Connection, String> {
    // Kind-only: sqlite/DPAPI error text can quote paths and params.
    if key.is_empty() {
        let conn = Connection::open_with_flags(path, rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY)
            .map_err(|_| "open".to_string())?;
        conn.busy_timeout(Duration::from_millis(sqlcipher::BUSY_TIMEOUT_MS))
            .map_err(|_| "open".to_string())?;
        Ok(conn)
    } else {
        sqlcipher::open_with_key_readonly(path, key).map_err(|_| "open".to_string())
    }
}

/// Restore verification (4.1): open read-only with the key;
/// `PRAGMA cipher_integrity_check` (tolerate unsupported — a build
/// without the pragma or an empty result never fails the verify, any
/// non-"ok" row does); `PRAGMA integrity_check` must be exactly "ok";
/// every user table's row count must equal the manifest's; the file's
/// sha256 must equal the manifest's. Kind-only errors.
pub fn verify_backup(path: &Path, key: &[u8], manifest: &BackupManifest) -> Result<(), String> {
    let sha = file_sha256(path).map_err(|e| format!("sha:{}", io_kind(&e)))?;
    if !sha.eq_ignore_ascii_case(&manifest.sha256) {
        return Err("sha256-mismatch".into());
    }
    let conn = open_ro(path, key)?;
    // cipher_integrity_check — tolerated when unsupported (prepare or
    // read errors, empty result), decisive when it reports problems.
    let mut cipher_ok = true;
    if let Ok(mut st) = conn.prepare("PRAGMA cipher_integrity_check;") {
        if let Ok(rows) = st.query_map([], |r| r.get::<_, String>(0)) {
            for row in rows.flatten() {
                if row.trim() != "ok" {
                    cipher_ok = false;
                }
            }
        }
    }
    if !cipher_ok {
        return Err("cipher-integrity".into());
    }
    let mut st = conn
        .prepare("PRAGMA integrity_check;")
        .map_err(|e| format!("integrity:{}", sqlite_kind(&e)))?;
    let rows: Vec<String> = st
        .query_map([], |r| r.get::<_, String>(0))
        .map_err(|e| format!("integrity:{}", sqlite_kind(&e)))?
        .flatten()
        .collect();
    if rows.len() != 1 || rows[0] != "ok" {
        return Err("integrity-check".into());
    }
    let counts = user_table_counts(&conn).map_err(|e| format!("counts:{}", sqlite_kind(&e)))?;
    if counts != manifest.counts {
        return Err("count-mismatch".into());
    }
    Ok(())
}

// --- H1: retention ---------------------------------------------------------

/// Pure retention selection (4.1, exhaustively unit-tested): the
/// newest stamp of each of the [`DAILY_KEEP`] newest calendar days,
/// union the newest stamp of each of the [`WEEKLY_KEEP`] newest ISO
/// weeks. Stamps that do not parse are ignored; duplicates collapse.
pub fn select_to_keep(stamps: &[String]) -> HashSet<String> {
    let mut newest_by_day: BTreeMap<String, String> = BTreeMap::new();
    let mut newest_by_week: BTreeMap<String, String> = BTreeMap::new();
    for s in stamps {
        let Some(p) = parse_stamp(s) else { continue };
        // Fixed-width stamps: lexicographic == chronological, so "max"
        // is a string comparison.
        newest_by_day
            .entry(p.day_key)
            .and_modify(|cur| {
                if *cur < *s {
                    *cur = s.clone();
                }
            })
            .or_insert_with(|| s.clone());
        newest_by_week
            .entry(p.week_key)
            .and_modify(|cur| {
                if *cur < *s {
                    *cur = s.clone();
                }
            })
            .or_insert_with(|| s.clone());
    }
    let mut keep = HashSet::with_capacity(DAILY_KEEP + WEEKLY_KEEP);
    for (_, newest) in newest_by_day.into_iter().rev().take(DAILY_KEEP) {
        keep.insert(newest);
    }
    for (_, newest) in newest_by_week.into_iter().rev().take(WEEKLY_KEEP) {
        keep.insert(newest);
    }
    keep
}

/// (`shadow-<stamp>.db` | `shadow-<stamp>.json`) → (stamp, kind).
/// Nothing else matches — tmp files, unrelated files, foreign names.
fn backup_file_kind(name: &str) -> Option<(String, &'static str)> {
    if let Some(s) = name.strip_prefix("shadow-").and_then(|s| s.strip_suffix(".db")) {
        return Some((s.to_string(), "db"));
    }
    if let Some(s) = name.strip_prefix("shadow-").and_then(|s| s.strip_suffix(".json")) {
        return Some((s.to_string(), "json"));
    }
    None
}

/// Prune finished backups (4.1): delete every `shadow-<stamp>.db` +
/// `.json` pair whose stamp is a retention candidate (parses, not from
/// the future) and not in [`select_to_keep`]'s keep set. Returns the
/// number of stamps whose files were removed.
///
/// Fail-closed rules: a file that does not match the naming pattern is
/// NEVER deleted; a stamp that does not parse is never deleted; a
/// future stamp (clock skew) is never deleted AND never evicts real
/// backups from selection.
pub fn prune_backups(dest_dir: &Path, now_ms: i64) -> usize {
    let Ok(entries) = std::fs::read_dir(dest_dir) else {
        return 0;
    };
    // stamp -> (has .db, has .json)
    let mut files: BTreeMap<String, (bool, bool)> = BTreeMap::new();
    for e in entries.flatten() {
        let name = e.file_name().to_string_lossy().into_owned();
        if let Some((stamp, kind)) = backup_file_kind(&name) {
            let slot = files.entry(stamp).or_insert((false, false));
            if kind == "db" {
                slot.0 = true;
            } else {
                slot.1 = true;
            }
        }
    }
    let candidates: Vec<String> = files
        .keys()
        .filter(|s| parse_stamp(s).is_some_and(|p| p.ms <= now_ms))
        .cloned()
        .collect();
    let keep = select_to_keep(&candidates);
    let mut pruned = 0usize;
    for (stamp, (has_db, has_json)) in &files {
        if !parse_stamp(stamp).is_some_and(|p| p.ms <= now_ms) {
            continue; // unparsable or future: never deleted
        }
        if keep.contains(stamp) {
            continue;
        }
        let mut removed = false;
        if *has_db {
            removed |=
                std::fs::remove_file(dest_dir.join(format!("shadow-{stamp}.db"))).is_ok();
        }
        if *has_json {
            removed |=
                std::fs::remove_file(dest_dir.join(format!("shadow-{stamp}.json"))).is_ok();
        }
        if removed {
            pruned += 1;
        }
    }
    pruned
}

// --- H2: media backup ------------------------------------------------------

/// One media-backup run, counts only (H-rule — never file names).
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct MediaBackupReport {
    /// Store files matching the `ab/cd/<sha256>` layout.
    pub scanned: usize,
    /// Files this run copied to the dest (missing there before).
    pub copied: usize,
    /// Copy failures (retried by the next run — the dest is never
    /// deleted from, so incremental means "try the missing ones
    /// again").
    pub copy_failed: usize,
    /// Size of the random 1 % sample actually verified.
    pub verified: usize,
    /// Sample files whose sha256 did not match their name.
    pub verify_failed: usize,
}

/// `ab/cd/<sha256>` file name — 64 lowercase hex chars.
fn is_sha_name(s: &str) -> bool {
    s.len() == 64 && s.bytes().all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase())
}

/// Copy one file into the dest via tmp+rename (a partial copy never
/// masquerades as a complete one). On any error the tmp is removed.
fn copy_tmp_rename(src: &Path, dest: &Path) -> bool {
    let Some(dir) = dest.parent() else { return false };
    if std::fs::create_dir_all(dir).is_err() {
        return false;
    }
    static TMP_SEQ: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
    let tmp = dir.join(format!(
        ".bak-{}-{}.tmp",
        std::process::id(),
        TMP_SEQ.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
    ));
    let ok = (|| -> Result<(), std::io::Error> {
        std::fs::copy(src, &tmp)?;
        std::fs::rename(&tmp, dest)?;
        Ok(())
    })();
    if ok.is_err() {
        let _ = std::fs::remove_file(&tmp);
    }
    ok.is_ok()
}

/// sha256-verify sample files against their own names (pure w.r.t.
/// selection: the paths are given, the bytes are read).
fn verify_sample(paths: &[PathBuf]) -> (usize, usize) {
    let (mut ok, mut bad) = (0usize, 0usize);
    for p in paths {
        let name = p
            .file_name()
            .map(|n| n.to_string_lossy().into_owned())
            .unwrap_or_default();
        match file_sha256(p) {
            Ok(sha) if sha == name => ok += 1,
            _ => bad += 1,
        }
    }
    (ok, bad)
}

/// Uniform random index below `n` (rejection sampling, `getrandom` —
/// already a dependency). `None` only when the OS RNG fails (callers
/// fail open: fewer files verified, never a false failure).
fn random_below(n: usize) -> Option<usize> {
    if n == 0 {
        return None;
    }
    let mut buf = [0u8; 8];
    loop {
        getrandom::getrandom(&mut buf).ok()?;
        let v = u64::from_le_bytes(buf);
        let zone = u64::MAX - (u64::MAX % n as u64);
        if v < zone {
            return Some((v % n as u64) as usize);
        }
    }
}

/// `n` distinct random indices below `len` (sample without replacement).
fn random_sample(len: usize, n: usize) -> Vec<usize> {
    let mut candidates: Vec<usize> = (0..len).collect();
    let mut out = Vec::with_capacity(n.min(len));
    while out.len() < n && !candidates.is_empty() {
        match random_below(candidates.len()) {
            Some(i) => out.push(candidates.swap_remove(i)),
            None => break,
        }
    }
    out
}

/// Incremental media backup (4.2): every store file `ab/cd/<sha>`
/// missing in `dest_root` is copied via tmp+rename. NEVER deletes (or
/// overwrites) anything in the dest — a file already there is left
/// alone. A random 1 % sample of what this run copied (at least one
/// file when any were copied) is sha256-verified against the file
/// name. Counts only.
pub fn backup_media(store_root: &Path, dest_root: &Path) -> MediaBackupReport {
    let mut report = MediaBackupReport::default();
    let mut copied: Vec<PathBuf> = Vec::new();
    let Ok(level1) = std::fs::read_dir(store_root) else {
        return report;
    };
    for a in level1.flatten() {
        let Ok(level2) = std::fs::read_dir(a.path()) else { continue };
        for b in level2.flatten() {
            let Ok(files) = std::fs::read_dir(b.path()) else { continue };
            for f in files.flatten() {
                let name = f.file_name().to_string_lossy().into_owned();
                if !is_sha_name(&name) {
                    continue;
                }
                report.scanned += 1;
                let rel = format!(
                    "{}/{}/{}",
                    a.file_name().to_string_lossy(),
                    b.file_name().to_string_lossy(),
                    name
                );
                let dest = dest_root.join(&rel);
                if dest.exists() {
                    continue;
                }
                if copy_tmp_rename(&f.path(), &dest) {
                    report.copied += 1;
                    copied.push(dest);
                } else {
                    report.copy_failed += 1;
                }
            }
        }
    }
    // Random 1 % sample, at least one file when any were copied.
    let n = (copied.len() / 100).max(1).min(copied.len());
    let picks: Vec<PathBuf> = random_sample(copied.len(), n)
        .into_iter()
        .map(|i| copied[i].clone())
        .collect();
    let (ok, bad) = verify_sample(&picks);
    report.verified = ok;
    report.verify_failed = bad;
    report
}

// --- H4: the run pipeline (flusher side + backup thread) -------------------

/// What the flusher reports back for one `Job::Backup` (the DB half of
/// a run; the media half runs on the backup thread itself). Kind-only
/// failure text.
#[derive(Debug, Clone)]
pub(crate) struct DbBackupOutcome {
    pub ok: bool,
    /// User tables in the manifest (the "tables=N" log field).
    pub tables: usize,
    /// Backup file size in bytes.
    pub size: u64,
    /// Backup sets pruned by retention this run.
    pub pruned: usize,
    /// Failure kind when `!ok`.
    pub kind: Option<String>,
}

impl DbBackupOutcome {
    fn failed(kind: &str) -> Self {
        Self {
            ok: false,
            tables: 0,
            size: 0,
            pruned: 0,
            kind: Some(kind.to_string()),
        }
    }
}

/// The flusher's side of one backup run (A5: called with the flusher's
/// own RW connection, serialized with every batch write): export via
/// [`backup_db`], then [`verify_backup`], then [`prune_backups`]. The
/// media half is the backup thread's, read-only on the store.
pub(crate) fn run_db_backup(
    conn: &Connection,
    dir: &Path,
    cfg: &ShadowSettings,
) -> DbBackupOutcome {
    let Some(dest) = cfg.backup_dir.as_deref() else {
        return DbBackupOutcome::failed("no-dir");
    };
    let dest_dir = PathBuf::from(dest);
    if let Err(e) = std::fs::create_dir_all(&dest_dir) {
        return DbBackupOutcome::failed(&format!("mkdir:{}", io_kind(&e)));
    }
    // L4/D4: the key bytes are reloaded here (the flusher's open path
    // wiped its copy) and wiped again once this backup holds them.
    let key = if cfg.encrypt {
        match sqlcipher::load_key(&super::key_file(dir)) {
            Ok(k) => Zeroizing::new(k),
            Err(_) => return DbBackupOutcome::failed("key"),
        }
    } else {
        Zeroizing::new(Vec::new())
    };
    let now = schema::now_ms();
    let manifest = match backup_db(conn, &key, &dest_dir, now) {
        Ok(m) => m,
        Err(kind) => return DbBackupOutcome::failed(&kind),
    };
    let db_path = backup_db_path(&dest_dir, now);
    if let Err(kind) = verify_backup(&db_path, &key, &manifest) {
        return DbBackupOutcome::failed(&kind);
    }
    let pruned = prune_backups(&dest_dir, now);
    DbBackupOutcome {
        ok: true,
        tables: manifest.counts.len(),
        size: manifest.size,
        pruned,
        kind: None,
    }
}

/// Start the backup thread (H4) — ONLY called when
/// `backup_enabled && backup_dir` are both set. Every
/// `backup_interval_hours` (and once ~2 min after start) it sends a
/// `Job::Backup` to the flusher and waits for the DB outcome; on ok it
/// runs [`backup_media`] on THIS thread (read-only on the store) and
/// logs the run's single line (counts only). A failed media sample
/// verification fails the run (`media-verify`) rather than logging
/// "ok" over a corrupt copy.
///
/// No shadow-dir parameter: the DB half runs on the flusher (it owns
/// the dir and the only RW connection, A5); this thread only reads the
/// media store and writes the backup dir.
pub(crate) fn start_backup_thread(cfg: ShadowSettings, tx: Sender<Job>) {
    std::thread::Builder::new()
        .name("shadow-backup".into())
        .spawn(move || {
            let dest_root = cfg
                .backup_dir
                .as_deref()
                .map(PathBuf::from)
                .unwrap_or_default();
            // Media backups live in their own subfolder of the backup
            // dir; retention only ever touches `shadow-*` files.
            let media_dest = dest_root.join("media");
            let interval =
                Duration::from_secs(3600 * u64::from(cfg.backup_interval_hours.max(1)));
            let mut first = true;
            loop {
                let delay = if first {
                    Duration::from_secs(FIRST_RUN_SECS)
                } else {
                    interval
                };
                first = false;
                std::thread::sleep(delay);
                let (rtx, rrx) = std::sync::mpsc::channel::<DbBackupOutcome>();
                if tx.send(Job::Backup { respond: rtx }).is_err() {
                    // Flusher gone (shutdown): stop; the next launch
                    // resumes on schedule.
                    break;
                }
                let db = rrx.recv().unwrap_or_else(|_| DbBackupOutcome::failed("flusher"));
                if !db.ok {
                    crate::dlog::log(&format!(
                        "shadow backup: FAILED ({})",
                        db.kind.as_deref().unwrap_or("unknown")
                    ));
                    continue;
                }
                // Read-only on the store, on this thread (H4).
                let store = super::media::media_store_root(&cfg);
                let media = backup_media(&store, &media_dest);
                if media.verify_failed > 0 {
                    crate::dlog::log("shadow backup: FAILED (media-verify)");
                } else {
                    crate::dlog::log(&format!(
                        "shadow backup: ok (tables={} size_mb={:.1} pruned={} media_copied={})",
                        db.tables,
                        db.size as f64 / 1_048_576.0,
                        db.pruned,
                        media.copied
                    ));
                }
            }
        })
        .ok();
}

#[cfg(test)]
mod tests {
    use super::*;
    use super::super::schema;

    // Fixed test vectors (computed with PowerShell
    // [DateTimeOffset]::ToUnixTimeMilliseconds, 2026-11-20):
    //  1795161374000 = 2026-11-20T07:56:14Z
    //   951868799000 = 2000-02-29T23:59:59Z (leap day)
    //  1767225600000 = 2026-01-01T00:00:00Z (Thursday → 2026-W01)
    //  1672531200000 = 2023-01-01T00:00:00Z (Sunday → 2022-W52)
    //  1735560000000 = 2024-12-30T12:00:00Z (Monday → 2025-W01)
    //  1609459200000 = 2021-01-01T00:00:00Z (Friday → 2020-W53)
    const MS_2026_11_20: i64 = 1_795_161_374_000;

    fn scratch(tag: &str) -> PathBuf {
        let d = std::env::temp_dir().join(format!(
            "zr-backup-test-{}-{tag}-{}",
            std::process::id(),
            schema::now_ms()
        ));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).unwrap();
        d
    }

    /// Encrypted in-memory shadow DB with a few FAKE rows.
    fn db_with_rows() -> (Connection, Vec<u8>) {
        let key = sqlcipher::generate_key().unwrap();
        let conn = sqlcipher::open_in_memory(&key).unwrap();
        schema::apply(&conn).unwrap();
        conn.execute(
            "INSERT INTO messages (msg_id, conv_id, sender_id, ts, type, text, payload_json, source)
             VALUES ('m1', 'c1', 'u1', 42, 1, 'fake', '{}', 'capture')",
            [],
        )
        .unwrap();
        conn.execute(
            "INSERT INTO conversations (id, type, updated_at) VALUES ('c1', 0, 42)",
            [],
        )
        .unwrap();
        conn.execute(
            "INSERT INTO raw_events (ts, direction, kind, endpoint, payload_json)
             VALUES (42, 'in', 'ws', 'ws:2/1', '{}')",
            [],
        )
        .unwrap();
        (conn, key)
    }

    fn st(day: &str, time: &str) -> String {
        format!("{day}-{time}")
    }

    // --- stamp + date + ISO math ------------------------------------------

    #[test]
    fn stamp_vectors() {
        assert_eq!(stamp_of(0), "19700101-000000");
        assert_eq!(stamp_of(MS_2026_11_20), "20261120-075614");
        assert_eq!(stamp_of(951_868_799_000), "20000229-235959");
        // Negative pre-epoch input still renders (never happens; the
        // math must not panic).
        assert_eq!(stamp_of(-1000), "19691231-235959");
    }

    #[test]
    fn parse_stamp_roundtrips_and_rejects() {
        assert_eq!(parse_stamp("19700101-000000").unwrap().ms, 0);
        assert_eq!(parse_stamp("20261120-075614").unwrap().ms, MS_2026_11_20);
        for bad in [
            "", "x", "20261120-07561", "20261120-0756144", "20261120075614",
            "2026-1120-075614", "20261120_075614", "2026112a-075614", "20261120-07561a",
            "00000101-000000",  // before the epoch range
            "20261301-000000",  // month 13
            "20260132-000000",  // day 32
            "20260101-240000",  // hour 24
            "20260101-006000",  // minute 60
            "20260101-000060",  // second 60
        ] {
            assert!(parse_stamp(bad).is_none(), "{bad:?} must not parse");
        }
    }

    #[test]
    fn civil_date_roundtrip_over_a_hard_span() {
        // Every ISO anchor above, plus month edges across leap years.
        for &(y, m, d) in &[
            (1970i64, 1u32, 1u32),
            (2000, 2, 29),
            (2021, 1, 1),
            (2023, 1, 1),
            (2024, 12, 30),
            (2024, 12, 31),
            (2026, 1, 1),
            (2026, 11, 20),
            (2100, 2, 28), // non-leap century year
            (1999, 12, 31),
        ] {
            let days = days_from_civil(y, m, d);
            assert_eq!(civil_from_days(days), (y, m, d));
        }
        assert_eq!(days_from_civil(1970, 1, 1), 0);
    }

    #[test]
    fn iso_week_vectors() {
        let days = |y: i64, m: u32, d: u32| days_from_civil(y, m, d);
        assert_eq!(iso_week_of(days(2026, 1, 1)), (2026, 1)); // Thursday
        assert_eq!(iso_week_of(days(2023, 1, 1)), (2022, 52)); // Sunday
        assert_eq!(iso_week_of(days(2024, 12, 30)), (2025, 1)); // Monday
        assert_eq!(iso_week_of(days(2021, 1, 1)), (2020, 53)); // Friday
        // Mid-week and year-mid dates stay in their own year.
        assert_eq!(iso_week_of(days(2026, 11, 20)), (2026, 47));
        assert_eq!(iso_week_of(days(2025, 6, 15)), (2025, 24));
        assert_eq!(weeks_in_iso_year(2020), 53);
        assert_eq!(weeks_in_iso_year(2026), 53); // 2026-12-28 is Monday of W53
        assert_eq!(weeks_in_iso_year(2025), 52);
    }

    #[test]
    fn stamp_of_matches_parse_and_week_keys() {
        // stamp_of → parse is a lossless cycle (ms truncated to the
        // second), and the week key is derivable from the stamp alone.
        for &ms in &[
            0i64,
            MS_2026_11_20,
            951_868_799_000,
            1_767_225_600_000,
            1_735_560_000_000,
        ] {
            let s = stamp_of(ms);
            let p = parse_stamp(&s).unwrap();
            assert_eq!(p.ms, ms - ms.rem_euclid(1000));
            assert_eq!(p.day_key, s[..8]);
        }
    }

    // --- select_to_keep ---------------------------------------------------

    #[test]
    fn selection_empty_single_and_same_day() {
        assert!(select_to_keep(&[]).is_empty());
        let one = vec![st("20261101", "090000")];
        assert_eq!(select_to_keep(&one), HashSet::from([one[0].clone()]));
        // Three backups the same day: only the newest survives.
        let day = vec![
            st("20261101", "090000"),
            st("20261101", "120000"),
            st("20261101", "235959"),
        ];
        assert_eq!(select_to_keep(&day), HashSet::from([st("20261101", "235959")]));
        // Duplicates collapse.
        let dup = vec![st("20261101", "090000"), st("20261101", "090000")];
        assert_eq!(select_to_keep(&dup).len(), 1);
    }

    #[test]
    fn selection_keeps_seven_newest_days() {
        // 2026-11-01 is a SUNDAY and 2026-11-02 a Monday, so Nov 03
        // (Tue) .. Nov 08 (Sun) share ISO week 45 and Nov 09 (Mon),
        // Nov 10 fall in week 46.
        let mut stamps = Vec::new();
        for d in 3..=10u32 {
            stamps.push(st(&format!("202611{d:02}"), "120000"));
        }
        let keep = select_to_keep(&stamps);
        // Days 04..10 kept; day 03 is dropped — its week's newest
        // (Nov 08) is already kept, so weekly retention does NOT
        // rescue it (the union is "newest of day" OR "newest of week").
        let expected: HashSet<String> = (4..=10u32)
            .map(|d| st(&format!("202611{d:02}"), "120000"))
            .collect();
        assert_eq!(keep, expected);
        assert_eq!(keep.len(), DAILY_KEEP);
        // With two backups per day, only each day's newest is kept.
        let mut two_per = Vec::new();
        for d in 3..=10u32 {
            two_per.push(st(&format!("202611{d:02}"), "010000"));
            two_per.push(st(&format!("202611{d:02}"), "020000"));
        }
        let keep = select_to_keep(&two_per);
        let expected: HashSet<String> = (4..=10u32)
            .map(|d| st(&format!("202611{d:02}"), "020000"))
            .collect();
        assert_eq!(keep, expected);
        assert_eq!(keep.len(), DAILY_KEEP);
    }

    #[test]
    fn selection_rescues_a_day_dropped_by_daily_but_newest_of_its_week() {
        // The complement of the case above, pinned by the real
        // calendar: Sunday 2026-11-01 is the ONLY stamp of ISO week 44
        // in the input, so when the daily window drops it, weekly
        // retention keeps it (it IS its week's newest).
        let stamps = vec![
            st("20261101", "120000"), // Sun, W44 — oldest day
            st("20261102", "120000"), // Mon, W45
            st("20261103", "120000"),
            st("20261104", "120000"),
            st("20261105", "120000"),
            st("20261106", "120000"),
            st("20261107", "120000"),
            st("20261108", "120000"), // Sun, W45's newest
        ];
        let keep = select_to_keep(&stamps);
        assert!(
            keep.contains(&stamps[0]),
            "the lone Sunday is its week's newest and survives weekly retention"
        );
        assert_eq!(keep.len(), 8, "7 daily + the rescued W44 stamp");
    }

    #[test]
    fn selection_weekly_rescues_beyond_the_daily_window() {
        // 21 days, Mon 2024-12-30 .. Sun 2025-01-19: exactly three ISO
        // weeks (2025-W01..W03), one backup per day.
        let mut stamps = Vec::new();
        let mut d = days_from_civil(2024, 12, 30);
        for _ in 0..21 {
            let (y, m, dd) = civil_from_days(d);
            stamps.push(st(&format!("{y:04}{m:02}{dd:02}"), "120000"));
            d += 1;
        }
        let keep = select_to_keep(&stamps);
        // Daily: the 7 newest days = 2025-01-13..19.
        let mut expected: HashSet<String> = (13..=19u32)
            .map(|dd| st(&format!("202501{dd:02}"), "120000"))
            .collect();
        // Weekly: newest of each of the 3 weeks — W03's is 01-19
        // (already kept), W02's is 01-12, W01's is 01-05 (rescued).
        expected.insert(st("20250112", "120000"));
        expected.insert(st("20250105", "120000"));
        assert_eq!(keep, expected);
        assert_eq!(keep.len(), 9);
    }

    #[test]
    fn selection_caps_weekly_at_four() {
        // 35 days = 5 ISO weeks from Mon 2024-12-30: the 4 newest weeks
        // keep one each; the OLDEST week's newest backup is dropped.
        let mut stamps = Vec::new();
        let mut d = days_from_civil(2024, 12, 30);
        for _ in 0..35 {
            let (y, m, dd) = civil_from_days(d);
            stamps.push(st(&format!("{y:04}{m:02}{dd:02}"), "120000"));
            d += 1;
        }
        let keep = select_to_keep(&stamps);
        assert!(!keep.contains(&st("20250105", "120000")), "W01's newest is past the 4-week window");
        // Daily window = 7 newest days (2025-01-27..02-02), weekly =
        // 02-02 (W05), 01-26 (W04), 01-19 (W03), 01-12 (W02); the
        // weekly 02-02 overlaps the daily window.
        let mut expected: HashSet<String> = (27..=31u32)
            .map(|dd| st(&format!("202501{dd:02}"), "120000"))
            .collect();
        expected.extend((1..=2u32).map(|dd| st(&format!("2025020{dd}"), "120000")));
        for rescue in ["20250126", "20250119", "20250112"] {
            expected.insert(st(rescue, "120000"));
        }
        assert_eq!(keep, expected);
        assert_eq!(keep.len(), 10, "7 daily + 4 weekly − 1 overlap");
    }

    #[test]
    fn selection_ignores_unparsable_and_keeps_total_bounded() {
        let mut stamps: Vec<String> = Vec::new();
        for i in 0..40u32 {
            let dd = (i % 28) + 1;
            stamps.push(st(&format!("202610{dd:02}"), "120000"));
        }
        stamps.push("garbage".into());
        stamps.push("20261399-999999".into()); // wrong everywhere
        stamps.push("not-a-stamp".into());
        let keep = select_to_keep(&stamps);
        assert!(keep.iter().all(|s| parse_stamp(s).is_some()));
        // 7 daily + ≤4 weekly (overlaps possible) — never more.
        assert!(keep.len() <= DAILY_KEEP + WEEKLY_KEEP);
        // A valid stamp alone among garbage is kept.
        let mixed = vec![
            "garbage".to_string(),
            "20261399-999999".to_string(),
            st("20261120", "075614"),
        ];
        assert_eq!(
            select_to_keep(&mixed),
            HashSet::from([st("20261120", "075614")])
        );
    }

    // --- prune_backups (real files) ----------------------------------------

    #[test]
    fn prune_deletes_only_unkept_pattern_files() {
        let dir = scratch("prune");
        let now = parse_stamp(&st("20261201", "000000")).unwrap().ms;
        // 12 daily backups, Nov 03 (Tue) .. Nov 14 (Sat) 2026. ISO
        // weeks: 45 = Nov 02..08 (stamps 03..08), 46 = Nov 09..15
        // (stamps 09..14). Daily keeps the 7 newest days (Nov 08..14);
        // weekly keeps each week's newest — Nov 08 and Nov 14, both
        // already in the daily window — so Nov 03..07 are pruned and
        // nothing is rescued.
        for d in 3..=14u32 {
            let stamp = st(&format!("202611{d:02}"), "120000");
            std::fs::write(dir.join(format!("shadow-{stamp}.db")), b"db").unwrap();
            std::fs::write(dir.join(format!("shadow-{stamp}.json")), b"json").unwrap();
        }
        // Files that must NEVER be touched: unparsable stamp, future
        // stamp, foreign names, a leftover tmp, a bare manifest.
        std::fs::write(dir.join("shadow-20261399-999999.db"), b"x").unwrap();
        std::fs::write(dir.join("shadow-20990101-000000.db"), b"future").unwrap();
        std::fs::write(dir.join("shadow-20990101-000000.json"), b"future").unwrap();
        std::fs::write(dir.join("other.db"), b"x").unwrap();
        std::fs::write(dir.join("notes.txt"), b"x").unwrap();
        std::fs::write(dir.join("shadow-20261105-000000.db.tmp"), b"tmp").unwrap();

        let pruned = prune_backups(&dir, now);
        assert_eq!(pruned, 5, "Nov 03..07 (both .db and .json each)");
        for d in 8..=14u32 {
            let stamp = st(&format!("202611{d:02}"), "120000");
            assert!(dir.join(format!("shadow-{stamp}.db")).is_file(), "{stamp} must stay");
            assert!(dir.join(format!("shadow-{stamp}.json")).is_file(), "{stamp} manifest must stay");
        }
        for d in 3..=7u32 {
            let stamp = st(&format!("202611{d:02}"), "120000");
            assert!(!dir.join(format!("shadow-{stamp}.db")).exists(), "{stamp} must go");
            assert!(!dir.join(format!("shadow-{stamp}.json")).exists(), "{stamp} manifest must go");
        }
        // Everything outside the pattern survived.
        assert!(dir.join("shadow-20261399-999999.db").is_file(), "unparsable stamp is never deleted");
        assert!(dir.join("shadow-20990101-000000.db").is_file(), "future stamp is never deleted");
        assert!(dir.join("shadow-20990101-000000.json").is_file());
        assert!(dir.join("other.db").is_file());
        assert!(dir.join("notes.txt").is_file());
        assert!(dir.join("shadow-20261105-000000.db.tmp").is_file(), "prune never touches tmp files");
        // A future stamp must not evict real backups either: it is
        // excluded from selection, so all 7 daily keeps above held.
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn prune_keeps_everything_under_the_limits() {
        let dir = scratch("prune-small");
        let now = parse_stamp(&st("20261201", "000000")).unwrap().ms;
        for d in 1..=5u32 {
            let stamp = st(&format!("202611{d:02}"), "120000");
            std::fs::write(dir.join(format!("shadow-{stamp}.db")), b"db").unwrap();
            std::fs::write(dir.join(format!("shadow-{stamp}.json")), b"json").unwrap();
        }
        assert_eq!(prune_backups(&dir, now), 0);
        for d in 1..=5u32 {
            let stamp = st(&format!("202611{d:02}"), "120000");
            assert!(dir.join(format!("shadow-{stamp}.db")).is_file());
        }
        // An empty/missing dir prunes nothing.
        assert_eq!(prune_backups(&dir.join("nope"), now), 0);
        std::fs::remove_dir_all(&dir).unwrap();
    }

    // --- backup_db + verify_backup (in-memory encrypted source) ----------

    #[test]
    fn backup_then_verify_ok_counts_match() {
        let (conn, key) = db_with_rows();
        let dest = scratch("roundtrip");
        let manifest = backup_db(&conn, &key, &dest, MS_2026_11_20).unwrap();
        assert_eq!(manifest.ts, MS_2026_11_20);
        assert_eq!(manifest.schema_version, schema::VERSION);
        // Counts for every user table, equal to the source's.
        assert_eq!(manifest.counts, user_table_counts(&conn).unwrap());
        assert_eq!(manifest.counts.len(), 12, "schema v1 user tables");
        assert_eq!(manifest.counts["messages"], 1);
        assert_eq!(manifest.counts["raw_events"], 1);
        assert_eq!(manifest.counts["conversations"], 1);
        assert_eq!(manifest.counts["schema_meta"], 1);
        assert_eq!(manifest.sha256.len(), 64);
        assert!(manifest.size > 0);
        // The files exist, exactly as the naming pattern demands.
        let db_path = backup_db_path(&dest, MS_2026_11_20);
        let json_path = dest.join("shadow-20261120-075614.json");
        assert!(db_path.is_file());
        assert!(json_path.is_file());
        // No leftover tmp.
        assert_eq!(cleanup_leftover_tmp(&dest), 0);
        // The manifest JSON on disk parses back identical.
        let on_disk: BackupManifest =
            serde_json::from_slice(&std::fs::read(&json_path).unwrap()).unwrap();
        assert_eq!(on_disk, manifest);
        // And the full verify passes.
        assert_eq!(verify_backup(&db_path, &key, &manifest), Ok(()));
        std::fs::remove_dir_all(&dest).unwrap();
    }

    #[test]
    fn backup_removes_leftover_tmp_from_a_killed_run() {
        let (conn, key) = db_with_rows();
        let dest = scratch("tmp-clean");
        // Plant killed-run leftovers: two of OURS (shadow-*.db.tmp)
        // and one foreign file that still matches the documented
        // `*.db.tmp` leftover glob — all three go at the start of the
        // next backup (the brief's rule is the glob, and a .db.tmp is
        // by name a half-written export, never a keepsake). A file
        // outside the glob must survive.
        std::fs::write(dest.join("shadow-20261101-000000.db.tmp"), b"partial").unwrap();
        std::fs::write(dest.join("shadow-20261102-000000.db.tmp"), b"partial").unwrap();
        std::fs::write(dest.join("unrelated.db.tmp"), b"half-written-too").unwrap();
        std::fs::write(dest.join("notes.txt"), b"keep-me").unwrap();

        let manifest = backup_db(&conn, &key, &dest, MS_2026_11_20).unwrap();
        assert!(!dest.join("shadow-20261101-000000.db.tmp").exists());
        assert!(!dest.join("shadow-20261102-000000.db.tmp").exists());
        assert!(!dest.join("unrelated.db.tmp").exists(), "matches *.db.tmp — goes too");
        assert!(dest.join("notes.txt").is_file(), "outside the glob — stays");
        // The fresh backup is complete.
        assert_eq!(
            verify_backup(&backup_db_path(&dest, manifest.ts), &key, &manifest),
            Ok(())
        );
        std::fs::remove_dir_all(&dest).unwrap();
    }

    #[test]
    fn corrupt_one_byte_fails_the_verify() {
        let (conn, key) = db_with_rows();
        let dest = scratch("corrupt");
        let manifest = backup_db(&conn, &key, &dest, MS_2026_11_20).unwrap();
        let db_path = backup_db_path(&dest, MS_2026_11_20);
        // Flip one byte mid-file.
        let mut bytes = std::fs::read(&db_path).unwrap();
        assert!(bytes.len() > 64);
        let mid = bytes.len() / 2;
        bytes[mid] ^= 0xFF;
        std::fs::write(&db_path, &bytes).unwrap();
        // sha256 is checked first: the manifest no longer describes
        // the file.
        assert_eq!(
            verify_backup(&db_path, &key, &manifest),
            Err("sha256-mismatch".into())
        );
        // With the sha papered over, the open/integrity layer must
        // still refuse the corrupt file.
        let mut fixed = manifest.clone();
        fixed.sha256 = file_sha256(&db_path).unwrap();
        let err = verify_backup(&db_path, &key, &fixed).unwrap_err();
        assert!(
            err != "sha256-mismatch" && err != "count-mismatch",
            "the corruption must be caught below the sha layer, got {err}"
        );
        std::fs::remove_dir_all(&dest).unwrap();
    }

    #[test]
    fn restore_open_with_wrong_key_fails() {
        let (conn, key) = db_with_rows();
        let dest = scratch("wrong-key");
        let manifest = backup_db(&conn, &key, &dest, MS_2026_11_20).unwrap();
        let db_path = backup_db_path(&dest, MS_2026_11_20);
        let wrong = sqlcipher::generate_key().unwrap();
        assert!(
            sqlcipher::open_with_key_readonly(&db_path, &wrong).is_err(),
            "a wrong key must be refused at open"
        );
        // verify_backup fails with the open kind (sha passes first —
        // it is key-independent; the keyed open then refuses).
        assert_eq!(verify_backup(&db_path, &wrong, &manifest), Err("open".into()));
        // And the right key still passes.
        assert_eq!(verify_backup(&db_path, &key, &manifest), Ok(()));
        std::fs::remove_dir_all(&dest).unwrap();
    }

    #[test]
    fn count_mismatch_fails_the_verify() {
        let (conn, key) = db_with_rows();
        let dest = scratch("counts");
        let manifest = backup_db(&conn, &key, &dest, MS_2026_11_20).unwrap();
        let db_path = backup_db_path(&dest, MS_2026_11_20);
        let mut forged = manifest.clone();
        *forged.counts.get_mut("messages").unwrap() += 1;
        assert_eq!(verify_backup(&db_path, &key, &forged), Err("count-mismatch".into()));
        // A missing table in the manifest is a mismatch too.
        let mut stripped = manifest.clone();
        stripped.counts.remove("messages");
        assert_eq!(verify_backup(&db_path, &key, &stripped), Err("count-mismatch".into()));
        std::fs::remove_dir_all(&dest).unwrap();
    }

    #[test]
    fn plaintext_backup_when_key_is_empty() {
        // The encrypt=false store: an unencrypted source exports to an
        // unencrypted backup that verifies with an empty key.
        let conn = rusqlite::Connection::open_in_memory().unwrap();
        schema::apply(&conn).unwrap();
        let dest = scratch("plain");
        let manifest = backup_db(&conn, &[], &dest, MS_2026_11_20).unwrap();
        let db_path = backup_db_path(&dest, MS_2026_11_20);
        assert_eq!(verify_backup(&db_path, &[], &manifest), Ok(()));
        // A keyed open must NOT work on the plaintext backup.
        let wrong = sqlcipher::generate_key().unwrap();
        assert!(verify_backup(&db_path, &wrong, &manifest).is_err());
        std::fs::remove_dir_all(&dest).unwrap();
    }

    // --- H2: media backup --------------------------------------------------

    /// Write `bytes` into `root/ab/cd/<sha256(bytes)>` (fake content,
    /// real content-addressed name) and return the relative path.
    fn store_file(root: &Path, bytes: &[u8]) -> (PathBuf, String) {
        let sha = {
            let mut h = Sha256::new();
            h.update(bytes);
            format!("{:x}", h.finalize())
        };
        let rel = format!("{}/{}/{}", &sha[0..2], &sha[2..4], sha);
        let path = root.join(&rel);
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(&path, bytes).unwrap();
        (path, rel)
    }

    #[test]
    fn media_backup_copies_missing_and_never_deletes_or_overwrites() {
        let store = scratch("media-store");
        let dest = scratch("media-dest");
        // Three fake files named by their real sha256.
        let (_, r1) = store_file(&store, b"fake-bytes-1");
        let (_, r2) = store_file(&store, b"fake-bytes-2");
        let (_, r3) = store_file(&store, b"fake-bytes-3");

        // Pre-plant one file in the dest with WRONG content under the
        // right name: it must be neither overwritten nor deleted.
        let planted = dest.join(&r3);
        std::fs::create_dir_all(planted.parent().unwrap()).unwrap();
        std::fs::write(&planted, b"planted-imposter").unwrap();

        let report = backup_media(&store, &dest);
        assert_eq!(report.scanned, 3);
        assert_eq!(report.copied, 2, "the planted name counts as present");
        assert_eq!(report.copy_failed, 0);
        assert!(report.verify_failed == 0, "copied bytes match their names");
        assert!(report.verified >= 1, "at least one copied file is sampled");
        // The two missing files landed…
        for rel in [&r1, &r2] {
            let to = dest.join(rel);
            assert!(to.is_file(), "{rel} must exist in the dest");
        }
        // …and the imposter is byte-for-byte untouched.
        assert_eq!(
            std::fs::read(&planted).unwrap(),
            b"planted-imposter",
            "never overwrite what is already in the dest"
        );
        // Nothing was deleted from the dest: the planted file plus the
        // two copies are all there is (counted recursively — the `ab`
        // level may dedupe to fewer dirs).
        let count_files = |root: &Path| -> usize {
            fn walk(dir: &Path, n: &mut usize) {
                for e in std::fs::read_dir(dir).unwrap().flatten() {
                    if e.path().is_dir() {
                        walk(&e.path(), n);
                    } else {
                        *n += 1;
                    }
                }
            }
            let mut n = 0usize;
            walk(root, &mut n);
            n
        };
        assert_eq!(count_files(&dest), 3, "3 files total: 2 copied + 1 planted");
        // No tmp files left behind anywhere.
        fn assert_no_tmp(dir: &Path) {
            for e in std::fs::read_dir(dir).unwrap().flatten() {
                if e.path().is_dir() {
                    assert_no_tmp(&e.path());
                } else {
                    assert!(
                        !e.file_name().to_string_lossy().ends_with(".tmp"),
                        "no .tmp leftovers in the dest"
                    );
                }
            }
        }
        assert_no_tmp(&dest);

        // A second run is a no-op (incremental).
        let report2 = backup_media(&store, &dest);
        assert_eq!(report2.scanned, 3);
        assert_eq!(report2.copied, 0);
        assert_eq!(report2.verified, 0);
        assert_eq!(report2.verify_failed, 0);
        assert_eq!(count_files(&dest), 3, "still 3 — nothing added or removed");
        std::fs::remove_dir_all(&store).unwrap();
        std::fs::remove_dir_all(&dest).unwrap();
    }

    #[test]
    fn media_backup_skips_non_store_layout() {
        let store = scratch("media-layout");
        let dest = scratch("media-layout-dest");
        store_file(&store, b"real");
        // Root-level tmp download leftovers and foreign files: not
        // part of the ab/cd/<sha> layout, never scanned or copied.
        std::fs::write(store.join(".dl-7.tmp"), b"partial").unwrap();
        std::fs::write(store.join("notes.txt"), b"x").unwrap();
        // A file at depth 2 whose name is not a sha.
        std::fs::create_dir_all(store.join("ab/cd")).unwrap();
        std::fs::write(store.join("ab/cd/not-a-sha-name"), b"x").unwrap();
        // Uppercase hex name (store names are lowercase).
        std::fs::write(store.join("ab/cd").join("A".repeat(64)), b"x").unwrap();

        let report = backup_media(&store, &dest);
        assert_eq!(report.scanned, 1, "only the one real store file");
        assert_eq!(report.copied, 1);
        assert_eq!(report.verify_failed, 0);
        assert!(!dest.join("notes.txt").exists());
        assert!(!dest.join("ab/cd/not-a-sha-name").exists());
        std::fs::remove_dir_all(&store).unwrap();
        std::fs::remove_dir_all(&dest).unwrap();
    }

    #[test]
    fn media_backup_missing_store_is_all_zeroes() {
        let dest = scratch("media-none");
        let report = backup_media(&PathBuf::from(r"N:\definitely\missing\zr"), &dest);
        assert_eq!(report, MediaBackupReport::default());
        std::fs::remove_dir_all(&dest).unwrap();
    }

    #[test]
    fn verify_sample_catches_corruption() {
        let dir = scratch("sample");
        let (good, _) = store_file(&dir, b"good-bytes");
        // A file whose name lies about its content.
        let mut h = Sha256::new();
        h.update(b"other-bytes");
        let wrong_name = format!("{:x}", h.finalize());
        let bad = dir.join("zz").join(&wrong_name);
        std::fs::create_dir_all(bad.parent().unwrap()).unwrap();
        std::fs::write(&bad, b"corrupted").unwrap();
        let (ok, failed) = verify_sample(&[good, bad.clone()]);
        assert_eq!((ok, failed), (1, 1));
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn random_sample_is_in_range_and_sized() {
        // No distribution test (would be flaky): range, distinctness
        // and size only — the uniformity comes from the rejection
        // sampling above.
        for (len, n) in [(0usize, 0usize), (1, 1), (5, 3), (100, 1), (250, 2)] {
            let picks = random_sample(len, n);
            assert_eq!(picks.len(), n.min(len));
            let mut sorted = picks.clone();
            sorted.sort_unstable();
            sorted.dedup();
            assert_eq!(sorted.len(), picks.len(), "picks are distinct");
            assert!(picks.iter().all(|&i| i < len));
        }
    }
}

/// H5 (reviewer-run): full backup+verify round trip against a temp
/// COPY of the live store — never the live dir.
///
/// Run: `cargo test --lib probe_backup_restore -- --ignored --nocapture`
#[cfg(test)]
mod probe_backup_restore {
    use super::*;
    use super::super::probe_util;
    use std::time::Instant;

    /// name -> (len, mtime) of every file in `dir` — metadata only,
    /// the DB itself is never opened here.
    fn fingerprint(dir: &Path) -> std::collections::BTreeMap<String, (u64, std::time::SystemTime)> {
        let mut out = std::collections::BTreeMap::new();
        if let Ok(entries) = std::fs::read_dir(dir) {
            for e in entries.flatten() {
                if let Ok(md) = e.metadata() {
                    out.insert(
                        e.file_name().to_string_lossy().into_owned(),
                        (md.len(), md.modified().unwrap_or(std::time::SystemTime::UNIX_EPOCH)),
                    );
                }
            }
        }
        out
    }

    #[test]
    #[ignore = "copies the live store to a temp dir and runs a real backup — reviewer-run"]
    fn probe_backup_restore() {
        // H-rule: the live dir is fingerprinted (metadata only) and
        // asserted UNCHANGED at the end — the backup runs from a temp
        // COPY, so this can never fire, but it is the assert the
        // reviewer asked for.
        let live = probe_util::probe_dir();
        let before = fingerprint(&live);

        // A temp COPY of the live set, opened read-write (the copy
        // plays the flusher's connection; the live dir is never
        // opened — probe_util's structural guarantee).
        let (src, tmp) = probe_util::open_copy_rw();
        let key_path = super::super::key_file(&tmp);
        let key = if key_path.exists() {
            Zeroizing::new(sqlcipher::load_key(&key_path).expect("load the copy's key"))
        } else {
            Zeroizing::new(Vec::new())
        };

        // A fresh dest under the OS temp dir.
        let dest = std::env::temp_dir().join(format!(
            "zr-backup-probe-{}-{}",
            std::process::id(),
            schema::now_ms()
        ));
        std::fs::create_dir_all(&dest).unwrap();

        let now = schema::now_ms();
        let t0 = Instant::now();
        let manifest = backup_db(&src, &key, &dest, now).expect("backup_db on the copy");
        let export_ms = t0.elapsed().as_millis();
        let db_path = backup_db_path(&dest, manifest.ts);

        let t1 = Instant::now();
        let verdict = verify_backup(&db_path, &key, &manifest);
        let verify_ms = t1.elapsed().as_millis();
        let pruned = prune_backups(&dest, manifest.ts);

        // Shape-only report (audit probe style): counts + timings.
        let rows: i64 = manifest.counts.values().sum();
        println!(
            "probe_backup_restore: tables={} rows_total={} size_bytes={} schema_version={}",
            manifest.counts.len(),
            rows,
            manifest.size,
            manifest.schema_version
        );
        println!(
            "  verdict={} export_ms={} verify_ms={} pruned={}",
            if verdict.is_ok() { "ok" } else { "FAILED" },
            export_ms,
            verify_ms,
            pruned
        );
        for (table, n) in &manifest.counts {
            println!("  {table}={n}");
        }
        assert_eq!(pruned, 0, "a fresh probe backup never prunes itself");
        assert!(verdict.is_ok(), "verify_backup must pass: {:?}", verdict.err());

        // The dest is a temp child, never the live dir…
        assert_ne!(dest, live);
        assert!(dest.starts_with(std::env::temp_dir()));
        // …and the live dir is byte-for-byte unchanged.
        let after = fingerprint(&live);
        assert_eq!(before, after, "the live store dir must never be written");
    }
}
