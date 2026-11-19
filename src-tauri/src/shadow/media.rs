//! P1b media auto-download (D8/D11, rebuild 2026-11-19).
//!
//! Rules (handoff):
//! - Only NEW media (attachments rows with status='ref' created by the
//!   writer from live traffic) — never a backfill scan of history.
//! - Rate-limited: one download at a time, a pause between files.
//! - Content-addressed store: `<root>/ab/cd/<sha256>`; the file lands
//!   via a .tmp + rename so a partial download never masquerades as a
//!   good one.
//! - Root resolution order: `settings.shadow.media_store`, else
//!   `D:\ZaloRust Data` when it exists (D11 decision for this install),
//!   else `<LOCALAPPDATA>\com.o365serveronms.zalors\ZaloRust Data`.
//! - The downloader keeps its OWN SQLCipher connection (WAL allows
//!   multiple connections); the flusher stays the only writer of domain
//!   rows, this thread only flips `attachments.status`.

use std::path::{Path, PathBuf};
use std::time::Duration;

use rusqlite::Connection;
use sha2::{Digest, Sha256};

use crate::migrate::sqlcipher;
use crate::settings::ShadowSettings;

/// Start the downloader thread (call once per process, after the DB
/// exists). Best-effort: failures are logged and retried next cycle.
pub fn start(dir: PathBuf, cfg: ShadowSettings) {
    std::thread::Builder::new()
        .name("shadow-media".into())
        .spawn(move || {
            let root = media_store_root(&cfg);
            let _ = std::fs::create_dir_all(&root);
            crate::dlog::log(&format!("shadow media: store at {}", root.display()));
            // One long-lived connection; reopen if it dies.
            let mut conn = open(&dir, &cfg);
            let mut backoff = 30u64;
            loop {
                std::thread::sleep(Duration::from_secs(backoff.max(5)));
                if conn.is_none() {
                    conn = open(&dir, &cfg);
                    continue;
                }
                let c = conn.as_ref().unwrap();
                let Ok(n) = download_one_cycle(c, &root) else {
                    crate::dlog::log("shadow media: DB error, reopening");
                    conn = None;
                    continue;
                };
                match n {
                    0 => backoff = 30,
                    n => {
                        backoff = 10;
                        crate::dlog::log(&format!("shadow media: downloaded {n} file(s)"));
                    }
                }
            }
        })
        .ok();
}

fn open(dir: &Path, cfg: &ShadowSettings) -> Option<Connection> {
    let key_path = dir.join("default.key");
    let Ok(key) = sqlcipher::load_key(&key_path) else {
        return None;
    };
    if !cfg.encrypt {
        return rusqlite::Connection::open(dir.join("default.db")).ok();
    }
    sqlcipher::open_with_key(&dir.join("default.db"), &key).ok()
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

/// One cycle: pick pending refs (oldest first), download up to a small
/// cap, flip statuses. Returns how many files landed.
fn download_one_cycle(conn: &Connection, root: &Path) -> Result<usize, rusqlite::Error> {
    let cap = 8usize;
    let mut st = conn.prepare(
        "SELECT rowid, msg_id, idx, kind, url FROM attachments \
         WHERE status = 'ref' AND url IS NOT NULL AND url LIKE 'https://%' \
         ORDER BY rowid LIMIT ?1",
    )?;
    let rows: Vec<(i64, String, i64, String, String)> = st
        .query_map([cap as i64], |r| {
            Ok((
                r.get(0)?,
                r.get(1)?,
                r.get(2)?,
                r.get(3)?,
                r.get(4)?,
            ))
        })?
        .filter_map(Result::ok)
        .collect();
    drop(st);
    let mut done = 0usize;
    for (rowid, msg_id, _idx, kind, url) in rows {
        match fetch_to_store(&url, root) {
            Ok((path, sha, size)) => {
                conn.execute(
                    "UPDATE attachments SET status='downloaded', local_path=?1, sha256=?2, size=?3 \
                     WHERE rowid = ?4",
                    rusqlite::params![path.to_string_lossy(), sha, size, rowid],
                )?;
                done += 1;
                let _ = msg_id;
                let _ = kind;
            }
            Err(e) => {
                // Network failures are normal (expired CDN urls); mark
                // failed so we do not loop on them forever.
                conn.execute(
                    "UPDATE attachments SET status='failed' WHERE rowid = ?1",
                    [rowid],
                )?;
                crate::dlog::log(&format!(
                    "shadow media: download failed ({}) — marked failed",
                    e.to_string().chars().take(80).collect::<String>()
                ));
            }
        }
        std::thread::sleep(Duration::from_millis(700));
    }
    Ok(done)
}

/// GET the url into the content-addressed store. Returns (final path,
/// sha256 hex, size). Never writes the plaintext-keyed name — content
/// hash only, so duplicates dedupe naturally.
fn fetch_to_store(url: &str, root: &Path) -> Result<(PathBuf, String, u64), Box<dyn std::error::Error>> {
    let agent: ureq::Agent = ureq::Agent::config_builder()
        .timeout_connect(Some(Duration::from_secs(20)))
        .timeout_recv_response(Some(Duration::from_secs(30)))
        .timeout_recv_body(Some(Duration::from_secs(60)))
        .build()
        .into();
    let mut reader = agent.get(url).call()?.into_body().into_reader();
    // Stream to a temp file while hashing.
    use std::io::Read;
    let tmp = root.join(format!(".dl-{}.tmp", std::process::id()));
    let mut file = std::fs::File::create(&tmp)?;
    let mut hasher = Sha256::new();
    let mut buf = [0u8; 64 * 1024];
    let mut size: u64 = 0;
    loop {
        let n = reader.read(&mut buf)?;
        if n == 0 {
            break;
        }
        hasher.update(&buf[..n]);
        std::io::Write::write_all(&mut file, &buf[..n])?;
        size += n as u64;
        if size > 512 * 1024 * 1024 {
            let _ = std::fs::remove_file(&tmp);
            return Err("file exceeds 512 MB cap".into());
        }
    }
    drop(file);
    let sha = format!("{:x}", hasher.finalize());
    let sub = root.join(&sha[0..2]).join(&sha[2..4]);
    std::fs::create_dir_all(&sub)?;
    let final_path = sub.join(&sha);
    match std::fs::rename(&tmp, &final_path) {
        Ok(()) => {}
        Err(_) => {
            // Windows rename-over-existing: fine if the target exists.
            if !final_path.exists() {
                let _ = std::fs::remove_file(&tmp);
                return Err("store rename failed".into());
            }
            let _ = std::fs::remove_file(&tmp);
        }
    }
    Ok((final_path, sha, size))
}
