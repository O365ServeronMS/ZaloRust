//! Zalo Desktop DB import (P2 skeleton — structure first, mapping next).
//!
//! Source layout (verified 2026-11-12/13, Zalo Desktop 26.11.12):
//! ```text
//! <dir>/  (D:\Zalo Data\message\Database\_production)
//!   <uid>/Core\Index.db          93 tables (conversations, contacts…)
//!   <uid>/Core\Message\g<id>.db  per-conversation message DBs (SQLCipher)
//!   <uid>/MsgInfo.db, Meta.db, E2ee.db, …
//! ```
//! All cipher DBs use the SAME key: the UIN string (len 32, sha256-12 =
//! `dca62c394a68` for this install). The key is provided ONLY through the
//! DPAPI-wrapped D7 capture file (`--key-file`), never as a CLI value.
//!
//! Safety (P2 acceptance):
//! - Every source DB opens READ_ONLY (SQLCipher cannot create -wal/-shm in
//!   that mode — the old dry-run's one flaw, fixed by construction).
//! - Import writes carry `source='import'`; the writer never lets an
//!   import row overwrite capture plaintext.
//! - `--apply` is explicit; default is a dry run that only counts.

use std::path::Path;

use rusqlite::Connection;
use serde_json::Value;

use super::writer;
use crate::migrate::sqlcipher;

#[derive(Debug, Default, Clone)]
pub struct Summary {
    pub conversations: usize,
    pub messages: usize,
    pub groups: usize,
    pub contacts: usize,
    pub skipped_dbs: usize,
}

/// Unwrap a DPAPI-wrapped key file captured by the D7 technique.
/// `label` is the entropy string used at wrap time (`zalors.d7` for the
/// 2026-11-19 capture).
pub fn load_labeled_key(path: &Path, label: &str) -> Result<Vec<u8>, String> {
    let blob = std::fs::read(path).map_err(|e| e.to_string())?;
    sqlcipher::unwrap_with_label(&blob, label).map_err(|e| e.to_string())
}

/// Run the import over the production dir.
pub fn run(
    from: &Path,
    account: &str,
    uin_hash: &str,
    key_file: Option<&Path>,
    apply: bool,
) -> Result<Summary, String> {
    // The DB root: <from>\<uid...>. We take the first uid-shaped child
    // unless the account id narrows it.
    let uid_dir = resolve_uid_dir(from, account).ok_or("no account directory under --from-zalo-pc")?;
    let key = match key_file {
        Some(p) => load_labeled_key(p, "zalors.d7")?,
        None => {
            return Err("missing --key-file (D7 capture); the UIN key is never passed as text".into())
        }
    };
    if key.len() != 32 {
        return Err(format!("unexpected key length {}", key.len()));
    }
    // Verify the key matches the expected uin hash before touching anything.
    use sha2::{Digest, Sha256};
    let got = Sha256::digest(&key);
    let got12 = got.iter().take(6).map(|b| format!("{b:02x}")).collect::<String>();
    if !uin_hash.is_empty() && got12 != uin_hash.to_lowercase() {
        return Err(format!("key/uin-hash mismatch: file hashes to {got12}"));
    }

    let mut s = Summary::default();
    // 1) Index.db — conversation + contact inventory (read-only).
    let index = uid_dir.join("Core").join("Index.db");
    if index.exists() {
        match open_readonly(&index, &key) {
            Ok(conn) => {
                count(&conn, &mut s, apply);
            }
            Err(e) => return Err(format!("Index.db open failed: {e}")),
        }
    } else {
        s.skipped_dbs += 1;
    }
    // 2) Per-conversation message DBs (mapping: next phase).
    let msg_dir = uid_dir.join("Core").join("Message");
    if let Ok(rd) = std::fs::read_dir(&msg_dir) {
        for entry in rd.flatten() {
            let p = entry.path();
            let name = p.file_name().and_then(|n| n.to_str()).unwrap_or("");
            if name.ends_with(".db") && name.starts_with('g') {
                s.skipped_dbs += 1; // counted for now; import mapping TODO
            }
        }
    }
    if apply {
        return Err("--apply not wired in this rebuild phase yet (dry-run only, fail-closed)".into());
    }
    Ok(s)
}

fn resolve_uid_dir(from: &Path, account: &str) -> Option<std::path::PathBuf> {
    // `account` is the ZaloRust account id ("default"); the on-disk child
    // is the Zalo uid (19 digits for this install). First numeric child wins.
    let direct = from.join(account);
    if direct.is_dir() {
        return Some(direct);
    }
    for entry in std::fs::read_dir(from).ok()?.flatten() {
        let name = entry.file_name().to_string_lossy().into_owned();
        if name.bytes().all(|b| b.is_ascii_digit()) && !name.is_empty() {
            return Some(entry.path());
        }
    }
    None
}

fn open_readonly(path: &Path, key: &[u8]) -> Result<Connection, String> {
    sqlcipher::open_with_key_readonly(path, key).map_err(|e| e.to_string())
}

fn count(conn: &Connection, s: &mut Summary, _apply: bool) {
    // Read-only inventory. Table names follow the Desktop schema (93
    // tables in Index.db); the mapping to shadow rows is the next phase,
    // so a dry run reports what it can see without guessing.
    let one = |sql: &str| -> usize {
        conn.query_row(sql, [], |r| r.get::<_, i64>(0))
            .map(|n| n as usize)
            .unwrap_or(0)
    };
    s.conversations += one("SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name LIKE '%conv%'");
    s.contacts += one("SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name LIKE '%contact%'");
    s.groups += one("SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name LIKE '%group%'");
    s.messages += one("SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name LIKE '%msg%'");
    let _ = Value::Null;
    let _ = writer::trim_raw_events;
}
