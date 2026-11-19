//! Probe access to the live shadow DB ALWAYS goes through a COPY
//! (audit M2-6, batch 5 E0).
//!
//! A READ_ONLY SQLite connection in WAL mode still creates/touches the
//! live `-shm` (and a fresh reader can force a checkpoint): "read
//! only" is NOT "0 ghi" while the app is soaking. Every probe therefore
//! copies `default.db` + `-wal` + `-shm` + `default.key` into a unique
//! temp dir and opens THAT — the live store is never opened at all.
//! Copies are left on disk (cheap; `maint_repair` deliberately leaves
//! its copy for the reviewer to inspect).
//!
//! H-rule: nothing here prints; callers print shapes only.
//!
//! Env overrides (both optional):
//! - `ZR_PROBE_DIR` — the live store dir to copy from (default
//!   `%LOCALAPPDATA%\com.o365serveronms.zalors\shadow`);
//! - `ZR_PROBE_SINCE_ID` — `raw_events` id baseline for coverage
//!   probes (default 0 = scan the whole ring).

use std::path::{Path, PathBuf};

use rusqlite::Connection;
use sha2::{Digest, Sha256};

use crate::migrate::sqlcipher;

/// The live store dir the probes copy from (`ZR_PROBE_DIR` override,
/// else the documented Roaming path).
pub fn probe_dir() -> PathBuf {
    if let Some(p) = std::env::var_os("ZR_PROBE_DIR") {
        if !p.is_empty() {
            return PathBuf::from(p);
        }
    }
    default_probe_dir(std::env::var_os("LOCALAPPDATA").unwrap_or_default())
}

/// `%LOCALAPPDATA%\com.o365serveronms.zalors\shadow` — the pure part of
/// [`probe_dir`], unit-tested without touching process env.
fn default_probe_dir(local: std::ffi::OsString) -> PathBuf {
    PathBuf::from(local)
        .join("com.o365serveronms.zalors")
        .join("shadow")
}

/// The file set copied for one probe: `<account>.db` + `-wal`/`-shm`
/// (when present) + `<account>.key`. The KQ10 account helpers own the
/// names — nothing here hardcodes "default".
fn live_set(dir: &Path) -> Vec<PathBuf> {
    let db = super::db_file(dir);
    let mut out = vec![db.clone()];
    for suffix in ["-wal", "-shm"] {
        let name = format!("{}{suffix}", db.file_name().unwrap().to_string_lossy());
        out.push(dir.join(name));
    }
    out.push(super::key_file(dir));
    out
}

/// The structural guarantee behind E4: everything this module opens is
/// a fresh child of the OS temp dir, never the live store.
fn assert_is_temp_copy(tmp: &Path) {
    assert!(
        tmp.starts_with(std::env::temp_dir()),
        "probe copy must live under the OS temp dir"
    );
    assert_ne!(tmp, probe_dir(), "probe copy must never be the live dir");
}

/// Copy the live set into a fresh `zr-probe-<pid>-<ms>-<seq>` dir under
/// the OS temp dir (same uniqueness pattern as `golden::open_oracle`:
/// pid+ms alone collided with parallel tests) and return the dir. The
/// copy is left on disk.
pub fn copy_live_set() -> PathBuf {
    static SEQ: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
    let tmp = std::env::temp_dir().join(format!(
        "zr-probe-{}-{}-{}",
        std::process::id(),
        super::schema::now_ms(),
        SEQ.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
    ));
    std::fs::create_dir_all(&tmp).unwrap();
    assert_is_temp_copy(&tmp);
    for from in live_set(&probe_dir()) {
        if !from.exists() {
            continue; // -wal/-shm are absent on a checkpointed store
        }
        let to = tmp.join(from.file_name().unwrap());
        std::fs::copy(&from, &to).unwrap();
        // Copies can inherit a read-only attribute (the frozen oracle
        // dir has one); clear it so SQLite can use the temp -shm.
        let mut perm = std::fs::metadata(&to).unwrap().permissions();
        #[allow(clippy::permissions_set_readonly_false)]
        perm.set_readonly(false);
        std::fs::set_permissions(&to, perm).unwrap();
    }
    tmp
}

fn open_at(tmp: &Path, readonly: bool) -> Connection {
    let key = sqlcipher::load_key(&super::key_file(tmp)).unwrap();
    let db = super::db_file(tmp);
    if readonly {
        sqlcipher::open_with_key_readonly(&db, &key).unwrap()
    } else {
        sqlcipher::open_with_key(&db, &key).unwrap()
    }
}

/// Open a COPY of the live DB read-only. Returns the connection plus
/// the temp dir holding the copy (left on disk).
pub fn open_copy() -> (Connection, PathBuf) {
    let tmp = copy_live_set();
    (open_at(&tmp, true), tmp)
}

/// Open a COPY of the live DB read-WRITE — maintenance probes only
/// (E4: `repair_v1` on a copy). The temp-copy assertion makes it
/// impossible for this helper to hand out a live-path connection.
pub fn open_copy_rw() -> (Connection, PathBuf) {
    let tmp = copy_live_set();
    assert_is_temp_copy(&tmp);
    (open_at(&tmp, false), tmp)
}

/// The `raw_events` id baseline for coverage probes (`ZR_PROBE_SINCE_ID`;
/// default 0 = the whole ring; an unparsable value falls back to 0 —
/// coverage must never silently skip rows).
pub fn since_id() -> i64 {
    parse_since(std::env::var("ZR_PROBE_SINCE_ID").ok().as_deref())
}

/// The pure part of [`since_id`], unit-tested without touching process env.
fn parse_since(raw: Option<&str>) -> i64 {
    raw.and_then(|s| s.trim().parse::<i64>().ok()).unwrap_or(0)
}

/// sha256 hex of `s`, first 12 chars — the probe-safe id fingerprint.
pub fn h12(s: &str) -> String {
    let mut h = Sha256::new();
    h.update(s.as_bytes());
    let hex = format!("{:x}", h.finalize());
    hex.chars().take(12).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    // Pure parts only (E0): h12 + env parsing + name derivation. The
    // copy itself is exercised by the ignored probes on real data.

    #[test]
    fn h12_known_vectors_and_shape() {
        // sha256("abc")  = ba7816bf8f01cfea4141…
        // sha256("")     = e3b0c44298fc1c14…
        assert_eq!(h12("abc"), "ba7816bf8f01");
        assert_eq!(h12(""), "e3b0c44298fc");
        // Always exactly 12 lowercase hex chars; never equal for
        // different inputs.
        for s in ["x", "fake-msg-id", "1234567890123456789"] {
            let h = h12(s);
            assert_eq!(h.len(), 12, "{s:?}");
            assert!(h.bytes().all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase()));
        }
        assert_ne!(h12("a"), h12("b"));
    }

    #[test]
    fn parse_since_shapes() {
        assert_eq!(parse_since(None), 0);
        assert_eq!(parse_since(Some("0")), 0);
        assert_eq!(parse_since(Some("42")), 42);
        assert_eq!(parse_since(Some(" -7 ")), -7, "trimmed");
        // Unparsable/empty fall back to 0 (scan the whole ring).
        assert_eq!(parse_since(Some("")), 0);
        assert_eq!(parse_since(Some("abc")), 0);
        assert_eq!(parse_since(Some("12x3")), 0);
    }

    #[test]
    fn default_probe_dir_is_the_documented_path() {
        assert_eq!(
            default_probe_dir(std::ffi::OsString::from(r"C:\Users\u\AppData\Local")),
            PathBuf::from(r"C:\Users\u\AppData\Local\com.o365serveronms.zalors\shadow")
        );
    }

    #[test]
    fn live_set_names_follow_the_account_helpers() {
        // Pure: the copy set is exactly db + -wal + -shm + key as the
        // KQ10 account helpers name them.
        let dir = Path::new(r"D:\shadow");
        assert_eq!(
            live_set(dir),
            vec![
                super::super::db_file(dir),
                dir.join("default.db-wal"),
                dir.join("default.db-shm"),
                super::super::key_file(dir),
            ]
        );
    }
}
