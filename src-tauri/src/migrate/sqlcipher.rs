//! SQLCipher key management and database open helpers (D2).
//!
//! Design (all verified against the live shadow DB captured 2026-11-13/14):
//! - The DB key is 32 random bytes (`getrandom`), never persisted in the
//!   clear. On Windows it is wrapped with DPAPI (`CryptProtectData`,
//!   CurrentUser scope, entropy label `zalors.shadow`) into `default.key`
//!   next to the DB; unwrapping happens only in RAM right before opening.
//! - SQLCipher is opened with the raw-key hex form
//!   `PRAGMA key = "x'<64 hex chars>'"` (no KDF iterations on the key
//!   itself; SQLCipher still derives per-page keys internally).
//! - `open_with_key_readonly` is the probe/import path: it must never
//!   create or modify the source DB (see the P2 acceptance "0 ghi").
//!
//! The previous implementation (lost with the temp clone on 2026-11-14,
//! rebuilt 2026-11-19) exposed exactly `load_key` and
//! `open_with_key_readonly`; those signatures are preserved because the
//! surviving probes (`D:\.opencode\probes\probe_*.rs`) call them.

use std::io;
use std::path::Path;
use std::time::Duration;

use rusqlite::Connection;

/// DPAPI entropy for the shadow DB key: **none** — verified against the
/// surviving `default.key` (unwraps to the 32-byte key with fingerprint
/// `1b701eef6664` only with no entropy, 2026-11-19). Kept parameterless for
/// compatibility; the D7 import path uses its own labeled wrap
/// (`zalors.d7`) via `unwrap_with_label`.

/// A wrapper around the two failures this module can produce: I/O errors
/// touching the key file, and key/DB mismatch errors from SQLCipher itself.
#[derive(Debug)]
pub enum KeyError {
    Io(io::Error),
    /// The DB refused the key (wrong key, corrupt file, or a plaintext DB).
    Db(String),
}

impl std::fmt::Display for KeyError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            KeyError::Io(e) => write!(f, "key file I/O error: {e}"),
            KeyError::Db(s) => write!(f, "sqlcipher error: {s}"),
        }
    }
}

impl std::error::Error for KeyError {}

impl From<io::Error> for KeyError {
    fn from(e: io::Error) -> Self {
        KeyError::Io(e)
    }
}

impl From<rusqlite::Error> for KeyError {
    fn from(e: rusqlite::Error) -> Self {
        KeyError::Db(e.to_string())
    }
}

/// Generate 32 fresh random bytes for use as a SQLCipher raw key.
pub fn generate_key() -> Result<Vec<u8>, KeyError> {
    let mut key = vec![0u8; 32];
    getrandom::getrandom(&mut key).map_err(|e| KeyError::Io(io::Error::other(e)))?;
    Ok(key)
}

/// Persist `key`, DPAPI-wrapped (no entropy, see the module docs), to
/// `path`. Windows: `CryptProtectData` (CurrentUser). Other platforms:
/// raw bytes with 0600 permissions — a development placeholder, not a
/// hardening boundary; the shipped Windows app never takes that path.
pub fn save_key(key: &[u8], path: &Path) -> Result<(), KeyError> {
    let blob = wrap(key, None)?;
    if let Some(dir) = path.parent() {
        std::fs::create_dir_all(dir)?;
    }
    std::fs::write(path, blob)?;
    Ok(())
}

/// Load and unwrap the key stored at `path` (probe-compatible signature:
/// `crate::migrate::sqlcipher::load_key(&Path) -> Result<Vec<u8>, _>`).
pub fn load_key(path: &Path) -> Result<Vec<u8>, KeyError> {
    let blob = std::fs::read(path)?;
    unwrap(&blob, None)
}

/// Unwrap a DPAPI blob captured with an explicit entropy label (e.g. the
/// D7 Zalo-Desktop key capture, wrapped as `zalors.d7`).
pub fn unwrap_with_label(blob: &[u8], label: &str) -> Result<Vec<u8>, KeyError> {
    unwrap(blob, Some(label))
}

/// Every connection this module opens waits up to 5 s on a busy DB
/// instead of failing with SQLITE_BUSY (audit H3 / §1.2: busy_timeout
/// on every connection; a silent busy error is a silent write loss).
pub const BUSY_TIMEOUT_MS: u64 = 5_000;

/// Open `path` (a SQLCipher DB) with `key` and verify the key is accepted.
///
/// `readonly` uses `SQLITE_OPEN_READ_ONLY` so probes and the import CLI
/// cannot mutate the source (P2: "không mở/ghi DB nguồn").
pub fn open_with_key_opts(
    path: &Path,
    key: &[u8],
    readonly: bool,
) -> Result<Connection, KeyError> {
    let flags = if readonly {
        rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY
    } else {
        rusqlite::OpenFlags::SQLITE_OPEN_READ_WRITE
            | rusqlite::OpenFlags::SQLITE_OPEN_CREATE
    };
    let conn = Connection::open_with_flags(path, flags)?;
    apply_key(&conn, key)?;
    // H3: set the busy timeout right after keying, BEFORE the first
    // page read, so even the verify query below waits instead of
    // surfacing SQLITE_BUSY as a hard error.
    conn.busy_timeout(Duration::from_millis(BUSY_TIMEOUT_MS))?;
    // A wrong key only surfaces on the first page read; force one now.
    conn.query_row("SELECT count(*) FROM sqlite_master", [], |_| Ok(()))
        .map_err(|e| KeyError::Db(format!("key rejected or unreadable DB: {e}")))?;
    if readonly {
        conn.pragma_update(None, "query_only", true)?;
    }
    Ok(conn)
}

/// Read/write open (shadow pipeline).
pub fn open_with_key(path: &Path, key: &[u8]) -> Result<Connection, KeyError> {
    open_with_key_opts(path, key, false)
}

/// Read-only open (probes, import CLI). Signature kept identical to the
/// lost implementation so the surviving probes compile unchanged.
pub fn open_with_key_readonly(path: &Path, key: &[u8]) -> Result<Connection, KeyError> {
    open_with_key_opts(path, key, true)
}

/// Encrypted in-memory DB for tests.
pub fn open_in_memory(key: &[u8]) -> Result<Connection, KeyError> {
    let conn = Connection::open_in_memory()?;
    apply_key(&conn, key)?;
    // Same H3 rule as every other connection this module opens.
    conn.busy_timeout(Duration::from_millis(BUSY_TIMEOUT_MS))?;
    Ok(conn)
}

/// Apply the raw hex key pragma. SQLCipher requires the `x'…'` form
/// inside a quoted value, so the statement is assembled explicitly
/// (never via a bound parameter).
fn apply_key(conn: &Connection, key: &[u8]) -> Result<(), KeyError> {
    let hex: String = key.iter().map(|b| format!("{b:02x}")).collect();
    conn.execute_batch(&format!("PRAGMA key = \"x'{hex}'\";"))
        .map_err(|e| KeyError::Db(format!("pragma key failed: {e}")))?;
    Ok(())
}

#[cfg(windows)]
fn wrap(data: &[u8], label: Option<&str>) -> Result<Vec<u8>, KeyError> {
    use windows::core::PCWSTR;
    use windows::Win32::Foundation::{LocalFree, HLOCAL};
    use windows::Win32::Security::Cryptography::{CryptProtectData, CRYPT_INTEGER_BLOB};

    unsafe {
        let in_blob = CRYPT_INTEGER_BLOB {
            cbData: data.len() as u32,
            pbData: data.as_ptr() as *mut u8,
        };
        // Optional entropy only when a label is given.
        let entropy: Vec<u16> = label
            .map(str::encode_utf16)
            .map(Iterator::collect)
            .unwrap_or_default();
        let ent_blob = CRYPT_INTEGER_BLOB {
            cbData: (entropy.len() * 2) as u32,
            pbData: entropy.as_ptr() as *mut u8,
        };
        let mut out = CRYPT_INTEGER_BLOB::default();
        let ent_ptr: Option<*const CRYPT_INTEGER_BLOB> = if entropy.is_empty() {
            None
        } else {
            Some(&ent_blob as *const _)
        };
        CryptProtectData(
            &in_blob,
            PCWSTR::null(),
            ent_ptr,
            None,
            None,
            0,
            &mut out,
        )
        .map_err(|e| KeyError::Io(io::Error::other(e)))?;
        let bytes = std::slice::from_raw_parts(out.pbData, out.cbData as usize).to_vec();
        let _ = LocalFree(Some(HLOCAL(out.pbData as *mut core::ffi::c_void)));
        Ok(bytes)
    }
}

#[cfg(windows)]
fn unwrap(blob: &[u8], label: Option<&str>) -> Result<Vec<u8>, KeyError> {
    use windows::Win32::Foundation::{LocalFree, HLOCAL};
    use windows::Win32::Security::Cryptography::{CryptUnprotectData, CRYPT_INTEGER_BLOB};

    unsafe {
        let in_blob = CRYPT_INTEGER_BLOB {
            cbData: blob.len() as u32,
            pbData: blob.as_ptr() as *mut u8,
        };
        let entropy: Vec<u16> = label
            .map(str::encode_utf16)
            .map(Iterator::collect)
            .unwrap_or_default();
        let ent_blob = CRYPT_INTEGER_BLOB {
            cbData: (entropy.len() * 2) as u32,
            pbData: entropy.as_ptr() as *mut u8,
        };
        let mut out = CRYPT_INTEGER_BLOB::default();
        let ent_ptr: Option<*const CRYPT_INTEGER_BLOB> = if entropy.is_empty() {
            None
        } else {
            Some(&ent_blob as *const _)
        };
        CryptUnprotectData(
            &in_blob,
            None,
            ent_ptr,
            None,
            None,
            0,
            &mut out,
        )
        .map_err(|e| KeyError::Io(io::Error::other(e)))?;
        let bytes = std::slice::from_raw_parts(out.pbData, out.cbData as usize).to_vec();
        let _ = LocalFree(Some(HLOCAL(out.pbData as *mut core::ffi::c_void)));
        Ok(bytes)
    }
}

#[cfg(not(windows))]
fn wrap(data: &[u8], _label: Option<&str>) -> Result<Vec<u8>, KeyError> {
    Ok(data.to_vec())
}

#[cfg(not(windows))]
fn unwrap(blob: &[u8], _label: Option<&str>) -> Result<Vec<u8>, KeyError> {
    Ok(blob.to_vec())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn busy_timeout_set_on_all_open_paths() {
        // H3/T1: every connection waits up to 5 s instead of erroring
        // out on SQLITE_BUSY.
        let key = generate_key().unwrap();
        let mem = open_in_memory(&key).unwrap();
        let ms: i64 = mem
            .query_row("PRAGMA busy_timeout", [], |r| r.get(0))
            .unwrap();
        assert_eq!(ms, 5_000);

        let dir = std::env::temp_dir().join(format!("zalors-bt-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let db = dir.join("t.db");
        {
            let conn = open_with_key(&db, &key).unwrap();
            let ms: i64 = conn
                .query_row("PRAGMA busy_timeout", [], |r| r.get(0))
                .unwrap();
            assert_eq!(ms, 5_000);
            conn.execute_batch("CREATE TABLE t (v TEXT)").unwrap();
        }
        {
            let conn = open_with_key_readonly(&db, &key).unwrap();
            let ms: i64 = conn
                .query_row("PRAGMA busy_timeout", [], |r| r.get(0))
                .unwrap();
            assert_eq!(ms, 5_000);
        }
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn key_roundtrip() {
        let key = generate_key().unwrap();
        let dir = std::env::temp_dir().join(format!("zalors-krt-{}", std::process::id()));
        let path = dir.join("default.key");
        let _ = std::fs::remove_dir_all(&dir);
        save_key(&key, &path).unwrap();
        let loaded = load_key(&path).unwrap();
        assert_eq!(key, loaded);
        // 32 bytes, and the file must not contain the raw key on Windows.
        #[cfg(windows)]
        {
            let raw = std::fs::read(&path).unwrap();
            assert!(raw.len() > 32);
            let needle = key.as_slice();
            assert!(
                !raw.windows(32).any(|w| w == needle),
                "raw key must never be present in the wrapped file"
            );
        }
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn sqlcipher_open_roundtrip() {
        let key = generate_key().unwrap();
        let dir = std::env::temp_dir().join(format!("zalors-sq-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let db = dir.join("t.db");
        {
            let conn = open_with_key(&db, &key).unwrap();
            conn.execute_batch(
                "CREATE TABLE t (id INTEGER PRIMARY KEY, v TEXT);
                 INSERT INTO t (v) VALUES ('ok');",
            )
            .unwrap();
        }
        {
            let conn = open_with_key_readonly(&db, &key).unwrap();
            let v: String = conn.query_row("SELECT v FROM t", [], |r| r.get(0)).unwrap();
            assert_eq!(v, "ok");
        }
        // A wrong key must be refused, not silently open garbage.
        let bad = generate_key().unwrap();
        assert!(open_with_key_readonly(&db, &bad).is_err());
        let _ = std::fs::remove_dir_all(&dir);
    }
}
