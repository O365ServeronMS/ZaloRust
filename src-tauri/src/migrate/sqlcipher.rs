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
//! Batch 18 (passphrase mode, "Option A"): a store may instead be keyed
//! by a USER-chosen passphrase via SQLCipher's own passphrase mode —
//! SQLCipher 4 defaults (PBKDF2-HMAC-SHA512, 256,000 iterations, per-DB
//! salt in the header), no other pragmas, so `default.db` + the password
//! open the store on ANY machine with any SQLCipher-4 tool. The mode is
//! marked by `shadow::passphrase` (`default.keymode.json`); the optional
//! machine-local convenience is a DPAPI-wrapped remember file
//! (`default.pass.dpapi`, entropy [`PASSPHRASE_ENTROPY`]). The passphrase
//! PRAGMAs always go through rusqlite's quoting, never `format!()`.
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
/// `1b701eef6664` only with no entropy, 2026-11-19). Kept parameterless
/// for compatibility; the D7 Zalo-Desktop import path also uses NO
/// entropy (audit M2-1) via [`unwrap_no_entropy`].

/// A wrapper around the two failures this module can produce: I/O errors
/// touching the key file, and key/DB mismatch errors from SQLCipher itself.
#[derive(Debug)]
pub enum KeyError {
    Io(io::Error),
    /// The DB refused the key (wrong key, corrupt file, or a plaintext DB).
    Db(String),
    /// Batch 18 (passphrase mode): the store IS in passphrase mode, the
    /// DB is there, but this exact passphrase did not open it — the
    /// first page read failed with SQLITE_NOTADB, SQLCipher's signature
    /// for a key that derives the wrong page-1 key. A TYPED error so the
    /// command layer can rate-limit and answer with a generic message,
    /// never a panic, and never the passphrase itself in the error text.
    WrongPassword,
}

impl std::fmt::Display for KeyError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            KeyError::Io(e) => write!(f, "key file I/O error: {e}"),
            KeyError::Db(s) => write!(f, "sqlcipher error: {s}"),
            // Never any detail that could echo the rejected passphrase.
            KeyError::WrongPassword => {
                write!(f, "wrong password (the database refused the key)")
            }
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

/// Unwrap a DPAPI blob captured with an explicit entropy label.
/// NOT the D7 path: the 2026-11-19 D7 Zalo-Desktop capture passed
/// `"zalors.d7"` as `szDataDescr` (the description parameter), NOT as
/// entropy, so its blob unwraps only with [`unwrap_no_entropy`]
/// (audit M2-1). Kept for genuinely labeled captures; nothing in the
/// production paths calls it today (the M2-1 regression test below
/// does — so it is compiled with the tests, not shipped dead in the
/// app binary).
#[cfg(test)]
pub fn unwrap_with_label(blob: &[u8], label: &str) -> Result<Vec<u8>, KeyError> {
    unwrap(blob, Some(label))
}

/// DPAPI unwrap with NO entropy — the D7 Zalo-Desktop capture path
/// (audit M2-1: the capture script's `"zalors.d7"` argument was
/// `szDataDescr`, not entropy; the blob unwraps only with entropy
/// `None`). Windows-only by design: non-Windows builds fail closed
/// with a clean error instead of handing back the wrapped bytes.
pub fn unwrap_no_entropy(blob: &[u8]) -> Result<Vec<u8>, KeyError> {
    #[cfg(windows)]
    {
        unwrap(blob, None)
    }
    #[cfg(not(windows))]
    {
        let _ = blob;
        Err(KeyError::Db(
            "DPAPI unwrap requires Windows (D7 captures only exist on Windows)".into(),
        ))
    }
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

// --- batch 18: SQLCipher passphrase mode ("Option A") -----------------------
//
// A passphrase-mode store uses SQLCipher's OWN defaults — PBKDF2-HMAC-SHA512,
// 256,000 iterations, per-DB salt in the file header — and NOTHING else, so
// third-party tools (DB Browser for SQLCipher) open it with the password and
// default settings on any machine. That is the whole point of the mode: no
// key file, no DPAPI, not machine-bound.
//
// Hard rules obeyed here:
// - the passphrase PRAGMAs go through rusqlite's quoting
//   (`pragma_update(None, "key"|"rekey", &pw)`), never `format!()` —
//   verified against rusqlite 0.34's pragma.rs, `pragma_update` renders the
//   value as a SQLite string literal with `''` escaping;
// - kdf_iter/cipher_* PRAGMAs are NEVER set (portability = SQLCipher 4
//   defaults);
// - a wrong password is the TYPED [`KeyError::WrongPassword`] (first page
//   read failing with SQLITE_NOTADB), never a panic, never a message that
//   echoes the password.

/// Is this rusqlite error SQLCipher's "this key did not open the DB"
/// signature? The primary signal is the error CODE (SQLITE_NOTADB = 26);
/// the message text ("file is not a database") is only a fallback for
/// builds that map the code oddly.
fn is_notadb(e: &rusqlite::Error) -> bool {
    use rusqlite::ffi::{ErrorCode, Error as FfiError};
    matches!(
        e,
        rusqlite::Error::SqliteFailure(
            FfiError { code: ErrorCode::NotADatabase, .. },
            ..
        )
    ) || e.to_string().contains("not a database")
}

/// Open `path` (a SQLCipher DB keyed as a PASSPHRASE) with `passphrase`.
///
/// No `kdf_iter`/`cipher_*` pragmas are set: SQLCipher 4 defaults ARE the
/// portable format. `readonly` adds `query_only` like the raw-key path.
pub fn open_with_passphrase_opts(
    path: &Path,
    passphrase: &str,
    readonly: bool,
) -> Result<Connection, KeyError> {
    let flags = if readonly {
        rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY
    } else {
        rusqlite::OpenFlags::SQLITE_OPEN_READ_WRITE
            | rusqlite::OpenFlags::SQLITE_OPEN_CREATE
    };
    let conn = Connection::open_with_flags(path, flags)?;
    // Injection-safe by construction: rusqlite quotes the value as a
    // SQLite string literal (`PRAGMA key = '<pw with '' escaped>';`).
    conn.pragma_update(None, "key", passphrase)
        .map_err(|e| KeyError::Db(format!("pragma key failed: {e}")))?;
    conn.busy_timeout(Duration::from_millis(BUSY_TIMEOUT_MS))?;
    // A wrong password only surfaces on the first page read; force one
    // now and classify it.
    match conn.query_row("SELECT count(*) FROM sqlite_master", [], |_| Ok(())) {
        Ok(()) => {}
        Err(e) if is_notadb(&e) => return Err(KeyError::WrongPassword),
        Err(e) => {
            return Err(KeyError::Db(format!("key rejected or unreadable DB: {e}")));
        }
    }
    if readonly {
        conn.pragma_update(None, "query_only", true)?;
    }
    Ok(conn)
}

/// Read/write open with a passphrase (the unlock/verification paths).
pub fn open_with_passphrase(path: &Path, passphrase: &str) -> Result<Connection, KeyError> {
    open_with_passphrase_opts(path, passphrase, false)
}

/// Read-only open with a passphrase (the shadow-unlock command's proof,
/// the archive/maintenance remember-file path).
pub fn open_with_passphrase_readonly(
    path: &Path,
    passphrase: &str,
) -> Result<Connection, KeyError> {
    open_with_passphrase_opts(path, passphrase, true)
}

/// Re-key an OPEN connection to `passphrase` (SQLCipher defaults apply).
/// Injection-safe via rusqlite's quoting, same as the key pragma.
///
/// THE REKEY-OK FACT (batch-18 review, verified in the vendored SQLCipher
/// `libsqlite3-sys-0.32.0/sqlcipher/sqlite3.c`, `sqlite3_rekey_v2`): rekey
/// sets the WRITE key first (`codec_set_pass_key(.., CIPHER_WRITE_CTX)`),
/// then rewrites every page in ONE write transaction; if that transaction
/// fails (e.g. another connection's lock makes it busy), it ROLLS BACK
/// and STILL RETURNS SQLITE_OK — the database keeps its OLD key while the
/// pragma "succeeded". No caller here may trust the rekey's return value
/// alone: every conversion re-opens and VERIFIES with the intended key
/// (`shadow::passphrase::verify_rekeyed`), and every failure after a
/// rekey rekeys BACK (the `rekey_landed` rule). Same for [`rekey_raw`].
pub fn rekey_passphrase(conn: &Connection, passphrase: &str) -> Result<(), KeyError> {
    conn.pragma_update(None, "rekey", passphrase)
        .map_err(|e| KeyError::Db(format!("pragma rekey failed: {e}")))?;
    Ok(())
}

/// Re-key an OPEN connection back to a 32-byte RAW key. Same statement
/// shape as [`apply_key`] (`PRAGMA rekey = "x'<64 hex chars>'";`) — the
/// raw-key form and its trailing-`;` shape are pinned by the R0 test;
/// this shares the builder so the two pragmas can never drift apart.
///
/// Subject to the same REKEY-OK FACT as [`rekey_passphrase`] (see the
/// comment there): a busy write transaction rolls back and the pragma
/// still answers SQLITE_OK — verify after every rekey, never trust it.
pub fn rekey_raw(conn: &Connection, key: &[u8]) -> Result<(), KeyError> {
    use zeroize::Zeroize;
    let mut stmt = raw_hex_pragma_stmt("rekey", key);
    let r = conn
        .execute_batch(stmt.as_str())
        .map_err(|e| KeyError::Db(format!("pragma rekey failed: {e}")));
    // Wipe the assembled statement now rather than waiting for its drop.
    stmt.zeroize();
    r?;
    Ok(())
}

/// Build `PRAGMA <name> = "x'<64 hex chars>'";` for a raw key. `name` is
/// only ever the `"key"`/`"rekey"` literals (not user input). The hex
/// form of the key and the assembled statement are key material: both
/// are zeroized by the caller after the pragma lands (L4/D4).
fn raw_hex_pragma_stmt(name: &str, key: &[u8]) -> zeroize::Zeroizing<String> {
    use std::fmt::Write as _;
    use zeroize::{Zeroize, Zeroizing};
    let mut hex = Zeroizing::new(String::with_capacity(key.len() * 2));
    for b in key {
        let _ = write!(&mut *hex, "{b:02x}");
    }
    let stmt = Zeroizing::new(format!("PRAGMA {name} = \"x'{}'\";", hex.as_str()));
    hex.zeroize();
    stmt
}

/// Encrypted in-memory DB for tests (every schema/writer/probe test
/// module opens its fake stores through this — nothing in the app
/// binary needs it, so it compiles with the tests only).
#[cfg(test)]
pub fn open_in_memory(key: &[u8]) -> Result<Connection, KeyError> {
    let conn = Connection::open_in_memory()?;
    apply_key(&conn, key)?;
    // Same H3 rule as every other connection this module opens.
    conn.busy_timeout(Duration::from_millis(BUSY_TIMEOUT_MS))?;
    Ok(conn)
}

/// Apply the raw hex key pragma. SQLCipher requires the `x'…'` form
/// inside a quoted value, so the statement is assembled explicitly
/// (never via a bound parameter). The exact shape is
/// `PRAGMA key = "x'<64 hex chars>'";` — semicolon OUTSIDE the
/// closing double quote, closing `'` BEFORE it. R0 (batch 4 review):
/// a version of this line swapped the trailing `'` and `;`, building
/// `PRAGMA key = "x'<hex>';"`, which SQLCipher silently treats as a
/// PASSPHRASE (`x'<hex>';` is not the raw-key form) and runs through
/// KDF instead — every pre-existing DB (the live shadow DB, the
/// golden oracle) then failed its first page read with
/// `hmac check failed for pgno=1`. A create+open roundtrip cannot
/// catch that (both sides use the same wrong form); the regression
/// test below pins the shape against a hand-built statement.
///
/// L4/D4 (batch 4): both the hex form of the key and the assembled
/// statement carry raw key material; both are zeroized after the
/// pragma lands instead of lingering in freed heap until reuse.
///
/// Batch 18: the statement itself comes from [`raw_hex_pragma_stmt`] so
/// `apply_key` ("key") and [`rekey_raw`] ("rekey") can never drift
/// apart; the built statement is BYTE-IDENTICAL to the pre-batch-18
/// form, which the R0 pin test below checks from the outside anyway.
fn apply_key(conn: &Connection, key: &[u8]) -> Result<(), KeyError> {
    use zeroize::Zeroize;
    let mut stmt = raw_hex_pragma_stmt("key", key);
    let r = conn
        .execute_batch(stmt.as_str())
        .map_err(|e| KeyError::Db(format!("pragma key failed: {e}")));
    // Wipe the assembled statement now rather than waiting for its drop.
    stmt.zeroize();
    r?;
    Ok(())
}

// --- batch 18: labeled DPAPI wraps ------------------------------------------
//
// The raw key file (`default.key`) is DPAPI-wrapped with NO entropy (the
// legacy-compat fact documented at the top of this module, verified
// 2026-11-19). The passphrase "remember on this machine" file
// (`default.pass.dpapi`) uses a FIXED, distinct entropy label so the two
// blobs can never be confused for one another, and the wrap of the
// passphrase can never be unwrapped by code that expects a raw key.

/// The fixed DPAPI entropy label of the passphrase remember-file —
/// distinct from the key file's (none). Not a secret (entropy labels are
/// a compatibility requirement, not a key).
pub const PASSPHRASE_ENTROPY: &str = "zalors.shadow.pass";

/// DPAPI (CurrentUser) wrap of `data` with the FIXED entropy `label`.
/// Batch 18: the remember-file path. Labeled so a `default.pass.dpapi`
/// blob can never unwrap through the no-entropy raw-key path and vice
/// versa. Non-Windows: identity (the documented dev placeholder for the
/// same reason `save_key` has one).
pub(crate) fn wrap_labeled(data: &[u8], label: &str) -> Result<Vec<u8>, KeyError> {
    wrap(data, Some(label))
}

/// The unwrap counterpart of [`wrap_labeled`]. Fail-closed on non-Windows.
pub(crate) fn unwrap_labeled(blob: &[u8], label: &str) -> Result<Vec<u8>, KeyError> {
    unwrap(blob, Some(label))
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
    #[cfg(windows)]
    fn d7_blobs_unwrap_with_no_entropy_not_a_label() {
        // M2-1 (batch 6): the D7 capture script passed "zalors.d7" as
        // szDataDescr, NOT as entropy — its blob opens with NO entropy
        // and must be REFUSED by the labeled unwrap the old skeleton
        // used (`unwrap_with_label(..., "zalors.d7")`).
        let payload = br#"{"fake":"d7-plaintext"}"#.to_vec();
        let blob = wrap(&payload, None).unwrap();
        assert_eq!(unwrap_no_entropy(&blob).unwrap(), payload);
        assert!(
            unwrap_with_label(&blob, "zalors.d7").is_err(),
            "a no-entropy blob must not open through the labeled unwrap"
        );
    }

    #[test]
    fn key_material_zeroizes_after_use() {
        // L4/D4: the zeroize helper really clears every buffer shape
        // the key paths use (Vec bytes, the 16-byte runtime keys, the
        // hex String form).
        use zeroize::Zeroize;
        let mut v = vec![0xA5u8; 32];
        v.zeroize();
        assert!(v.iter().all(|&b| b == 0), "Vec<u8> key bytes must wipe");
        let mut a = [0x5Au8; 16];
        a.zeroize();
        assert!(a.iter().all(|&b| b == 0), "the [u8;16] runtime keys must wipe");
        let mut s = String::from("0123456789abcdef0123456789abcdef");
        s.zeroize();
        assert!(s.bytes().all(|b| b == 0), "the hex String form must wipe");
    }

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

    // --- batch 18: passphrase mode -------------------------------------------

    /// An OBVIOUSLY FAKE passphrase (H-rule: tests never carry anything
    /// that looks like a real secret). >= 12 chars, no quotes, no NUL.
    const FAKE_PASS: &str = "fake-pass-phrase-0123456789";
    const FAKE_PASS_2: &str = "fake-other-pass-abcdefghij";

    fn scratch(tag: &str) -> std::path::PathBuf {
        static SEQ: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
        let dir = std::env::temp_dir().join(format!(
            "zalors-pass-{}-{tag}-{}",
            std::process::id(),
            SEQ.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
        ));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[test]
    fn passphrase_open_roundtrip_and_wrong_password_is_typed() {
        let dir = scratch("open");
        let db = dir.join("t.db");
        {
            let conn = open_with_passphrase(&db, FAKE_PASS).unwrap();
            conn.execute_batch(
                "CREATE TABLE t (id INTEGER PRIMARY KEY, v TEXT);
                 INSERT INTO t (v) VALUES ('ok');",
            )
            .unwrap();
        }
        {
            let conn = open_with_passphrase_readonly(&db, FAKE_PASS).unwrap();
            let v: String = conn.query_row("SELECT v FROM t", [], |r| r.get(0)).unwrap();
            assert_eq!(v, "ok");
            // readonly really is query_only.
            assert!(conn.execute_batch("CREATE TABLE x (v TEXT)").is_err());
        }
        // A wrong passphrase is the TYPED error, never a panic, and the
        // error text never echoes the passphrase (H-rule).
        let err = open_with_passphrase_readonly(&db, FAKE_PASS_2).unwrap_err();
        assert!(matches!(err, KeyError::WrongPassword), "got: {err:?}");
        let text = err.to_string();
        assert!(!text.contains(FAKE_PASS_2));
        // A raw-key open must NOT open a passphrase DB (the modes are
        // distinct key material by construction).
        let raw = generate_key().unwrap();
        assert!(open_with_key_readonly(&db, &raw).is_err());
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn passphrase_db_opens_with_a_plain_third_party_pragma() {
        // The portability contract (brief R5): a PLAIN connection that
        // only runs `PRAGMA key = '<pw>';` — the exact statement DB
        // Browser for SQLCipher / the sqlite3 shell issue, with NO other
        // pragmas — must read the DB. That proves SQLCipher 4 defaults,
        // not a private parameter set.
        let dir = scratch("thirdparty");
        let db = dir.join("t.db");
        {
            let conn = open_with_passphrase(&db, FAKE_PASS).unwrap();
            conn.execute_batch(
                "CREATE TABLE t (id INTEGER PRIMARY KEY, v TEXT);
                 INSERT INTO t (v) VALUES ('default-settings');",
            )
            .unwrap();
        }
        let conn = Connection::open_with_flags(&db, rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY)
            .unwrap();
        conn.execute_batch(&format!("PRAGMA key = '{FAKE_PASS}';")).unwrap();
        let v: String = conn.query_row("SELECT v FROM t", [], |r| r.get(0)).unwrap();
        assert_eq!(v, "default-settings");
        // And NO other pragmas were needed: cipher_version exists with
        // the default profile (the KDF settings were never overridden).
        let ver: String = conn
            .query_row("PRAGMA cipher_version;", [], |r| r.get(0))
            .unwrap();
        assert!(!ver.is_empty());
        // Windows cannot delete a file an open connection still holds.
        drop(conn);
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn rekey_between_passphrases_and_back_to_raw() {
        let dir = scratch("rekey");
        let db = dir.join("t.db");
        // Start raw-keyed, with rows.
        let raw = generate_key().unwrap();
        {
            let conn = open_with_key(&db, &raw).unwrap();
            conn.execute_batch(
                "CREATE TABLE t (id INTEGER PRIMARY KEY, v TEXT);
                 INSERT INTO t (v) VALUES ('v1');",
            )
            .unwrap();
            // Convert to a passphrase on the OPEN connection (rekey).
            rekey_passphrase(&conn, FAKE_PASS).unwrap();
        }
        // The passphrase alone reopens it (raw key no longer works).
        assert!(open_with_key_readonly(&db, &raw).is_err());
        {
            let conn = open_with_passphrase(&db, FAKE_PASS).unwrap();
            let v: String = conn.query_row("SELECT v FROM t", [], |r| r.get(0)).unwrap();
            assert_eq!(v, "v1");
            // Change to a second passphrase.
            rekey_passphrase(&conn, FAKE_PASS_2).unwrap();
        }
        assert!(open_with_passphrase_readonly(&db, FAKE_PASS).is_err());
        {
            let conn = open_with_passphrase(&db, FAKE_PASS_2).unwrap();
            let v: String = conn.query_row("SELECT v FROM t", [], |r| r.get(0)).unwrap();
            assert_eq!(v, "v1");
            // Remove: rekey back to a FRESH raw key.
            let raw2 = generate_key().unwrap();
            rekey_raw(&conn, &raw2).unwrap();
            assert!(open_with_passphrase_readonly(&db, FAKE_PASS_2).is_err());
            let check = open_with_key_readonly(&db, &raw2).unwrap();
            let v: String = check.query_row("SELECT v FROM t", [], |r| r.get(0)).unwrap();
            assert_eq!(v, "v1");
        }
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    #[cfg(windows)]
    fn labeled_wraps_never_cross_the_no_entropy_key_file_path() {
        // The remember-file blob must unwrap ONLY through the labeled
        // path — the no-entropy (key-file) path must refuse it, and a
        // key-file blob must refuse the labeled unwrap. Distinct
        // entropies, distinct blobs, no confusion in either direction.
        let pw = FAKE_PASS.as_bytes();
        let blob = wrap_labeled(pw, PASSPHRASE_ENTROPY).unwrap();
        assert_eq!(unwrap_labeled(&blob, PASSPHRASE_ENTROPY).unwrap(), pw);
        assert!(unwrap_labeled(&blob, "some.other.label").is_err());
        assert!(
            unwrap_no_entropy(&blob).is_err(),
            "the remember blob must not open through the key-file unwrap"
        );
        let key_blob = wrap(pw, None).unwrap();
        assert!(
            unwrap_labeled(&key_blob, PASSPHRASE_ENTROPY).is_err(),
            "a key-file blob must not open through the labeled unwrap"
        );
    }

    #[test]
    fn pragma_key_raw_key_shape_cross_open() {
        // R0 (batch 4 review): pin the statement shape against an
        // INDEPENDENT encoder. The DB below is created by executing a
        // literal `PRAGMA key = "x'<hex>'";` built BY HAND here (not via
        // `apply_key`), then opened with `open_with_key` — which uses
        // `apply_key`. If `apply_key` ever again builds a swapped
        // `"x'<hex>';"` (or any other shape), the open fails.
        //
        // A create+open roundtrip through `apply_key` on both sides
        // cannot catch this: both use the same wrong form and the KDF
        // key the wrong form creates is simply reproducible. This test
        // can, because the CREATE side is spelled out independently.
        let fake_key: Vec<u8> = (0..32u8).map(|i| i.wrapping_mul(7).wrapping_add(1)).collect();
        // Independent hex encoding: a nibble lookup table, not the
        // `write!` loop `apply_key` uses.
        const HEX: &[u8; 16] = b"0123456789abcdef";
        let mut hex = String::with_capacity(fake_key.len() * 2);
        for b in &fake_key {
            hex.push(HEX[(b >> 4) as usize] as char);
            hex.push(HEX[(b & 0x0f) as usize] as char);
        }
        let literal = format!("PRAGMA key = \"x'{hex}'\";");
        let dir = std::env::temp_dir().join(format!("zalors-r0-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let db = dir.join("t.db");
        {
            let conn = Connection::open_with_flags(
                &db,
                rusqlite::OpenFlags::SQLITE_OPEN_READ_WRITE
                    | rusqlite::OpenFlags::SQLITE_OPEN_CREATE,
            )
            .unwrap();
            conn.execute_batch(&literal).unwrap();
            conn.execute_batch(
                "CREATE TABLE t (id INTEGER PRIMARY KEY, v TEXT);
                 INSERT INTO t (v) VALUES ('raw-key-shape');",
            )
            .unwrap();
        }
        // Open through `apply_key`: must accept the hand-keyed DB.
        {
            let conn = open_with_key(&db, &fake_key).unwrap();
            let v: String = conn.query_row("SELECT v FROM t", [], |r| r.get(0)).unwrap();
            assert_eq!(v, "raw-key-shape");
        }
        // Proving raw-key mode with the two passphrase forms that
        // really run KDF. NOTE (verified at runtime on this SQLCipher
        // build): the SQL quote STYLE does not select the mode —
        // SQLCipher inspects the pragma VALUE, and any value shaped
        // `x'<hex>'` is the raw key, even when spelled with single
        // quotes as `'x''<hex>'''` (that spelling OPENS this DB; the
        // failed first version of this assert proved it). The forms
        // below do not match the raw-key shape, so SQLCipher treats
        // them as passphrases and derives a different key:
        // (1) the same hex text WITHOUT the x'…' wrapper;
        // (2) the R0-corrupted statement itself — `"x'<hex>';"`, the
        //     trailing `'` and `;` swapped — exactly the form that
        //     made every pre-existing DB fail under batch 4.
        for wrong in [
            format!("PRAGMA key = '{hex}';"),
            format!("PRAGMA key = \"x'{hex}';\";"),
        ] {
            let conn =
                Connection::open_with_flags(&db, rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY)
                    .unwrap();
            let readable = conn
                .execute_batch(&wrong)
                .and_then(|_| {
                    conn.query_row("SELECT count(*) FROM sqlite_master", [], |_| Ok(()))
                })
                .is_ok();
            assert!(
                !readable,
                "a passphrase-form key must not open a raw-key DB (form {})",
                if wrong.starts_with("PRAGMA key = '") { "hex text" } else { "swapped ';'" }
            );
        }
        let _ = std::fs::remove_dir_all(&dir);
    }
}
