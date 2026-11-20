//! Store passphrase mode ("Option A", batch 18): the shadow DB protectable
//! by a password the USER chooses, so `default.db` + the password open it
//! on ANY machine (no key file, no DPAPI, not machine-bound).
//!
//! Two modes per store dir, marked by a small PLAINTEXT JSON marker
//! `default.keymode.json` (`{"mode":"passphrase","kdf":"sqlcipher4-default",
//! "since_ms":…}` — no secrets). Absent marker + `default.key` present =
//! raw mode, byte-for-byte the pre-batch-18 behaviour (backward compatible).
//!
//! - Passphrase mode = SQLCipher's OWN passphrase keying with SQLCipher 4
//!   defaults (PBKDF2-HMAC-SHA512, 256,000 iterations, per-DB salt in the
//!   header). No `kdf_iter`/`cipher_*` pragmas are ever set: portability
//!   with third-party tools (DB Browser for SQLCipher) is the point.
//! - "Remember on this machine" (optional convenience): the passphrase
//!   DPAPI-wrapped (CurrentUser, entropy
//!   [`crate::migrate::sqlcipher::PASSPHRASE_ENTROPY`], distinct from the
//!   raw-key file's no-entropy wrap) into `default.pass.dpapi`. Deleting
//!   that file just means the app asks again.
//! - Hard rules obeyed: passwords are held in `Zeroizing<String>` only;
//!   never logged, never in error strings (every error here is a KIND
//!   only), never in settings.json, never on the command line or in env
//!   vars; the passphrase PRAGMAs go through rusqlite's quoting, never
//!   `format!()`.
//!
//! Conversions run on the FLUSHER thread (the single writer, A5) — the
//! jobs in `runtime.rs` call [`set_passphrase`] / [`change_passphrase`] /
//! [`remove_passphrase`]. Every step is ordered so a failure BEFORE the
//! marker is written leaves the store in its OLD mode and usable:
//! - raw → passphrase: pre-backup (with the OLD raw key — machine-bound,
//!   under `pre-passphrase-backups/`), journal to DELETE (rekey is not
//!   WAL-safe), rekey, reopen with ONLY the passphrase, verify integrity
//!   + counts, write the marker, rename `default.key` →
//!   `default.key.pre-passphrase`, then the remember file if asked.
//! - change: rekey old → new, verify, adjust the remember file.
//! - remove: rekey to a FRESH random raw key (saved DPAPI into
//!   `default.key` before the rekey — a stranded raw key is
//!   unrecoverable, a stranded passphrase is not), verify, then remove
//!   the marker and the remember file.
//!
//! Recovery rules (batch-18 review fixes):
//! - **Journal first (F1):** `PRAGMA journal_mode = DELETE` does not
//!   fail LOUDLY when another connection keeps the store in WAL: the
//!   documented shape answers the switch with `wal` (no error), the
//!   vendored build surfaces SQLITE_BUSY on the statement. Either way
//!   [`JournalGuard::enter`] refuses with the kind `store-busy` BEFORE
//!   any rekey, touching no key, marker or remember file.
//! - **`rekey_landed` (F3):** the flag is set right after the rekey
//!   returns Ok; ANY `Err` after that point rekeys back (set → the
//!   original raw key, marker failure included; change → the old
//!   passphrase; remove → the current passphrase, after which the
//!   fresh `default.key` is deleted so no raw key file sits beside a
//!   marker that still says passphrase). The rekey-back is verified
//!   before that delete, because the vendored `sqlite3_rekey_v2` can
//!   roll back and STILL return SQLITE_OK (see the comment at
//!   [`crate::migrate::sqlcipher::rekey_passphrase`]).
//! - **Key-file generations (F4):** `default.key.pre-passphrase` is
//!   kept, never deleted — and when one from an EARLIER conversion
//!   already exists it is archived under a stamp of its era (old
//!   marker `since_ms`, else the file's mtime ms), also never
//!   deleted: each generation is the only key that opens that era's
//!   `pre-passphrase-backups/` backup.
//! - **Store gate (F2):** the journal→finalize span holds the
//!   process-wide [`STORE_GATE`]'s WRITE guard; the media cycle's DB
//!   use holds its READ guard, so no in-process reader connection
//!   exists during a conversion, and the next open picks up the shared
//!   key cell's CURRENT value (the flusher publishes it at boot and
//!   after every successful set/change/remove).
//!
//! Capture while the store is passphrase-locked (no remembered
//! passphrase) is dropped by design: the pipeline does not start until
//! the user unlocks, and the running webviews' events have nowhere to
//! land. Documented trade-off (brief R2, acceptable).

use std::collections::BTreeMap;
use std::path::Path;
use std::time::Instant;

use rusqlite::Connection;
use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

use crate::migrate::sqlcipher;

use super::backup::{self, BackupKey};

// --- the mode marker --------------------------------------------------------

/// `kdf` recorded in the marker: SQLCipher 4 defaults, nothing else.
pub const KDF_LABEL: &str = "sqlcipher4-default";

/// The marker JSON (`default.keymode.json`). NO secrets — mode + kdf +
/// when. `mode` is the only field the runtime dispatches on.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct KeyModeMarker {
    pub mode: String,
    pub kdf: String,
    pub since_ms: i64,
}

/// The store's key mode as the marker says it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StoreKeyMode {
    /// No marker (or the raw-key path): today's mode, byte-for-byte.
    Raw,
    /// `default.keymode.json` says `passphrase`.
    Passphrase,
    /// A marker exists but names a mode this build does not know —
    /// fail closed in [`open_store`], never silently open as raw.
    Unknown,
}

/// Read the store's mode from the marker file (`Raw` when absent).
/// A marker that fails to parse is [`StoreKeyMode::Unknown`], never
/// silently raw: an unreadable marker on a passphrase store must not
/// trick this build into opening (or worse, writing) with a raw key.
pub fn read_mode(dir: &Path) -> StoreKeyMode {
    let path = super::keymode_file(dir);
    if !path.is_file() {
        return StoreKeyMode::Raw;
    }
    match std::fs::read_to_string(&path) {
        Ok(text) => match serde_json::from_str::<KeyModeMarker>(&text) {
            Ok(m) if m.mode == "passphrase" => StoreKeyMode::Passphrase,
            Ok(_) => StoreKeyMode::Unknown,
            Err(_) => StoreKeyMode::Unknown,
        },
        Err(_) => StoreKeyMode::Unknown,
    }
}

/// Write the passphrase-mode marker (no secrets). One small file write;
/// the conversion sequence only reaches this after verification, so a
/// failure here aborts with the store already rekeyed back to its old key.
pub fn write_marker(dir: &Path, now_ms: i64) -> Result<(), std::io::Error> {
    let marker = KeyModeMarker {
        mode: "passphrase".into(),
        kdf: KDF_LABEL.into(),
        since_ms: now_ms,
    };
    let json = serde_json::to_vec(&marker).map_err(std::io::Error::other)?;
    std::fs::write(super::keymode_file(dir), json)
}

/// Remove the marker (the remove-password step, after verification).
/// Idempotent.
pub fn remove_marker(dir: &Path) -> Result<(), std::io::Error> {
    let path = super::keymode_file(dir);
    match std::fs::remove_file(&path) {
        Ok(()) => Ok(()),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(e) => Err(e),
    }
}

// --- the remember file ------------------------------------------------------

/// Save the "remember on this machine" wrap: DPAPI (CurrentUser) with the
/// FIXED entropy label (see [`sqlcipher::PASSPHRASE_ENTROPY`]) — distinct
/// from the raw-key file's no-entropy wrap.
pub fn save_remembered(dir: &Path, passphrase: &str) -> Result<(), std::io::Error> {
    let blob = sqlcipher::wrap_labeled(passphrase.as_bytes(), sqlcipher::PASSPHRASE_ENTROPY)
        .map_err(std::io::Error::other)?;
    std::fs::create_dir_all(dir)?;
    std::fs::write(super::pass_dpapi_file(dir), blob)
}

/// Load the remembered passphrase (RAM only; zeroized on drop). Errors on
/// a missing or unwrappable file — the caller decides what that means
/// (the runtime asks the user again; a stale wrap after a password change
/// is deleted by the change step itself).
pub fn load_remembered(dir: &Path) -> Result<Zeroizing<String>, String> {
    let blob = std::fs::read(super::pass_dpapi_file(dir))
        .map_err(|_| "remember file unreadable".to_string())?;
    let bytes = sqlcipher::unwrap_labeled(&blob, sqlcipher::PASSPHRASE_ENTROPY)
        .map_err(|_| "remember file refused".to_string())?;
    // DPAPI hands back the exact bytes that were wrapped; a blob that
    // somehow unwraps to invalid UTF-8 is not a passphrase we accept.
    let text = String::from_utf8(bytes).map_err(|_| "remember file not utf-8".to_string())?;
    Ok(Zeroizing::new(text))
}

/// Delete the remember file (idempotent). The "off" side of the toggle
/// and the change-password step that no longer remembers.
pub fn forget_remembered(dir: &Path) -> Result<(), std::io::Error> {
    let path = super::pass_dpapi_file(dir);
    match std::fs::remove_file(&path) {
        Ok(()) => Ok(()),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(e) => Err(e),
    }
}

/// Is a remember file present? (The settings UI shows the toggle from
/// this; the file's contents are never shown.)
pub fn remembered_present(dir: &Path) -> bool {
    super::pass_dpapi_file(dir).is_file()
}

// --- passphrase validation ---------------------------------------------------

/// Minimum length (brief R3: "min 12 chars"). Counted in characters — a
/// multi-byte passphrase is not penalized.
pub const MIN_PASS_LEN: usize = 12;
/// Sanity cap so a runaway paste cannot assemble a megabyte PRAGMA.
pub const MAX_PASS_LEN: usize = 256;

/// Why a candidate passphrase was refused (the command layer translates).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PassInvalid {
    TooShort,
    TooLong,
    /// NUL bytes cannot survive rusqlite's string-literal quoting.
    BadChars,
}

/// Validate a candidate passphrase (pure). The confirm-equality check
/// lives in the command layer with the other user-input checks.
pub fn validate_passphrase(pw: &str) -> Result<(), PassInvalid> {
    let chars = pw.chars().count();
    if chars < MIN_PASS_LEN {
        return Err(PassInvalid::TooShort);
    }
    if chars > MAX_PASS_LEN {
        return Err(PassInvalid::TooLong);
    }
    if pw.contains('\0') {
        return Err(PassInvalid::BadChars);
    }
    Ok(())
}

// --- wrong-password rate limiting (brief R2) ---------------------------------

/// Free tries before the backoff starts biting.
const FREE_TRIES: u32 = 5;
/// One flat backoff window once the free tries are spent.
const BLOCK_SECS: u64 = 30;

/// Brute-force limiter for every password-checking shadow command
/// (`shadow_unlock`, change, remove). Same shape as `lock::UnlockThrottle`
/// but per the brief's rule: 5 tries free, then 30 s. In memory only —
/// restarting the app resets it, and every attempt still costs a full
/// PBKDF2 round on SQLCipher's side.
#[derive(Debug, Default)]
pub struct ShadowThrottle {
    failures: u32,
    blocked_until: Option<Instant>,
}

impl ShadowThrottle {
    /// `Err(seconds_left)` while attempts are blocked.
    pub fn check(&self, now: Instant) -> Result<(), u64> {
        match self.blocked_until {
            Some(t) if t > now => Err((t - now).as_secs() + 1),
            _ => Ok(()),
        }
    }

    pub fn record_failure(&mut self, now: Instant) {
        self.failures = self.failures.saturating_add(1);
        // Brief R2: 5 tries, THEN the 30 s backoff — the 5th failure
        // arms the window, so the 6th attempt is refused.
        if self.failures >= FREE_TRIES {
            self.blocked_until = Some(now + std::time::Duration::from_secs(BLOCK_SECS));
        }
    }

    pub fn record_success(&mut self) {
        *self = Self::default();
    }
}

/// The process-wide limiter, shared by the commands (one store, one
/// secret — the settings window and the unlock window rate-limit
/// together, which is the point).
pub static SHADOW_THROTTLE: std::sync::Mutex<Option<ShadowThrottle>> =
    std::sync::Mutex::new(None);

/// Run one password probe under the throttle: refuse while blocked,
/// record the outcome (success resets the window, a wrong password
/// counts toward the backoff). Pure bookkeeping around `f`.
pub fn throttled_probe(now: Instant, f: impl FnOnce() -> bool) -> Result<(), u64> {
    let Ok(mut guard) = SHADOW_THROTTLE.lock() else {
        return Ok(()); // poisoned: proceed, the limiter is bookkeeping only
    };
    let entry = guard.get_or_insert_with(ShadowThrottle::default);
    entry.check(now)?;
    if f() {
        entry.record_success();
        Ok(())
    } else {
        entry.record_failure(now);
        Err(0)
    }
}

// --- shared store open (R4: everything else that opens the store) -------------

/// Which key opened the store — the callers keep this so a backup taken
/// right after uses the SAME mode (`import --apply`'s pre-import backup)
/// and the runtime can hold the passphrase in RAM for the flusher.
#[derive(Debug)]
pub enum StoreKey {
    Raw(Zeroizing<Vec<u8>>),
    Passphrase(Zeroizing<String>),
}

impl StoreKey {
    /// The manifest `mode` label (no secrets).
    pub fn label(&self) -> &'static str {
        match self {
            StoreKey::Raw(_) => "raw",
            StoreKey::Passphrase(_) => "passphrase",
        }
    }

    /// The [`backup::BackupKey`] for an export/verify of THIS store.
    pub fn backup_key(&self) -> BackupKey<'_> {
        match self {
            StoreKey::Raw(k) => BackupKey::Raw(k.as_slice()),
            StoreKey::Passphrase(p) => BackupKey::Passphrase(p.as_str()),
        }
    }
}

/// Why [`open_store`] failed. `Locked` = passphrase mode and no usable
/// remember file: the caller shows the clear refusal (brief R4), never
/// a password prompt of its own and never a password input on argv/env.
#[derive(Debug)]
pub enum StoreOpenError {
    Locked,
    /// Kind-only text (H-rule: no paths, no sqlite error text, no secrets).
    Other(String),
}

/// Open the ENCRYPTED store at `dir` with whatever mode the marker says:
/// raw (`default.key`, DPAPI) or passphrase (`default.pass.dpapi` — the
/// remember file is the ONLY passphrase source here, by design: probes,
/// the archive window, maint tools and the import CLI never accept a
/// password). Passphrase mode without a usable remember file is
/// [`StoreOpenError::Locked`]. The `encrypt=false` plaintext path stays
/// with the callers (they already own that branch).
pub fn open_store(dir: &Path, readonly: bool) -> Result<(Connection, StoreKey), StoreOpenError> {
    let db_path = super::db_file(dir);
    match read_mode(dir) {
        StoreKeyMode::Raw => {
            let key_path = super::key_file(dir);
            if !key_path.is_file() {
                return Err(StoreOpenError::Other("no-key-file".into()));
            }
            let key =
                Zeroizing::new(sqlcipher::load_key(&key_path).map_err(|e| {
                    StoreOpenError::Other(key_kind(&e))
                })?);
            let conn = if readonly {
                sqlcipher::open_with_key_readonly(&db_path, &key)
            } else {
                sqlcipher::open_with_key(&db_path, &key)
            }
            .map_err(|e| StoreOpenError::Other(key_kind(&e)))?;
            Ok((conn, StoreKey::Raw(key)))
        }
        StoreKeyMode::Passphrase => {
            // No remember file, or one that no longer opens the DB (the
            // password changed): the same user situation, by design.
            let pw = load_remembered(dir).map_err(|_| StoreOpenError::Locked)?;
            let conn = match sqlcipher::open_with_passphrase_opts(&db_path, &pw, readonly) {
                Ok(c) => c,
                Err(sqlcipher::KeyError::WrongPassword) => {
                    return Err(StoreOpenError::Locked)
                }
                Err(e) => return Err(StoreOpenError::Other(key_kind(&e))),
            };
            Ok((conn, StoreKey::Passphrase(pw)))
        }
        StoreKeyMode::Unknown => Err(StoreOpenError::Other("marker-unknown".into())),
    }
}

/// Log/error-safe kind of a [`sqlcipher::KeyError`] (never its text — the
/// Db variant can carry sqlite messages, and H-rule says kinds only).
fn key_kind(e: &sqlcipher::KeyError) -> String {
    match e {
        sqlcipher::KeyError::Io(_) => "io".into(),
        sqlcipher::KeyError::Db(_) => "db".into(),
        sqlcipher::KeyError::WrongPassword => "wrong-password".into(),
    }
}

// --- F2: the in-process shared key cell + the store gate ----------------------

/// The process-wide shared key cell (F2): the CURRENT passphrase as the
/// flusher holds it in RAM (`None` in raw mode) plus a `u64` epoch that
/// increments on every successful set/change/remove and on unlock (the
/// flusher publishes its boot key right after unlocking boots it).
///
/// Writers: ONLY the flusher thread (the single writer, A5) — via
/// [`publish_key`] at boot and after each conversion job in
/// `runtime.rs`. Readers: everything in THIS process that opens the
/// store on its own connection — the media thread's per-cycle open and
/// the archive window's cached session. Separate processes (probes,
/// maint tools, the import CLI) never see it: they keep the
/// remember-file-only [`open_store`].
///
/// The epoch exists for connection caching: the archive window stamps
/// its cached connection with the epoch it was opened under and drops
/// it the moment the epoch moves, so a stale key never outlives the
/// conversion that changed it.
struct SharedKeyCell {
    pass: Option<Zeroizing<String>>,
    epoch: u64,
}

static KEY_CELL: std::sync::Mutex<SharedKeyCell> = std::sync::Mutex::new(SharedKeyCell {
    pass: None,
    epoch: 0,
});

/// Publish the flusher's CURRENT RAM passphrase (flusher thread only).
/// Bumps the epoch so every cached connection opened under the old
/// value is dropped and reopened. Poisoned: recover the cell — it is a
/// cache, never a lock the store's correctness depends on.
pub fn publish_key(pass: Option<Zeroizing<String>>) -> u64 {
    let mut cell = KEY_CELL
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    cell.pass = pass;
    cell.epoch += 1;
    cell.epoch
}

/// The cell's CURRENT passphrase (a clone — RAM only, zeroized on
/// drop), or `None` (raw mode, or a locked passphrase store).
pub fn cell_passphrase() -> Option<Zeroizing<String>> {
    KEY_CELL
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .pass
        .clone()
}

/// The cell's CURRENT epoch (the cache-staleness stamp).
pub fn cell_epoch() -> u64 {
    KEY_CELL
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .epoch
}

/// The process-wide "store gate" (F2): the media cycle holds the READ
/// guard for exactly its connection's lifetime; a key-mode conversion
/// holds the WRITE guard from the journal step through the finalize.
/// With the gate honoured on both sides, NO in-process reader
/// connection exists while the store is being rekeyed, and the next
/// reader open happens with the key cell's new value.
pub static STORE_GATE: std::sync::RwLock<()> = std::sync::RwLock::new(());

/// The store gate's read guard (media cycle: hold it for the cycle's
/// DB use and drop it when the connection goes away).
pub fn store_gate_read() -> std::sync::RwLockReadGuard<'static, ()> {
    STORE_GATE
        .read()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
}

/// The store gate's write guard (conversion engines: from the journal
/// step through the rekey-back/finalize).
pub fn store_gate_write() -> std::sync::RwLockWriteGuard<'static, ()> {
    STORE_GATE
        .write()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
}

/// (F2) [`open_store`] for callers that live in THIS process with the
/// running pipeline behind them (the archive window; the media
/// thread's per-cycle open): in passphrase mode the shared key cell's
/// value is preferred — unlocking WITHOUT "remember" still opens
/// everything in-process — and a stale cell value (a conversion raced
/// us) simply falls through to the remember-file rules of
/// [`open_store`]. Probes, maint tools and the import CLI keep
/// calling [`open_store`]: remember file only, by design.
pub fn open_store_with_cell(
    dir: &Path,
    readonly: bool,
) -> Result<(Connection, StoreKey), StoreOpenError> {
    if read_mode(dir) == StoreKeyMode::Passphrase {
        if let Some(pw) = cell_passphrase() {
            match sqlcipher::open_with_passphrase_opts(&super::db_file(dir), &pw, readonly) {
                Ok(conn) => return Ok((conn, StoreKey::Passphrase(pw))),
                // A stale cell value behaves like no cell value: the
                // remember file (or the Locked refusal) decides.
                Err(sqlcipher::KeyError::WrongPassword) => {}
                Err(e) => return Err(StoreOpenError::Other(key_kind(&e))),
            }
        }
    }
    open_store(dir, readonly)
}

/// Serializes the tests that mutate the process-wide key cell, so
/// parallel test threads cannot publish over each other's values
/// (production never runs concurrently like this — one flusher).
#[cfg(test)]
pub(crate) static CELL_TEST_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

// --- the conversion engine (runs on the flusher thread) ---------------------

/// Where a test injects a failure. Production passes `None`; the impl
/// functions take `Option<FailAt>` so the recovery paths are exercisable
/// without globals (parallel-test safe).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FailAt {
    /// Right after the rekey lands, before the reopen verification.
    AfterRekey,
    /// After the verification, before the marker/rename finalize steps.
    AfterVerify,
    /// The marker step of set/remove (a `write_marker` / `remove_marker`
    /// failure). There is no marker step in change; unused there.
    Marker,
}

/// Steps around a rekey: SQLCipher's `PRAGMA rekey` is not WAL-safe (the
/// WAL frames written during the rekey would mix old- and new-key pages),
/// so the store steps down to DELETE journal for the rekey window and
/// back to WAL afterwards. Restoring WAL is best-effort: a DELETE-journal
/// store is fully usable, just slower — logged, never fatal.
struct JournalGuard<'a> {
    conn: &'a Connection,
    was_wal: bool,
}

impl<'a> JournalGuard<'a> {
    fn enter(conn: &'a Connection) -> Result<Self, String> {
        let mode: String = conn
            .query_row("PRAGMA journal_mode;", [], |r| r.get(0))
            .map_err(|e| format!("journal:{}", super::pipeline::sqlite_kind(&e)))?;
        let was_wal = mode.eq_ignore_ascii_case("wal");
        if was_wal {
            // F1 (blocker): SQLite does not fail LOUDLY when it cannot
            // leave WAL because another connection (the archive
            // window's cached session, an external tool) still has the
            // store open. Two shapes exist: the documented one answers
            // the switch with `wal` (no error), and THIS vendored
            // SQLCipher build surfaces SQLITE_BUSY on the statement
            // (verified by the store-busy test). Read the ANSWER and
            // treat either shape the same: the journal is still WAL,
            // so a rekey here would run beside a live reader (rekey is
            // not WAL-safe) — refuse BEFORE touching any key, marker
            // or remember file. The caller maps `store-busy` to
            // "close the archive window and try again".
            let got: Result<String, rusqlite::Error> =
                conn.query_row("PRAGMA journal_mode = DELETE;", [], |r| r.get(0));
            match got {
                Ok(m) if m.eq_ignore_ascii_case("delete") => {}
                Ok(_) => return Err("store-busy".into()),
                Err(e) => {
                    // Kind-only log line (H-rule) so the underlying
                    // sqlite shape stays diagnosable.
                    crate::dlog::log(&format!(
                        "shadow: journal stays WAL — conversion refused ({}); close other \
                         windows/tools using the store",
                        super::pipeline::sqlite_kind(&e)
                    ));
                    return Err("store-busy".into());
                }
            }
        }
        Ok(Self { conn, was_wal })
    }

    /// Back to WAL (best-effort; the caller logs a failure).
    fn exit(self) -> bool {
        if self.was_wal {
            self.conn
                .query_row("PRAGMA journal_mode = WAL;", [], |r| r.get::<_, String>(0))
                .is_ok()
        } else {
            true
        }
    }
}

/// Row count per user table — same query as the backup manifest, so a
/// conversion's before/after comparison is exactly the verify set.
fn counts(conn: &Connection) -> Result<BTreeMap<String, i64>, String> {
    backup::user_table_counts(conn)
        .map_err(|e| format!("counts:{}", super::pipeline::sqlite_kind(&e)))
}

/// `PRAGMA integrity_check` must be exactly "ok" (same rule as
/// [`backup::verify_backup`]).
fn integrity_ok(conn: &Connection) -> Result<(), String> {
    let mut st = conn
        .prepare("PRAGMA integrity_check;")
        .map_err(|e| format!("integrity:{}", super::pipeline::sqlite_kind(&e)))?;
    let rows: Vec<String> = st
        .query_map([], |r| r.get(0))
        .map_err(|e| format!("integrity:{}", super::pipeline::sqlite_kind(&e)))?
        .flatten()
        .collect();
    if rows.len() != 1 || rows[0] != "ok" {
        return Err("integrity-check".into());
    }
    Ok(())
}

/// Re-open the rekeyed DB read-only and run the full verification: key
/// accepted, integrity "ok", counts equal. `kind_of_open` says which
/// verifier to use ("passphrase"/"raw").
fn verify_rekeyed(
    db_path: &Path,
    kind_of_open: &str,
    pw: Option<&str>,
    raw: Option<&[u8]>,
    before: &BTreeMap<String, i64>,
) -> Result<(), String> {
    let check = match (kind_of_open, pw, raw) {
        ("passphrase", Some(p), _) => {
            sqlcipher::open_with_passphrase_readonly(db_path, p).map_err(|_| "verify-open".to_string())?
        }
        ("raw", _, Some(k)) => {
            sqlcipher::open_with_key_readonly(db_path, k).map_err(|_| "verify-open".to_string())?
        }
        _ => return Err("verify-open".into()),
    };
    integrity_ok(&check)?;
    if counts(&check).map_err(|_| "verify-counts".to_string())? != *before {
        return Err("verify-counts".into());
    }
    Ok(())
}

/// Convert the store raw → passphrase (the flusher's connection, opened
/// with the RAW key). Steps per the brief; every error is a KIND only
/// (H-rule). On any failure after the rekey the store is rekeyed BACK to
/// the original raw key, so it stays raw mode and usable — the marker is
/// only written after the full verification.
pub fn set_passphrase(
    conn: &Connection,
    dir: &Path,
    passphrase: &str,
    remember: bool,
    now_ms: i64,
) -> Result<(), String> {
    set_passphrase_impl(conn, dir, passphrase, remember, now_ms, None)
}

pub(crate) fn set_passphrase_impl(
    conn: &Connection,
    dir: &Path,
    passphrase: &str,
    remember: bool,
    now_ms: i64,
    inject: Option<FailAt>,
) -> Result<(), String> {
    // Preconditions: raw mode with a raw key file on disk.
    if read_mode(dir) != StoreKeyMode::Raw {
        return Err("not-raw".into());
    }
    let key_path = super::key_file(dir);
    if !key_path.is_file() {
        return Err("no-key-file".into());
    }
    let raw_key =
        Zeroizing::new(sqlcipher::load_key(&key_path).map_err(|_| "key".to_string())?);
    validate_passphrase(passphrase).map_err(|_| "invalid-passphrase".to_string())?;
    let before = counts(conn)?;

    // Pre-backup with the OLD raw key (machine-bound by definition: it
    // opens only through this machine's DPAPI). Its folder name and the
    // manifest's `mode: raw` label it as such.
    let backup_dir = dir.join("pre-passphrase-backups");
    let mut stamp = now_ms;
    while backup::backup_db_path(&backup_dir, stamp).exists() {
        stamp += 1_000;
    }
    let manifest = backup::backup_db(conn, &BackupKey::Raw(raw_key.as_slice()), &backup_dir, stamp)
        .map_err(|kind| format!("backup:{kind}"))?;
    backup::verify_backup(
        &backup::backup_db_path(&backup_dir, stamp),
        &BackupKey::Raw(raw_key.as_slice()),
        &manifest,
    )
    .map_err(|kind| format!("backup-verify:{kind}"))?;

    // F2 (blocker): from the journal step through the finalize, the
    // store gate's WRITE guard must be held — the media cycle honours
    // the READ guard, so no in-process reader connection exists during
    // the conversion, and the next cycle opens with the cell's NEW key.
    let _gate = store_gate_write();
    // F1 (blocker): the journal must actually LEAVE WAL before any
    // rekey; a `store-busy` refusal here touches no key, marker or
    // remember file (the pre-backup above staying behind is fine).
    let journal = JournalGuard::enter(conn)?;
    let result = set_passphrase_after_backup(
        conn,
        dir,
        passphrase,
        remember,
        now_ms,
        &raw_key,
        &before,
        inject,
    );
    if !journal.exit() {
        crate::dlog::log("shadow: journal_mode restore to WAL failed (store stays usable)");
    }
    drop(_gate);
    result
}

fn set_passphrase_after_backup(
    conn: &Connection,
    dir: &Path,
    passphrase: &str,
    remember: bool,
    now_ms: i64,
    raw_key: &[u8],
    before: &BTreeMap<String, i64>,
    inject: Option<FailAt>,
) -> Result<(), String> {
    let db_path = super::db_file(dir);
    // F3 (blocker): set right after the rekey returns Ok — ANY Err
    // from that point on rekeys back to the ORIGINAL raw key (the
    // marker was never written and `default.key` is untouched, so the
    // store stays raw mode and usable). String-matching on error kinds
    // used to miss `marker` and the integrity prepare/query kinds.
    let mut rekey_landed = false;
    let result = (|| -> Result<(), String> {
        if let Err(e) = sqlcipher::rekey_passphrase(conn, passphrase) {
            return Err(format!("rekey:{}", key_kind(&e)));
        }
        rekey_landed = true;
        if inject == Some(FailAt::AfterRekey) {
            return Err("injected-after-rekey".into());
        }
        // Re-open with ONLY the passphrase (the portability proof) and verify.
        if let Err(why) = verify_rekeyed(&db_path, "passphrase", Some(passphrase), None, before) {
            return Err(why);
        }
        if inject == Some(FailAt::AfterVerify) {
            return Err("injected-after-verify".into());
        }
        // Marker only AFTER the verify; F3: a marker-write failure here
        // must rekey back too — the store would otherwise be keyed
        // with the passphrase while `default.key` still holds the raw
        // key, and every later open would try the raw key and fail.
        let marker_outcome = if inject == Some(FailAt::Marker) {
            Err(std::io::Error::other("injected"))
        } else {
            write_marker(dir, now_ms)
        };
        if marker_outcome.is_err() {
            return Err("marker".into());
        }
        // From here on the store IS passphrase mode: the remaining
        // steps are best-effort warnings, never conversion failures.
        // Rename the raw key file (kept, never deleted — the UI says
        // the user may delete it later). F4 (blocker): an existing
        // pre-passphrase key file from an EARLIER conversion is
        // archived aside under a stamp of its era — never deleted:
        // it is the only key that opens that era's pre-backup. If the
        // archive-aside fails, skip the rename entirely rather than
        // overwrite the older key.
        let pre = super::pre_passphrase_key_file(dir);
        let archived = if pre.exists() {
            match archive_pre_passphrase_key(dir, now_ms) {
                Ok(_) => true,
                Err(e) => {
                    crate::dlog::log(&format!(
                        "shadow: keeping default.key beside the marker (old pre-passphrase key \
                         not archived: {})",
                        io_kind(&e)
                    ));
                    false
                }
            }
        } else {
            true
        };
        if archived {
            if let Err(e) = std::fs::rename(super::key_file(dir), &pre) {
                crate::dlog::log(&format!(
                    "shadow: keeping default.key beside the marker (rename failed: {})",
                    io_kind(&e)
                ));
            }
        }
        if remember {
            // Best-effort by design: the store IS converted (marker written);
            // a remember-file failure is logged and retried later through the
            // "Nhớ trên máy này" toggle rather than failing the conversion.
            if let Err(e) = save_remembered(dir, passphrase) {
                crate::dlog::log(&format!(
                    "shadow: remember file NOT written ({}) — use the settings toggle to retry",
                    io_kind(&e)
                ));
            }
        } else {
            // A conversion never inherits an old remember file (raw mode
            // cannot have one, but a leftover from an earlier passphrase era
            // must not silently unlock the new one).
            let _ = forget_remembered(dir);
        }
        crate::dlog::log(&format!(
            "shadow: store converted to passphrase mode (tables={} backup=pre-passphrase-backups)",
            before.len()
        ));
        Ok(())
    })();
    if rekey_landed && result.is_err() {
        // F3: rekey back so the store stays RAW mode and usable. The
        // chosen recovery, tested by injection for every failure point.
        if let Err(e) = sqlcipher::rekey_raw(conn, raw_key) {
            crate::dlog::log(&format!(
                "shadow: CRITICAL rekey-back failed ({}) — the store file is now keyed with the \
                 new passphrase but the marker was NOT written; set the same password again, or \
                 restore from pre-passphrase-backups",
                key_kind(&e)
            ));
        }
    }
    result
}

/// Change the passphrase (the flusher's connection, already keyed with
/// the CURRENT passphrase). The command layer proves the OLD password by
/// opening the DB with it before this runs; `old_ram` is the flusher's
/// RAM copy of the same passphrase, used ONLY to recover a failure
/// after the rekey (rekey back so the user's old password keeps working
/// and the remember file stays truthful). The remember file is saved
/// (remember=true) or deleted (remember=false) so it can never go stale.
pub fn change_passphrase(
    conn: &Connection,
    dir: &Path,
    old_ram: Option<&str>,
    new: &str,
    remember: bool,
) -> Result<(), String> {
    change_passphrase_impl(conn, dir, old_ram, new, remember, None)
}

pub(crate) fn change_passphrase_impl(
    conn: &Connection,
    dir: &Path,
    old_ram: Option<&str>,
    new: &str,
    remember: bool,
    inject: Option<FailAt>,
) -> Result<(), String> {
    if read_mode(dir) != StoreKeyMode::Passphrase {
        return Err("not-passphrase".into());
    }
    validate_passphrase(new).map_err(|_| "invalid-passphrase".to_string())?;
    let db_path = super::db_file(dir);
    let before = counts(conn)?;
    // F2: the store gate's write guard spans the journal step through
    // the finalize (see set_passphrase_impl).
    let _gate = store_gate_write();
    // F1: refuse `store-busy` BEFORE the rekey when the journal cannot
    // leave WAL — no key, marker or remember file is touched.
    let journal = JournalGuard::enter(conn)?;
    // F3: set right after the rekey returns Ok — ANY Err after that
    // point rekeys back to the OLD passphrase (the old error-kind
    // string list missed nothing in practice here, but the flag makes
    // the rule structural instead of name-based).
    let mut rekey_landed = false;
    let result = (|| -> Result<(), String> {
        if let Err(e) = sqlcipher::rekey_passphrase(conn, new) {
            return Err(format!("rekey:{}", key_kind(&e)));
        }
        rekey_landed = true;
        if inject == Some(FailAt::AfterRekey) {
            return Err("injected-after-rekey".into());
        }
        if let Err(why) = verify_rekeyed(&db_path, "passphrase", Some(new), None, &before) {
            return Err(why);
        }
        if inject == Some(FailAt::AfterVerify) {
            return Err("injected-after-verify".into());
        }
        if remember {
            // Best-effort (see set_passphrase): a failed remember write
            // is logged and retried through the toggle, never a rollback.
            if let Err(e) = save_remembered(dir, new) {
                crate::dlog::log(&format!(
                    "shadow: remember file NOT updated ({}) — the password DID change; use the \
                     settings toggle to retry",
                    io_kind(&e)
                ));
            }
        } else {
            // Dropping the remember file matters here: it holds the OLD
            // password, which no longer opens the store. A failure is
            // logged; the next start's unlock prompt (new password) is
            // the recovery.
            if let Err(e) = forget_remembered(dir) {
                crate::dlog::log(&format!(
                    "shadow: remember file NOT deleted ({}) — it is stale now",
                    io_kind(&e)
                ));
            }
        }
        crate::dlog::log("shadow: store passphrase changed (mode unchanged)");
        Ok(())
    })();
    if rekey_landed && result.is_err() {
        // The rekey HAD landed (verification failed, or the injected
        // test) and left the store keyed with `new` while the user
        // still holds `old`: rekey back so the old password (and an
        // untouched remember file) keep working.
        if let Some(old) = old_ram {
            if let Err(e) = sqlcipher::rekey_passphrase(conn, old) {
                crate::dlog::log(&format!(
                    "shadow: CRITICAL rekey-back failed ({}) — the store is keyed with the NEW \
                     passphrase; the old one no longer opens it",
                    key_kind(&e)
                ));
            }
        }
    }
    if !journal.exit() {
        crate::dlog::log("shadow: journal_mode restore to WAL failed (store stays usable)");
    }
    drop(_gate);
    result
}

/// Remove the password: rekey to a FRESH random raw key (saved DPAPI into
/// `default.key` BEFORE the rekey — so a failure can never strand the
/// store keyed with a key that exists nowhere on disk), verify, then
/// remove the marker + remember file. `default.key.pre-passphrase` is
/// left exactly as it is. A failure after the rekey rekeys back to
/// `current_pass` (marker + remember file + actual key agree again),
/// and the freshly written `default.key` is then deleted: it must not
/// exist while the marker still says passphrase, because a later
/// "set" would treat it as the raw key of this store — which it is not.
pub fn remove_passphrase(conn: &Connection, dir: &Path, current_pass: &str) -> Result<(), String> {
    remove_passphrase_impl(conn, dir, current_pass, None)
}

pub(crate) fn remove_passphrase_impl(
    conn: &Connection,
    dir: &Path,
    current_pass: &str,
    inject: Option<FailAt>,
) -> Result<(), String> {
    if read_mode(dir) != StoreKeyMode::Passphrase {
        return Err("not-passphrase".into());
    }
    let db_path = super::db_file(dir);
    let before = counts(conn)?;
    // F2: the store gate's write guard spans the journal step through
    // the finalize (see set_passphrase_impl).
    let _gate = store_gate_write();
    // F1: refuse `store-busy` BEFORE generating or saving the fresh
    // raw key — on this refusal the key file, the marker and the
    // remember file are all untouched.
    let journal = JournalGuard::enter(conn)?;
    // F3: set right after the rekey returns Ok — ANY Err after that
    // point rekeys back to the current passphrase.
    let mut rekey_landed = false;
    let result = (|| -> Result<(), String> {
        // Fresh raw key, saved BEFORE the rekey (see the module docs: a
        // stranded raw key is unrecoverable, a stranded passphrase is
        // not; and while the marker still says passphrase, a stray raw
        // key file is simply ignored by every open path).
        let new_raw =
            Zeroizing::new(sqlcipher::generate_key().map_err(|_| "keygen".to_string())?);
        sqlcipher::save_key(&new_raw, &super::key_file(dir))
            .map_err(|_| "key-file".to_string())?;
        if let Err(e) = sqlcipher::rekey_raw(conn, &new_raw) {
            return Err(format!("rekey:{}", key_kind(&e)));
        }
        rekey_landed = true;
        if inject == Some(FailAt::AfterRekey) {
            return Err("injected-after-rekey".into());
        }
        if let Err(why) = verify_rekeyed(&db_path, "raw", None, Some(&new_raw), &before) {
            return Err(why);
        }
        if inject == Some(FailAt::AfterVerify) {
            return Err("injected-after-verify".into());
        }
        // F3: a marker-REMOVAL failure after the rekey must rekey back
        // too — the store would otherwise be keyed with the fresh raw
        // key while the marker still says passphrase, and nothing
        // would ever try that raw key.
        let marker_outcome = if inject == Some(FailAt::Marker) {
            Err(std::io::Error::other("injected"))
        } else {
            remove_marker(dir)
        };
        if marker_outcome.is_err() {
            return Err("marker".into());
        }
        // Best-effort (see set_passphrase): the store is raw-keyed and
        // the marker is gone; a stale remember file that fails to delete
        // is logged — it simply no longer opens anything.
        if let Err(e) = forget_remembered(dir) {
            crate::dlog::log(&format!(
                "shadow: remember file NOT deleted ({})",
                io_kind(&e)
            ));
        }
        crate::dlog::log("shadow: store passphrase removed (raw key mode)");
        Ok(())
    })();
    if rekey_landed && result.is_err() {
        // The store left the passphrase key (rekey landed) but did not
        // finalize: put the passphrase back so the marker and the
        // remember file are truthful again. The freshly written
        // `default.key` must then GO: it must not exist while the
        // marker still says passphrase (a later "set" would treat it as
        // the raw key). Deleted only after PROVING the passphrase opens
        // the store again — `sqlite3_rekey_v2` can roll back a busy
        // rekey and STILL return SQLITE_OK (the rekey-v2 fact; see
        // `migrate::sqlcipher::rekey_passphrase`), and in that rolled
        // back state `default.key` holds the ONLY key that opens the
        // store, so deleting it unverified would strand the store.
        let back_ok = match sqlcipher::rekey_passphrase(conn, current_pass) {
            Err(e) => {
                crate::dlog::log(&format!(
                    "shadow: CRITICAL rekey-back failed ({}) — default.key already holds the new \
                     raw key but the marker still says passphrase; delete default.keymode.json to \
                     use the raw key, or restore from pre-passphrase-backups",
                    key_kind(&e)
                ));
                false
            }
            Ok(()) => match sqlcipher::open_with_passphrase_readonly(&db_path, current_pass) {
                Ok(_) => true,
                Err(e) => {
                    crate::dlog::log(&format!(
                        "shadow: CRITICAL rekey-back did not land ({}) — default.key already holds \
                         the new raw key but the marker still says passphrase; delete \
                         default.keymode.json to use the raw key, or restore from \
                         pre-passphrase-backups",
                        key_kind(&e)
                    ));
                    false
                }
            },
        };
        if back_ok {
            if let Err(e) = std::fs::remove_file(super::key_file(dir)) {
                crate::dlog::log(&format!(
                    "shadow: fresh default.key NOT removed after the rekey-back ({}) — it does \
                     not open this passphrase-keyed store; delete it manually after removing \
                     the password",
                    io_kind(&e)
                ));
            }
        }
    }
    if !journal.exit() {
        crate::dlog::log("shadow: journal_mode restore to WAL failed (store stays usable)");
    }
    drop(_gate);
    result
}

// --- F4: pre-passphrase key generations are never deleted --------------------

/// F4: rename an existing `default.key.pre-passphrase` aside — NEVER
/// delete it. Each generation of that file is the ONLY key that opens
/// the `pre-passphrase-backups/` backup taken right before that
/// conversion, so the archived name records which ERA it belongs to:
/// the old marker's `since_ms` when one is still readable, else the
/// file's mtime in ms (else the conversion's `now_ms`), plus a counter
/// when even that collides.
fn archive_pre_passphrase_key(
    dir: &Path,
    now_ms: i64,
) -> Result<std::path::PathBuf, std::io::Error> {
    let pre = super::pre_passphrase_key_file(dir);
    let stamp = old_marker_since_ms(dir)
        .or_else(|| file_mtime_ms(&pre))
        .unwrap_or(now_ms);
    let mut target = with_suffix(&pre, &stamp.to_string());
    let mut n = 1u64;
    while target.exists() {
        target = with_suffix(&pre, &format!("{stamp}.{n}"));
        n += 1;
    }
    std::fs::rename(&pre, &target)?;
    Ok(target)
}

/// Best-effort `since_ms` of a marker still readable next to the key
/// file being archived. In practice the marker is gone by the time a
/// raw-era key file gets archived (the store is raw mode then, which
/// is exactly the no-marker state) — the file's mtime is the working
/// stamp; this read just prefers the more precise value when it exists.
fn old_marker_since_ms(dir: &Path) -> Option<i64> {
    let text = std::fs::read_to_string(super::keymode_file(dir)).ok()?;
    serde_json::from_str::<KeyModeMarker>(&text)
        .ok()
        .map(|m| m.since_ms)
}

/// mtime of `path` in epoch ms (best-effort).
fn file_mtime_ms(path: &Path) -> Option<i64> {
    let meta = std::fs::metadata(path).ok()?;
    let t = meta.modified().ok()?;
    Some(t.duration_since(std::time::UNIX_EPOCH).ok()?.as_millis() as i64)
}

/// `<dir>/<name>.<suffix>` for a sibling rename — built manually on
/// purpose: `PathBuf::with_extension` would rewrite after the LAST dot
/// of a file name that already carries two (`default.key.pre-passphrase`).
fn with_suffix(base: &Path, suffix: &str) -> std::path::PathBuf {
    let mut name = base.file_name().map_or_else(
        || std::ffi::OsString::from("default.key.pre-passphrase"),
        |n| n.to_os_string(),
    );
    name.push(".");
    name.push(suffix);
    base.with_file_name(name)
}

/// Log-safe io error kind (H-rule: never the path, never the raw text).
fn io_kind(e: &std::io::Error) -> String {
    format!("{:?}", e.kind())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::migrate::sqlcipher;
    use std::path::PathBuf;

    // OBVIOUSLY FAKE passwords (H-rule: tests never carry anything that
    // resembles a real secret). All >= MIN_PASS_LEN so validation passes.
    const FAKE_PASS: &str = "fake-pass-phrase-0123456789";
    const FAKE_PASS_2: &str = "fake-other-pass-abcdefghij";

    fn scratch(tag: &str) -> PathBuf {
        static SEQ: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
        let dir = std::env::temp_dir().join(format!(
            "zr-pass-store-{}-{tag}-{}",
            std::process::id(),
            SEQ.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
        ));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    /// A synthetic RAW-mode store: default.key (DPAPI-wrapped by
    /// `save_key`) + default.db with the schema and two user rows, WAL
    /// journal (exactly what `runtime::open_db` produces). Returns
    /// (dir, raw key) with the store CLOSED.
    fn raw_store(tag: &str) -> (PathBuf, Zeroizing<Vec<u8>>) {
        let dir = scratch(tag);
        let key = Zeroizing::new(sqlcipher::generate_key().unwrap());
        sqlcipher::save_key(&key, &super::super::key_file(&dir)).unwrap();
        {
            let conn = sqlcipher::open_with_key(&super::super::db_file(&dir), &key).unwrap();
            crate::shadow::schema::apply(&conn).unwrap();
            seed_rows(&conn);
        }
        (dir, key)
    }

    fn seed_rows(conn: &Connection) {
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
    }

    /// Open the store's RW connection the way the flusher would (raw).
    fn flusher_conn_raw(dir: &Path, key: &[u8]) -> Connection {
        sqlcipher::open_with_key(&super::super::db_file(dir), key).unwrap()
    }

    fn message_rows(conn: &Connection) -> i64 {
        conn.query_row("SELECT COUNT(*) FROM messages", [], |r| r.get(0))
            .unwrap()
    }

    // --- the mode marker --------------------------------------------------

    #[test]
    fn absent_marker_is_raw_and_a_bad_marker_is_unknown() {
        let dir = scratch("marker");
        assert_eq!(read_mode(&dir), StoreKeyMode::Raw);
        write_marker(&dir, 1_795_000_000_000).unwrap();
        assert_eq!(read_mode(&dir), StoreKeyMode::Passphrase);
        // The marker is plaintext JSON with the documented shape, and
        // carries NO secret material.
        let text = std::fs::read_to_string(super::super::keymode_file(&dir)).unwrap();
        let m: serde_json::Value = serde_json::from_str(&text).unwrap();
        assert_eq!(m["mode"], "passphrase");
        assert_eq!(m["kdf"], "sqlcipher4-default");
        assert_eq!(m["since_ms"], serde_json::json!(1_795_000_000_000i64));
        assert_eq!(text.lines().count(), 1, "one small line, no padding");
        // Anything unreadable/unknown is UNKNOWN, never silently raw.
        std::fs::write(super::super::keymode_file(&dir), b"{not json").unwrap();
        assert_eq!(read_mode(&dir), StoreKeyMode::Unknown);
        std::fs::write(
            super::super::keymode_file(&dir),
            br#"{"mode":"some-future-mode","kdf":"x","since_ms":0}"#,
        )
        .unwrap();
        assert_eq!(read_mode(&dir), StoreKeyMode::Unknown);
        // remove_marker is idempotent.
        remove_marker(&dir).unwrap();
        remove_marker(&dir).unwrap();
        assert_eq!(read_mode(&dir), StoreKeyMode::Raw);
    }

    // --- validation + throttle --------------------------------------------

    #[test]
    fn validation_bounds_and_characters() {
        assert_eq!(validate_passphrase(FAKE_PASS), Ok(()));
        assert_eq!(validate_passphrase("short"), Err(PassInvalid::TooShort));
        assert_eq!(
            validate_passphrase("exactly12ch!"),
            Ok(()),
            "12 chars is accepted"
        );
        assert_eq!(
            validate_passphrase(&"x".repeat(MAX_PASS_LEN + 1)),
            Err(PassInvalid::TooLong)
        );
        assert_eq!(
            validate_passphrase("has-nul-byte-\0-inside"),
            Err(PassInvalid::BadChars)
        );
        // A passphrase with single quotes survives rusqlite's literal
        // quoting (the roundtrip test below covers it end-to-end).
        assert_eq!(validate_passphrase("fake-with-quote-'-12"), Ok(()));
    }

    #[test]
    fn throttle_five_free_then_thirty_second_backoff() {
        let t0 = Instant::now();
        let mut t = ShadowThrottle::default();
        for i in 0..(FREE_TRIES - 1) {
            t.record_failure(t0);
            assert!(t.check(t0).is_ok(), "try {} must still be free", i + 1);
        }
        // The FREE_TRIES-th failure arms the window: the NEXT attempt
        // is blocked for the 30 s backoff (check returns the ceiling,
        // so a fresh block yields 31, and 1 second left yields 2); the
        // window shrinks as time passes and a success resets
        // everything.
        t.record_failure(t0);
        assert_eq!(t.check(t0), Err(BLOCK_SECS + 1));
        assert_eq!(t.check(t0 + std::time::Duration::from_secs(29)), Err(2));
        assert!(t.check(t0 + std::time::Duration::from_secs(30)).is_ok());
        t.record_success();
        assert!(t.check(t0).is_ok());
        // Sanity on the shared shape.
        assert_eq!(FREE_TRIES, 5);
        assert_eq!(BLOCK_SECS, 30);
    }

    // --- the remember file --------------------------------------------------

    #[test]
    fn remember_file_roundtrip_and_refusal_without_it() {
        let dir = scratch("remember");
        assert!(!remembered_present(&dir));
        // Without a marker this is a raw dir: open_store needs a key
        // file, so a locked store cannot even arise here.
        save_remembered(&dir, FAKE_PASS).unwrap();
        assert!(remembered_present(&dir));
        let back = load_remembered(&dir).unwrap();
        assert_eq!(back.as_str(), FAKE_PASS);
        // The wrapped file never contains the passphrase in the clear.
        let blob = std::fs::read(super::super::pass_dpapi_file(&dir)).unwrap();
        assert!(
            !blob.windows(FAKE_PASS.len()).any(|w| w == FAKE_PASS.as_bytes()),
            "the remember file must not hold the passphrase in the clear"
        );
        forget_remembered(&dir).unwrap();
        assert!(!remembered_present(&dir));
        assert!(load_remembered(&dir).is_err());
        // Idempotent delete.
        forget_remembered(&dir).unwrap();
    }

    // --- the full R5 conversion lifecycle -----------------------------------

    #[test]
    fn raw_to_passphrase_then_portable_open_in_a_fresh_dir() {
        let (dir, raw_key) = raw_store("convert");
        {
            let conn = flusher_conn_raw(&dir, &raw_key);
            set_passphrase(&conn, &dir, FAKE_PASS, true, 1_795_000_000_000).unwrap();
        }
        // The marker says passphrase with the given stamp.
        let marker: KeyModeMarker = serde_json::from_str(
            &std::fs::read_to_string(super::super::keymode_file(&dir)).unwrap(),
        )
        .unwrap();
        assert_eq!(marker.mode, "passphrase");
        assert_eq!(marker.since_ms, 1_795_000_000_000);
        // The raw key file was RENAMED (kept), not deleted.
        assert!(!super::super::key_file(&dir).is_file());
        assert!(super::super::pre_passphrase_key_file(&dir).is_file());
        // The remember file exists (remember=true) and unwraps.
        assert_eq!(load_remembered(&dir).unwrap().as_str(), FAKE_PASS);
        // The pre-conversion backup landed under its own folder and is
        // MACHINE-BOUND: it opens with the OLD raw key and refuses the
        // passphrase (mode label "raw").
        let backup_dir = dir.join("pre-passphrase-backups");
        let mut found = 0;
        for entry in std::fs::read_dir(&backup_dir).unwrap().flatten() {
            if entry.path().extension().is_some_and(|e| e == "json") {
                found += 1;
                let manifest: backup::BackupManifest =
                    serde_json::from_slice(&std::fs::read(entry.path()).unwrap()).unwrap();
                assert_eq!(manifest.mode, "raw");
                let db_path = entry.path().with_extension("db");
                assert!(matches!(
                    sqlcipher::open_with_passphrase_readonly(&db_path, FAKE_PASS),
                    Err(sqlcipher::KeyError::WrongPassword)
                ));
                assert!(sqlcipher::open_with_key_readonly(&db_path, &raw_key).is_ok());
            }
        }
        assert_eq!(found, 1, "exactly one pre-passphrase backup set");
        // The store itself no longer opens with the raw key.
        assert!(sqlcipher::open_with_key_readonly(&super::super::db_file(&dir), &raw_key).is_err());
        // open_store (the shared R4 path) opens it through the remember
        // file and reports the passphrase mode.
        let (conn, key) = open_store(&dir, true).unwrap();
        assert_eq!(key.label(), "passphrase");
        assert_eq!(message_rows(&conn), 1);
        // The journal mode went back to WAL.
        let mode: String = conn.query_row("PRAGMA journal_mode;", [], |r| r.get(0)).unwrap();
        drop(conn); // Windows: the copy below needs the file handle free
        assert_eq!(mode.to_ascii_lowercase(), "wal");

        // PORTABILITY (the brief's headline property): a FRESH dir
        // containing ONLY default.db opens with the password alone.
        let fresh = scratch("convert-fresh");
        std::fs::copy(super::super::db_file(&dir), fresh.join("default.db")).unwrap();
        let plain = rusqlite::Connection::open(fresh.join("default.db")).unwrap();
        plain
            .execute_batch(&format!("PRAGMA key = '{FAKE_PASS}';"))
            .unwrap();
        let n: i64 = plain
            .query_row("SELECT COUNT(*) FROM messages", [], |r| r.get(0))
            .unwrap();
        assert_eq!(n, 1);
        drop(plain); // Windows: the cleanup deletes the file
        // The fresh copy has no key file, no DPAPI, no marker — and the
        // wrong password is TYPED-refused.
        assert!(matches!(
            sqlcipher::open_with_passphrase_readonly(&fresh.join("default.db"), FAKE_PASS_2),
            Err(sqlcipher::KeyError::WrongPassword)
        ));
        std::fs::remove_dir_all(&dir).unwrap();
        std::fs::remove_dir_all(&fresh).unwrap();
    }

    #[test]
    fn a_quote_in_the_passphrase_survives_the_quoting() {
        // rusqlite's `pragma_update` renders the value as a SQLite
        // string literal; a `'` in the middle must roundtrip (proving no
        // format!()-style injection either broke the key or the SQL).
        // The manual third-party statement below escapes the quote the
        // SQLite way — exactly what DB Browser / the sqlite3 shell do
        // with a typed password.
        let pw = "fake-with-quote-'-12";
        let (dir, raw_key) = raw_store("quote");
        {
            let conn = flusher_conn_raw(&dir, &raw_key);
            set_passphrase(&conn, &dir, pw, false, 1).unwrap();
        }
        let fresh = scratch("quote-fresh");
        std::fs::copy(super::super::db_file(&dir), fresh.join("default.db")).unwrap();
        let plain = rusqlite::Connection::open(fresh.join("default.db")).unwrap();
        plain
            .execute_batch(&format!("PRAGMA key = '{}';", pw.replace('\'', "''")))
            .unwrap();
        let n: i64 = plain
            .query_row("SELECT COUNT(*) FROM messages", [], |r| r.get(0))
            .unwrap();
        assert_eq!(n, 1);
        drop(plain);
        std::fs::remove_dir_all(&dir).unwrap();
        std::fs::remove_dir_all(&fresh).unwrap();
    }

    #[test]
    fn conversion_failure_injection_leaves_the_store_raw_and_usable() {
        for inject in [FailAt::AfterRekey, FailAt::AfterVerify] {
            let (dir, raw_key) = raw_store(&format!("inject-{:?}", inject));
            let conn = flusher_conn_raw(&dir, &raw_key);
            let err = set_passphrase_impl(
                &conn,
                &dir,
                FAKE_PASS,
                true,
                1_795_000_000_000,
                Some(inject),
            )
            .unwrap_err();
            // The error is a KIND only — never the password, never a
            // path, never sqlite text (H-rule).
            assert!(
                !err.contains(FAKE_PASS) && !err.contains("sqlcipher error"),
                "error must stay kind-only: {err}"
            );
            assert_eq!(err, format!("injected-{}", match inject {
                FailAt::AfterRekey => "after-rekey",
                FailAt::AfterVerify => "after-verify",
                // This loop never injects the marker step (its own test
                // covers it); the arm just keeps the match exhaustive.
                FailAt::Marker => "marker",
            }));
            // The store stayed RAW and usable: the marker never landed,
            // the key file was never renamed, the remember file never
            // appeared, and the ORIGINAL key still opens the data.
            assert_eq!(read_mode(&dir), StoreKeyMode::Raw);
            assert!(super::super::key_file(&dir).is_file());
            assert!(!super::super::keymode_file(&dir).is_file());
            assert!(!super::super::pass_dpapi_file(&dir).is_file());
            assert_eq!(message_rows(&conn), 1);
            drop(conn);
            let reopen = flusher_conn_raw(&dir, &raw_key);
            assert_eq!(message_rows(&reopen), 1, "a fresh open reads the data");
            // The journal mode still went back to WAL.
            let mode: String =
                reopen.query_row("PRAGMA journal_mode;", [], |r| r.get(0)).unwrap();
            drop(reopen); // Windows: the cleanup below deletes the db file
            assert_eq!(mode.to_ascii_lowercase(), "wal");
            // And the pre-passphrase backup did land (machine-bound,
            // openable with the ORIGINAL raw key).
            let stamps = std::fs::read_dir(dir.join("pre-passphrase-backups"))
                .unwrap()
                .flatten()
                .filter(|e| e.path().extension().is_some_and(|x| x == "db"))
                .count();
            assert_eq!(stamps, 1);
            std::fs::remove_dir_all(&dir).unwrap();
        }
    }

    #[test]
    fn change_password_requires_the_marker_and_verifies() {
        let (dir, raw_key) = raw_store("change");
        {
            let conn = flusher_conn_raw(&dir, &raw_key);
            set_passphrase(&conn, &dir, FAKE_PASS, true, 1).unwrap();
        }
        // The change runs on the passphrase-keyed "flusher" connection;
        // `old_ram` is the recovery key, exactly like the runtime job.
        {
            let conn = sqlcipher::open_with_passphrase(&super::super::db_file(&dir), FAKE_PASS)
                .unwrap();
            // Raw-mode precondition refuses (a dir with no marker).
            assert_eq!(
                change_passphrase(
                    &conn,
                    std::path::Path::new("no-such-store-dir"),
                    None,
                    FAKE_PASS_2,
                    true
                ),
                Err("not-passphrase".into())
            );
            change_passphrase(&conn, &dir, Some(FAKE_PASS), FAKE_PASS_2, true).unwrap();
        }
        // The OLD password no longer opens it; the NEW one does; the
        // remember file was updated to the new password.
        assert!(matches!(
            sqlcipher::open_with_passphrase_readonly(&super::super::db_file(&dir), FAKE_PASS),
            Err(sqlcipher::KeyError::WrongPassword)
        ));
        let conn = sqlcipher::open_with_passphrase(&super::super::db_file(&dir), FAKE_PASS_2)
            .unwrap();
        assert_eq!(message_rows(&conn), 1);
        assert_eq!(read_mode(&dir), StoreKeyMode::Passphrase);
        assert_eq!(load_remembered(&dir).unwrap().as_str(), FAKE_PASS_2);
        drop(conn);
        // change with remember=false drops the remember file.
        {
            let conn = sqlcipher::open_with_passphrase(&super::super::db_file(&dir), FAKE_PASS_2)
                .unwrap();
            change_passphrase(&conn, &dir, Some(FAKE_PASS_2), FAKE_PASS, false).unwrap();
        }
        assert!(!remembered_present(&dir));
        // A change failure after the rekey REKEYS BACK: the old password
        // keeps working (the injected engine uses old_ram for recovery).
        {
            let conn = sqlcipher::open_with_passphrase(&super::super::db_file(&dir), FAKE_PASS)
                .unwrap();
            let err = change_passphrase_impl(
                &conn,
                &dir,
                Some(FAKE_PASS),
                FAKE_PASS_2,
                true,
                Some(FailAt::AfterVerify),
            )
            .unwrap_err();
            assert_eq!(err, "injected-after-verify");
            assert!(!err.contains(FAKE_PASS_2), "kind only");
        }
        assert_eq!(
            sqlcipher::open_with_passphrase_readonly(&super::super::db_file(&dir), FAKE_PASS)
                .map(|c| message_rows(&c))
                .unwrap(),
            1,
            "the old password still opens the store after a failed change"
        );
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn remove_password_goes_back_to_a_fresh_raw_key() {
        let (dir, raw_key) = raw_store("remove");
        {
            let conn = flusher_conn_raw(&dir, &raw_key);
            set_passphrase(&conn, &dir, FAKE_PASS, true, 1).unwrap();
        }
        {
            let conn = sqlcipher::open_with_passphrase(&super::super::db_file(&dir), FAKE_PASS)
                .unwrap();
            remove_passphrase(&conn, &dir, FAKE_PASS).unwrap();
        }
        // The marker and remember file are gone; the pre-passphrase key
        // file is STILL kept; a fresh random raw key file exists whose
        // key is NOT the original one (fresh = different bytes).
        assert_eq!(read_mode(&dir), StoreKeyMode::Raw);
        assert!(!remembered_present(&dir));
        assert!(super::super::pre_passphrase_key_file(&dir).is_file());
        let new_key = sqlcipher::load_key(&super::super::key_file(&dir)).unwrap();
        assert_ne!(new_key.as_slice(), raw_key.as_slice());
        // The new key opens the store; neither the passphrase nor the
        // OLD raw key does.
        let conn = sqlcipher::open_with_key(&super::super::db_file(&dir), &new_key).unwrap();
        assert_eq!(message_rows(&conn), 1);
        drop(conn);
        assert!(matches!(
            sqlcipher::open_with_passphrase_readonly(&super::super::db_file(&dir), FAKE_PASS),
            Err(sqlcipher::KeyError::WrongPassword)
        ));
        assert!(sqlcipher::open_with_key_readonly(&super::super::db_file(&dir), &raw_key).is_err());
        // open_store now reports raw mode through the shared path.
        let (conn, key) = open_store(&dir, true).unwrap();
        assert_eq!(key.label(), "raw");
        assert_eq!(message_rows(&conn), 1);
        drop(conn); // Windows: the cleanup below deletes the db file
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn remove_failure_injection_keeps_the_passphrase_store_truthful() {
        for inject in [FailAt::AfterRekey, FailAt::AfterVerify] {
            let (dir, raw_key) = raw_store(&format!("remove-inject-{:?}", inject));
            {
                let conn = flusher_conn_raw(&dir, &raw_key);
                set_passphrase(&conn, &dir, FAKE_PASS, true, 1).unwrap();
            }
            {
                let conn =
                    sqlcipher::open_with_passphrase(&super::super::db_file(&dir), FAKE_PASS)
                        .unwrap();
                let err =
                    remove_passphrase_impl(&conn, &dir, FAKE_PASS, Some(inject)).unwrap_err();
                assert_eq!(
                    err,
                    format!("injected-{}", match inject {
                        FailAt::AfterRekey => "after-rekey",
                        FailAt::AfterVerify => "after-verify",
                        // Never iterated here (the marker test covers it).
                        FailAt::Marker => "marker",
                    })
                );
                assert!(!err.contains(FAKE_PASS), "kind only");
            }
            // Marker + remember + actual key all still say passphrase.
            assert_eq!(read_mode(&dir), StoreKeyMode::Passphrase);
            assert!(remembered_present(&dir));
            assert_eq!(
                sqlcipher::open_with_passphrase_readonly(&super::super::db_file(&dir), FAKE_PASS)
                    .map(|c| message_rows(&c))
                    .unwrap(),
                1
            );
            std::fs::remove_dir_all(&dir).unwrap();
        }
    }

    // --- F1–F4 (batch-18 review fixes) ---------------------------------------

    #[test]
    fn a_second_wal_reader_makes_every_conversion_refuse_store_busy() {
        // F1 (blocker): `PRAGMA journal_mode = DELETE` answers `wal`
        // (NOT an error) while another connection holds the store's
        // WAL. Every conversion must refuse with `store-busy` BEFORE
        // any rekey — and touch no key, marker or remember file. (The
        // pre-backup of a refused set staying behind is accepted.)
        let (dir, raw_key) = raw_store("busy");
        let db_path = super::super::db_file(&dir);
        let key_bytes_before = std::fs::read(super::super::key_file(&dir)).unwrap();
        {
            let conn = flusher_conn_raw(&dir, &raw_key);
            // A second READ-ONLY connection that has actually read —
            // the archive window's cached session, or an external tool.
            let reader = sqlcipher::open_with_key_readonly(&db_path, &raw_key).unwrap();
            let _: i64 = reader
                .query_row("SELECT COUNT(*) FROM messages", [], |r| r.get(0))
                .unwrap();
            assert_eq!(
                set_passphrase_impl(
                    &conn,
                    &dir,
                    FAKE_PASS,
                    true,
                    1_795_000_000_000,
                    None
                )
                .unwrap_err(),
                "store-busy"
            );
            // Nothing changed: raw mode, no marker, no remember file,
            // the key file neither renamed nor rewritten.
            assert_eq!(read_mode(&dir), StoreKeyMode::Raw);
            assert!(!super::super::keymode_file(&dir).is_file());
            assert!(!super::super::pass_dpapi_file(&dir).is_file());
            assert_eq!(
                std::fs::read(super::super::key_file(&dir)).unwrap(),
                key_bytes_before,
                "the raw key file must not be renamed or rewritten"
            );
            assert_eq!(message_rows(&conn), 1, "the store is untouched");
        }
        // The change/remove half needs a passphrase-mode store: the
        // reader must be gone for THAT conversion.
        {
            let conn = flusher_conn_raw(&dir, &raw_key);
            set_passphrase(&conn, &dir, FAKE_PASS, true, 1).unwrap();
        }
        {
            let conn = sqlcipher::open_with_passphrase(&db_path, FAKE_PASS).unwrap();
            let reader = sqlcipher::open_with_passphrase_readonly(&db_path, FAKE_PASS).unwrap();
            let _: i64 = reader
                .query_row("SELECT COUNT(*) FROM messages", [], |r| r.get(0))
                .unwrap();
            assert_eq!(
                change_passphrase_impl(
                    &conn,
                    &dir,
                    Some(FAKE_PASS),
                    FAKE_PASS_2,
                    true,
                    None
                )
                .unwrap_err(),
                "store-busy"
            );
            assert_eq!(read_mode(&dir), StoreKeyMode::Passphrase);
            assert_eq!(
                load_remembered(&dir).unwrap().as_str(),
                FAKE_PASS,
                "the remember file is untouched"
            );
            assert_eq!(
                remove_passphrase_impl(&conn, &dir, FAKE_PASS, None).unwrap_err(),
                "store-busy"
            );
            // No fresh raw key was written beside the passphrase
            // marker (the keygen happens only after the journal step).
            assert!(!super::super::key_file(&dir).is_file());
            assert_eq!(message_rows(&conn), 1, "the old password still reads the store");
        }
        // With the reader gone, the same change succeeds: the refusal
        // is a safety net, never a wedge.
        {
            let conn = sqlcipher::open_with_passphrase(&db_path, FAKE_PASS).unwrap();
            change_passphrase(&conn, &dir, Some(FAKE_PASS), FAKE_PASS_2, true).unwrap();
        }
        assert!(matches!(
            sqlcipher::open_with_passphrase_readonly(&db_path, FAKE_PASS_2)
                .map(|c| message_rows(&c)),
            Ok(1)
        ));
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn a_marker_failure_rekeys_set_back_to_raw_and_remove_back_to_the_passphrase() {
        // F3 (blocker): a marker-step failure happens AFTER the rekey.
        // The old code returned "marker" without rekeying back, stranding
        // the store (set: keyed passphrase, no marker, raw key file in
        // place; remove: keyed raw, marker says passphrase).
        let (dir, raw_key) = raw_store("marker-fail");
        let db_path = super::super::db_file(&dir);
        {
            let conn = flusher_conn_raw(&dir, &raw_key);
            assert_eq!(
                set_passphrase_impl(
                    &conn,
                    &dir,
                    FAKE_PASS,
                    true,
                    1_795_000_000_000,
                    Some(FailAt::Marker)
                )
                .unwrap_err(),
                "marker"
            );
            // The store is RAW and usable: no marker, key file in
            // place, ORIGINAL key opens it, counts equal, no remember
            // file ever appeared.
            assert_eq!(read_mode(&dir), StoreKeyMode::Raw);
            assert!(!super::super::keymode_file(&dir).is_file());
            assert!(super::super::key_file(&dir).is_file());
            assert!(!super::super::pass_dpapi_file(&dir).is_file());
            assert_eq!(message_rows(&conn), 1);
        }
        {
            let reopen = flusher_conn_raw(&dir, &raw_key);
            assert_eq!(message_rows(&reopen), 1, "a fresh open reads the data");
            let mode: String =
                reopen.query_row("PRAGMA journal_mode;", [], |r| r.get(0)).unwrap();
            drop(reopen); // Windows: the cleanup below deletes the db file
            assert_eq!(mode.to_ascii_lowercase(), "wal");
        }
        // remove: convert first, then fail the marker REMOVAL.
        {
            let conn = flusher_conn_raw(&dir, &raw_key);
            set_passphrase(&conn, &dir, FAKE_PASS, true, 1).unwrap();
        }
        {
            let conn = sqlcipher::open_with_passphrase(&db_path, FAKE_PASS).unwrap();
            assert_eq!(
                remove_passphrase_impl(&conn, &dir, FAKE_PASS, Some(FailAt::Marker))
                    .unwrap_err(),
                "marker"
            );
            // The store is PASSPHRASE and truthful again: the marker
            // and the remember file survived the failed removal, the
            // ORIGINAL password opens it, counts are equal — and the
            // freshly written default.key was deleted after the
            // successful rekey-back (it must not sit beside a marker
            // that still says passphrase).
            assert_eq!(read_mode(&dir), StoreKeyMode::Passphrase);
            assert!(remembered_present(&dir));
            assert_eq!(message_rows(&conn), 1);
            assert!(
                !super::super::key_file(&dir).is_file(),
                "no stray fresh raw key beside a passphrase marker"
            );
            // The pre-passphrase key file from the set is still kept.
            assert!(super::super::pre_passphrase_key_file(&dir).is_file());
        }
        assert!(matches!(
            sqlcipher::open_with_passphrase_readonly(&db_path, FAKE_PASS)
                .map(|c| message_rows(&c)),
            Ok(1)
        ));
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn set_remove_set_keeps_every_pre_passphrase_key_and_each_opens_its_backup() {
        // F4 (blocker): set → remove → set. The old code DELETED the
        // first era's `default.key.pre-passphrase` — the only key that
        // opens the FIRST pre-passphrase backup. It must be archived
        // aside instead, and each era's key opens exactly its own
        // backup.
        let (dir, raw_key0) = raw_store("eras");
        let t1 = 1_795_000_000_000i64;
        let t2 = t1 + 60_000;
        let backup_dir = dir.join("pre-passphrase-backups");
        {
            let conn = flusher_conn_raw(&dir, &raw_key0);
            set_passphrase(&conn, &dir, FAKE_PASS, true, t1).unwrap();
        }
        let pre = super::super::pre_passphrase_key_file(&dir);
        assert!(pre.is_file(), "the first era's key file is kept");
        // remove: back to a FRESH raw key (era 2).
        let key1 = {
            let conn = sqlcipher::open_with_passphrase(&super::super::db_file(&dir), FAKE_PASS)
                .unwrap();
            remove_passphrase(&conn, &dir, FAKE_PASS).unwrap();
            sqlcipher::load_key(&super::super::key_file(&dir)).unwrap()
        };
        assert_ne!(key1.as_slice(), raw_key0.as_slice());
        assert!(pre.is_file(), "remove leaves the first era's key file alone");
        // set again: the existing pre file must be ARCHIVED, not deleted.
        {
            let conn = flusher_conn_raw(&dir, &key1);
            set_passphrase(&conn, &dir, FAKE_PASS_2, true, t2).unwrap();
        }
        // BOTH old key files exist: the second era's at the well-known
        // name, the first era's archived under its stamp.
        assert!(pre.is_file());
        let archived: Vec<std::path::PathBuf> = std::fs::read_dir(&dir)
            .unwrap()
            .flatten()
            .map(|e| e.path())
            .filter(|p| {
                p.file_name()
                    .and_then(|n| n.to_str())
                    .is_some_and(|n| {
                        n.starts_with("default.key.pre-passphrase.")
                            && n != "default.key.pre-passphrase"
                    })
            })
            .collect();
        assert_eq!(archived.len(), 1, "exactly one archived key generation");
        let key0 = sqlcipher::load_key(&archived[0]).unwrap();
        assert_eq!(key0.as_slice(), raw_key0.as_slice());
        let key1_reloaded = sqlcipher::load_key(&pre).unwrap();
        assert_eq!(key1_reloaded.as_slice(), key1.as_slice());
        // Each key opens ITS OWN pre-passphrase backup (and refuses the
        // other era's backup).
        let backup1 = backup::backup_db_path(&backup_dir, t1);
        let backup2 = backup::backup_db_path(&backup_dir, t2);
        assert!(backup1.is_file() && backup2.is_file());
        {
            let c1 = sqlcipher::open_with_key_readonly(&backup1, &key0).unwrap();
            let n: i64 = c1
                .query_row("SELECT COUNT(*) FROM messages", [], |r| r.get(0))
                .unwrap();
            assert_eq!(n, 1);
            drop(c1); // Windows: the cleanup below deletes the db file
        }
        {
            let c2 = sqlcipher::open_with_key_readonly(&backup2, &key1_reloaded).unwrap();
            let n: i64 = c2
                .query_row("SELECT COUNT(*) FROM messages", [], |r| r.get(0))
                .unwrap();
            assert_eq!(n, 1);
            drop(c2);
        }
        assert!(
            sqlcipher::open_with_key_readonly(&backup1, &key1_reloaded).is_err(),
            "the first backup does not open with the second era's key"
        );
        assert!(
            sqlcipher::open_with_key_readonly(&backup2, &key0).is_err(),
            "the second backup does not open with the first era's key"
        );
        // And the store itself is keyed with the second passphrase.
        assert!(matches!(
            sqlcipher::open_with_passphrase_readonly(&super::super::db_file(&dir), FAKE_PASS_2)
                .map(|c| message_rows(&c)),
            Ok(1)
        ));
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn the_key_cell_holds_the_passphrase_and_bumps_its_epoch() {
        // F2 (blocker): the shared cell — publish bumps the epoch every
        // time; the value is the flusher's CURRENT RAM passphrase, None
        // in raw mode. Serialized with the other cell-mutating tests
        // through CELL_TEST_LOCK (production has ONE flusher).
        let _g = CELL_TEST_LOCK
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let e0 = cell_epoch();
        publish_key(Some(Zeroizing::new(FAKE_PASS.to_string())));
        let e1 = cell_epoch();
        assert!(e1 > e0, "publishing bumps the epoch");
        assert_eq!(
            cell_passphrase().as_deref().map(|p| p.as_str()),
            Some(FAKE_PASS)
        );
        publish_key(None);
        assert!(cell_epoch() > e1, "every publish bumps the epoch");
        assert!(cell_passphrase().is_none(), "None is the raw-mode value");
        // Leave the cell neutral for whichever test runs next.
        publish_key(None);
    }

    #[test]
    fn open_store_with_cell_prefers_the_cell_value_over_the_remember_file() {
        // F2: the archive window's open path. Unlocking WITHOUT
        // "remember" must still open the store in-process (the cell
        // holds the unlock's password); a stale cell value is skipped,
        // never trusted, and the remember file decides instead.
        let _g = CELL_TEST_LOCK
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let (dir, raw_key) = raw_store("cell-open");
        {
            let conn = flusher_conn_raw(&dir, &raw_key);
            set_passphrase(&conn, &dir, FAKE_PASS, true, 1).unwrap();
        }
        // No cell value yet: the remember file opens it (pre-F2 rules).
        publish_key(None);
        {
            let (conn, key) = open_store(&dir, true).unwrap();
            assert_eq!(key.label(), "passphrase");
            drop(conn);
        }
        // A WRONG cell value (a conversion raced us) is skipped: the
        // remember file decides, so the open still succeeds.
        publish_key(Some(Zeroizing::new(FAKE_PASS_2.to_string())));
        {
            let (conn, key) = open_store_with_cell(&dir, true).unwrap();
            assert_eq!(key.label(), "passphrase");
            assert_eq!(load_remembered(&dir).unwrap().as_str(), FAKE_PASS);
            drop(conn);
        }
        // The RIGHT cell value opens it even with NO remember file —
        // the "unlocked without remember" case the archive window
        // used to refuse.
        forget_remembered(&dir).unwrap();
        publish_key(Some(Zeroizing::new(FAKE_PASS.to_string())));
        {
            let (conn, key) = open_store_with_cell(&dir, true).unwrap();
            assert_eq!(key.label(), "passphrase");
            drop(conn);
        }
        // Neither source: the documented Locked refusal.
        publish_key(None);
        assert!(matches!(
            open_store_with_cell(&dir, true),
            Err(StoreOpenError::Locked)
        ));
        publish_key(None);
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn the_store_gate_write_guard_waits_for_a_held_read_guard() {
        // F2: the write guard (a conversion) blocks until every read
        // guard (a media cycle) is released — unit-level, no app launch.
        let read = store_gate_read();
        let (tx, rx) = std::sync::mpsc::channel::<()>();
        let writer = std::thread::spawn(move || {
            let _write = store_gate_write();
            let _ = tx.send(());
            // Hold it briefly so the main thread also observes it held.
            std::thread::sleep(std::time::Duration::from_millis(100));
        });
        assert!(
            rx.recv_timeout(std::time::Duration::from_millis(300)).is_err(),
            "the write guard must not be acquired while a read guard is held"
        );
        drop(read);
        assert!(
            rx.recv_timeout(std::time::Duration::from_secs(5)).is_ok(),
            "the write guard is acquired once the read guard is released"
        );
        writer.join().unwrap();
    }

    // --- open_store (R4) -----------------------------------------------------

    #[test]
    fn open_store_is_locked_without_a_usable_remember_file() {
        let (dir, raw_key) = raw_store("locked");
        {
            let conn = flusher_conn_raw(&dir, &raw_key);
            set_passphrase(&conn, &dir, FAKE_PASS, false, 1).unwrap();
        }
        // remember=false → no remember file → LOCKED, the documented R4
        // refusal (callers translate; the CLI never asks for a password).
        assert!(matches!(open_store(&dir, true), Err(StoreOpenError::Locked)));
        assert!(matches!(open_store(&dir, false), Err(StoreOpenError::Locked)));
        // A stale remember file (wrong password: the password changed
        // elsewhere) behaves the same way.
        save_remembered(&dir, FAKE_PASS_2).unwrap();
        assert!(matches!(open_store(&dir, true), Err(StoreOpenError::Locked)));
        // With the RIGHT remember file both opens work.
        save_remembered(&dir, FAKE_PASS).unwrap();
        assert!(open_store(&dir, true).is_ok());
        assert!(open_store(&dir, false).is_ok());
        // A raw dir with no key file fails with Other, not Locked.
        let bare = scratch("locked-bare");
        assert!(matches!(
            open_store(&bare, true),
            Err(StoreOpenError::Other(_))
        ));
        std::fs::remove_dir_all(&dir).unwrap();
    }

    // --- passwords never surface anywhere (H-rule, brief R5) -----------------

    #[test]
    fn passwords_never_appear_in_errors_markers_or_store_files() {
        let (dir, raw_key) = raw_store("secrecy");
        let outcomes: Vec<String> = {
            let conn = flusher_conn_raw(&dir, &raw_key);
            let mut errs = Vec::new();
            // Wrong-mode refusals and injected failures, all kind-only.
            errs.push(change_passphrase(&conn, &dir, Some(FAKE_PASS), FAKE_PASS_2, true)
                .unwrap_err());
            errs.push(remove_passphrase(&conn, &dir, FAKE_PASS).unwrap_err());
            errs.push(set_passphrase_impl(
                &conn, &dir, "short", false, 1, None,
            )
            .unwrap_err());
            errs.push(
                set_passphrase_impl(&conn, &dir, FAKE_PASS, true, 1, Some(FailAt::AfterRekey))
                    .unwrap_err(),
            );
            errs
        };
        for e in &outcomes {
            assert!(
                !e.contains(FAKE_PASS) && !e.contains(FAKE_PASS_2),
                "no error kind may quote a password: {e}"
            );
        }
        // The store dir holds no passphrase bytes in ANY plaintext file:
        // the marker is mode metadata; the remember file is DPAPI.
        let marker = std::fs::read_to_string(super::super::keymode_file(&dir))
            .unwrap_or_default();
        assert!(!marker.contains(FAKE_PASS));
        // set_passphrase with an invalid passphrase changed nothing.
        assert_eq!(read_mode(&dir), StoreKeyMode::Raw);
        // Conversion success: the DB header + pages hold only the
        // PBKDF2-derived key (SQLCipher), never the passphrase text —
        // proven by the portability test; here assert the marker file
        // once more and that settings-shaped files do not exist.
        {
            let conn = flusher_conn_raw(&dir, &raw_key);
            set_passphrase(&conn, &dir, FAKE_PASS, true, 1).unwrap();
        }
        let marker = std::fs::read_to_string(super::super::keymode_file(&dir)).unwrap();
        assert!(!marker.contains(FAKE_PASS));
        assert!(!dir.join("settings.json").exists());
        std::fs::remove_dir_all(&dir).unwrap();
    }

    // --- the wrong-password proof + throttle wiring --------------------------

    #[test]
    fn prove_under_the_throttle_counts_failures_and_blocks() {
        // The command layer's proof shape (commands::prove_passphrase):
        // one wrong probe counts, the 6th blocks, a success resets.
        // Exercised through the same `throttled_probe` wiring.
        let (dir, raw_key) = raw_store("prove");
        {
            let conn = flusher_conn_raw(&dir, &raw_key);
            set_passphrase(&conn, &dir, FAKE_PASS, false, 1).unwrap();
        }
        let db_path = super::super::db_file(&dir);
        let probe = |pw: &str| {
            throttled_probe(std::time::Instant::now(), || {
                matches!(
                    sqlcipher::open_with_passphrase_readonly(&db_path, pw),
                    Ok(_)
                )
            })
        };
        // Reset the shared limiter for this test's probes.
        *SHADOW_THROTTLE.lock().unwrap() = Some(ShadowThrottle::default());
        for i in 0..FREE_TRIES {
            assert_eq!(
                probe(FAKE_PASS_2),
                Err(0),
                "wrong password #{} counts without blocking",
                i + 1
            );
        }
        // The 5th failure armed the window: the NEXT attempt — wrong or
        // right — is gated (the throttle bounds attempts, not the key).
        assert!(matches!(probe(FAKE_PASS_2), Err(s) if s > 0));
        assert!(probe(FAKE_PASS).is_err());
        // After a reset (a fresh process would start unblocked), the
        // right password proves and the limiter stays clean.
        *SHADOW_THROTTLE.lock().unwrap() = Some(ShadowThrottle::default());
        assert_eq!(probe(FAKE_PASS), Ok(()));
        // A consecutive wrong attempt is free again (success reset it).
        assert_eq!(probe(FAKE_PASS_2), Err(0));
        std::fs::remove_dir_all(&dir).unwrap();
    }
}
