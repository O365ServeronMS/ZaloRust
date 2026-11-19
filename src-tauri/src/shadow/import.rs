//! Zalo Desktop DB import (P2 — dry-run skeleton; audit §4 items
//! 2.0–2.4, batch 6 F2–F4).
//!
//! Source layout (verified 2026-11-12/13, Zalo Desktop 26.11.12):
//! ```text
//! <snapshot>/  (a cold copy of <uid>/ from the Desktop DB tree)
//!   snapshot-manifest.json        written by tools/snapshot.ps1 (F5)
//!   Core\Index.db                 93 tables (conversations, contacts…)
//!   Core\Message\<id>.db         1-1 conversation message DBs
//!   Core\Message\g<id>.db        group conversation message DBs
//!   Core\Message\stranger_box.db  stranger messages
//!   Core\Message\undefined.db    skipped, counted (M2-4)
//!   … plus every -wal/-shm sidecar, copied by the snapshot script
//! ```
//!
//! Key facts (audit M2, all fixed here):
//! - The D7 capture is DPAPI-wrapped with NO entropy — its second
//!   argument was `szDataDescr`, not entropy (M2-1) — and the
//!   plaintext is JSON `{date, target_sha12, value_len, value}` with a
//!   32-char passphrase `value` (M2-2), not a raw 32-byte key.
//! - The Desktop DBs are keyed as a PASSPHRASE: string-form
//!   `PRAGMA key = '…'` runs the KDF (M2-3). The raw `x'hex'` form
//!   would bypass the KDF and derive the wrong page keys.
//! - `SQLITE_OPEN_READ_ONLY` alone still creates `-shm` on a WAL DB
//!   (M2-6): every source DB therefore opens through the URI
//!   `file:<path>?mode=ro&immutable=1`, which touches nothing.
//! - The import only ever reads a COLD SNAPSHOT (KQ4): `run` refuses
//!   the live Desktop tree by path component AND refuses any directory
//!   without `snapshot-manifest.json`.
//!
//! Safety (P2 acceptance):
//! - The passphrase arrives ONLY through the DPAPI-wrapped D7 file,
//!   is zeroized on drop, and is never printed or logged — only its
//!   length and sha256-12 ever appear.
//! - `--apply` stays fail-closed (2.5 wires the writer later).

use std::path::{Path, PathBuf};

use rusqlite::Connection;
use serde::Deserialize;
use serde_json::Value;
use sha2::{Digest, Sha256};
use zeroize::{Zeroize, Zeroizing};

use crate::migrate::sqlcipher;

use super::cli::ImportArgs;

/// The snapshot manifest file (F5 writes it, `run` requires it):
/// proof that `--from-snapshot` is a cold, byte-verified copy.
pub const SNAPSHOT_MANIFEST: &str = "snapshot-manifest.json";

/// sha256 of `bytes`, first 12 hex chars — the only key fingerprint
/// ever printed (brief: "only its length and sha256-12").
fn sha12(bytes: &[u8]) -> String {
    let d = Sha256::digest(bytes);
    d.iter().take(6).map(|b| format!("{b:02x}")).collect()
}

// --- F2: the D7 key capture ----------------------------------------------

/// The validated shape of a D7 plaintext (audit M2-2). `date` and any
/// other fields are informational and ignored; the three fields below
/// are load-bearing and cross-checked.
#[derive(Deserialize)]
struct D7Plain {
    value: String,
    value_len: u64,
    target_sha12: String,
}

/// Validate a D7 plaintext (pure, unit-tested): must be JSON with a
/// string `value` (the passphrase), `value_len == value.len()` and
/// `target_sha12 == sha256-12(value)`. The passphrase is returned
/// zeroized-on-drop and is never printed or logged.
pub fn parse_d7_plaintext(json: &[u8]) -> Result<Zeroizing<String>, String> {
    let mut d7: D7Plain = serde_json::from_slice(json)
        .map_err(|e| format!("d7 plaintext is not the D7 JSON capture: {e}"))?;
    if d7.value_len != d7.value.len() as u64 {
        let msg = format!(
            "d7 plaintext: value_len says {} but the passphrase has {} chars",
            d7.value_len,
            d7.value.len()
        );
        d7.value.zeroize();
        return Err(msg);
    }
    let got = sha12(d7.value.as_bytes());
    if !d7.target_sha12.eq_ignore_ascii_case(&got) {
        let msg = format!(
            "d7 plaintext: target_sha12 is {} but the passphrase hashes to {got}",
            d7.target_sha12
        );
        d7.value.zeroize();
        return Err(msg);
    }
    Ok(Zeroizing::new(std::mem::take(&mut d7.value)))
}

/// Load the D7 capture file (audit M2-1/M2-2): a DPAPI blob wrapped
/// with NO entropy (the capture script's `"zalors.d7"` was
/// `szDataDescr`, not entropy), unwrapping to the JSON plaintext
/// above. The DPPI plaintext buffer — the JSON — is wiped right after
/// parsing; the passphrase lives on inside the returned `Zeroizing`.
pub fn load_d7_key(path: &Path) -> Result<Zeroizing<String>, String> {
    let blob = std::fs::read(path).map_err(|e| format!("--key-file {path:?}: {e}"))?;
    let mut plain = sqlcipher::unwrap_no_entropy(&blob)
        .map_err(|e| format!("--key-file {path:?}: DPAPI unwrap failed ({e})"))?;
    let pass = parse_d7_plaintext(&plain);
    // Wipe the JSON buffer now that it is parsed (batch-4 rule: key
    // material never lingers in freed heap until reuse).
    plain.zeroize();
    pass
}

// --- F3: profiles + the immutable snapshot open -------------------------

/// The SQLCipher parameter profile of a Desktop DB (audit M2-3: the
/// exact cipher parameters are unknown until tried; 2.2 detects them).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CipherProfile {
    /// SQLCipher 4 defaults — `PRAGMA cipher_compatibility = 4`.
    Compat4,
    /// SQLCipher 3 defaults (kdf_iter 64000, page 1024, …) —
    /// `PRAGMA cipher_compatibility = 3`.
    Compat3,
}

impl CipherProfile {
    /// The `cipher_compatibility` value to set.
    pub fn compatibility(self) -> u32 {
        match self {
            CipherProfile::Compat4 => 4,
            CipherProfile::Compat3 => 3,
        }
    }

    /// Stable name for the one output line (F4).
    pub fn name(self) -> &'static str {
        match self {
            CipherProfile::Compat4 => "compat4",
            CipherProfile::Compat3 => "compat3",
        }
    }

    /// Detection order (F3): try 4, then 3.
    pub const TRY_ORDER: [CipherProfile; 2] = [CipherProfile::Compat4, CipherProfile::Compat3];
}

/// `file:` URI for `path` with `mode=ro&immutable=1` (KQ4/M2-6): forward
/// slashes, percent-encoded where the URI grammar requires it. With
/// `immutable=1` SQLite performs no locking and never creates or
/// opens `-wal`/`-shm`/`-journal`.
fn immutable_ro_uri(path: &Path) -> Result<String, String> {
    let raw = path
        .as_os_str()
        .to_str()
        .ok_or_else(|| format!("{}: non-UTF-8 path", path.display()))?;
    let mut uri = String::from("file:///");
    for b in raw.bytes() {
        match b {
            b'\\' => uri.push('/'),
            b'%' => uri.push_str("%25"),
            b'?' => uri.push_str("%3F"),
            b'#' => uri.push_str("%23"),
            b' ' => uri.push_str("%20"),
            _ => uri.push(b as char),
        }
    }
    uri.push_str("?mode=ro&immutable=1");
    Ok(uri)
}

/// String-form key pragma (M2-3): `PRAGMA key = '<pass>'` routes the
/// passphrase through SQLCipher's KDF — the Desktop DBs are keyed as
/// passphrases, never as raw `x'hex'` blobs. The assembled statement
/// and the escaped passphrase copy are zeroized (batch-4 rule).
fn apply_passphrase_key(conn: &Connection, passphrase: &str) -> Result<(), String> {
    let mut escaped = Zeroizing::new(passphrase.replace('\'', "''"));
    let stmt = Zeroizing::new(format!("PRAGMA key = '{}';", escaped.as_str()));
    escaped.zeroize();
    conn.execute_batch(stmt.as_str())
        .map_err(|e| format!("pragma key failed: {e}"))
}

/// Open a SNAPSHOT Desktop DB read-only + immutable (M2-3/M2-6/KQ4):
/// the URI open, the string-form key, the profile's
/// `cipher_compatibility`, then a verify read. No busy/journal
/// pragmas — nothing here may create or touch sidecar files.
pub fn open_desktop_db(
    path: &Path,
    passphrase: &str,
    profile: CipherProfile,
) -> Result<Connection, String> {
    let uri = immutable_ro_uri(path)?;
    let conn = Connection::open_with_flags(
        uri,
        rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY | rusqlite::OpenFlags::SQLITE_OPEN_URI,
    )
    .map_err(|e| format!("{}: open failed: {e}", path.display()))?;
    apply_passphrase_key(&conn, passphrase)?;
    conn.execute_batch(&format!(
        "PRAGMA cipher_compatibility = {};",
        profile.compatibility()
    ))
    .map_err(|e| {
        format!(
            "{}: cipher_compatibility={} rejected: {e}",
            path.display(),
            profile.compatibility()
        )
    })?;
    // A wrong key only surfaces on the first page read; force one now.
    conn.query_row("SELECT count(*) FROM sqlite_master", [], |_| Ok(()))
        .map_err(|e| format!("{}: key/profile verify failed ({e})", path.display()))?;
    Ok(conn)
}

/// Detect the profile of `path` with `pass` (2.2): try compat 4, then
/// 3 — the first profile whose verify read succeeds wins. Returns the
/// profile, never the key.
pub fn try_profiles(path: &Path, pass: &str) -> Result<CipherProfile, String> {
    let mut last_err = String::new();
    for &profile in CipherProfile::TRY_ORDER.iter() {
        match open_desktop_db(path, pass, profile) {
            Ok(_) => return Ok(profile),
            Err(e) => last_err = e,
        }
    }
    Err(format!(
        "{}: no cipher profile opened the DB (tried cipher_compatibility 4 then 3; \
         wrong key, or not a standard-SQLCipher file); last error: {last_err}",
        path.display()
    ))
}

// --- F3: the snapshot guard ----------------------------------------------

/// Refuse anything whose path points at (or into) the live Desktop
/// data tree (KQ4 belt-and-braces: import reads only cold snapshots).
fn refuse_zalo_data_path(from: &Path) -> Result<(), String> {
    for comp in from.components() {
        let Some(name) = comp.as_os_str().to_str() else {
            continue;
        };
        if name.eq_ignore_ascii_case("Zalo Data") {
            return Err(format!(
                "--from-snapshot must point at a cold snapshot, never the live \
                 Desktop tree (path component 'Zalo Data' found in {from:?})"
            ));
        }
    }
    Ok(())
}

/// Validate `<from>/snapshot-manifest.json` — the F5 output shape:
/// `{ "created": <epoch ms>, "source_root_sha12": "<12 hex>",
///    "files": [ { "rel": …, "size": …, "mtime": <epoch ms> } … ] }`.
/// Strict on required fields, lenient on extras; a UTF-8 BOM is
/// tolerated (the jsonfile convention).
fn validate_snapshot_manifest(from: &Path) -> Result<(), String> {
    let manifest = from.join(SNAPSHOT_MANIFEST);
    if !manifest.is_file() {
        return Err(format!(
            "missing {manifest:?}: --from-snapshot must be a cold snapshot made by \
             tools/snapshot.ps1 (KQ4: the live Desktop dir is never read)"
        ));
    }
    let raw = std::fs::read_to_string(&manifest)
        .map_err(|e| format!("cannot read {manifest:?}: {e}"))?;
    let raw = raw.trim_start_matches('\u{feff}');
    let v: Value = serde_json::from_str(raw)
        .map_err(|e| format!("{manifest:?} is not valid JSON: {e}"))?;
    let obj = v
        .as_object()
        .ok_or_else(|| format!("{manifest:?}: top level must be a JSON object"))?;
    obj.get("created")
        .and_then(Value::as_i64)
        .ok_or_else(|| format!("{manifest:?}: missing field 'created' (epoch ms)"))?;
    let sha = obj
        .get("source_root_sha12")
        .and_then(Value::as_str)
        .ok_or_else(|| format!("{manifest:?}: missing field 'source_root_sha12'"))?;
    if sha.len() != 12 || !sha.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Err(format!(
            "{manifest:?}: 'source_root_sha12' must be 12 hex chars"
        ));
    }
    let files = obj
        .get("files")
        .and_then(Value::as_array)
        .ok_or_else(|| format!("{manifest:?}: missing field 'files' (array)"))?;
    for (i, f) in files.iter().enumerate() {
        let f = f
            .as_object()
            .ok_or_else(|| format!("{manifest:?}: files[{i}] must be an object"))?;
        let rel = f
            .get("rel")
            .and_then(Value::as_str)
            .filter(|s| !s.is_empty())
            .ok_or_else(|| format!("{manifest:?}: files[{i}].rel must be a non-empty string"))?;
        if Path::new(rel).is_absolute() {
            return Err(format!("{manifest:?}: files[{i}].rel must be relative"));
        }
        f.get("size")
            .and_then(Value::as_u64)
            .ok_or_else(|| format!("{manifest:?}: files[{i}].size must be a non-negative integer"))?;
        f.get("mtime")
            .and_then(Value::as_i64)
            .ok_or_else(|| format!("{manifest:?}: files[{i}].mtime must be an integer (epoch ms)"))?;
    }
    Ok(())
}

/// The snapshot guard (KQ4): refuse the live Desktop tree, then refuse
/// a directory without a valid `snapshot-manifest.json`. Error messages
/// name exactly what is missing.
pub fn validate_snapshot(from: &Path) -> Result<(), String> {
    refuse_zalo_data_path(from)?;
    validate_snapshot_manifest(from)
}

// --- F4: message DB enumeration ------------------------------------------

/// One `Core\Message\*.db` (M2-4: the old skeleton only matched `g*`
/// and silently dropped 65% of the message DBs).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DbKind {
    /// `<digits>.db` — a 1-1 conversation message DB, id = the digits.
    OneToOne(u64),
    /// `g<digits>.db` — a group conversation message DB, id = the digits.
    Group(u64),
    /// `stranger_box.db`.
    StrangerBox,
    /// `undefined.db` — counted and skipped, never imported.
    Undefined,
    /// Anything else — counted.
    Other,
}

/// Classify a `Core\Message` file name into its DB kind. Pure; case is
/// significant (Desktop names are lower-case `g<id>.db`; `G1.db` is
/// `Other`). Non-`.db` names (e.g. `123.db-wal`) are `Other`.
pub fn classify_message_db(file_name: &str) -> DbKind {
    let Some(stem) = file_name.strip_suffix(".db") else {
        return DbKind::Other;
    };
    if stem == "stranger_box" {
        return DbKind::StrangerBox;
    }
    if stem == "undefined" {
        return DbKind::Undefined;
    }
    let (is_group, digits) = match stem.strip_prefix('g') {
        Some(d) => (true, d),
        None => (false, stem),
    };
    if digits.is_empty() || !digits.bytes().all(|b| b.is_ascii_digit()) {
        return DbKind::Other;
    }
    let Ok(id) = digits.parse::<u64>() else {
        return DbKind::Other;
    };
    if is_group {
        DbKind::Group(id)
    } else {
        DbKind::OneToOne(id)
    }
}

/// Dry-run inventory of a snapshot (F4). The `line()` form is printed
/// verbatim by the CLI: counts, profile name, key sha12 — nothing else.
#[derive(Debug, Default, Clone, PartialEq)]
pub struct Summary {
    /// `Core\Message\*.db` classified as `<digits>.db`.
    pub one_to_one: usize,
    /// … classified as `g<digits>.db`.
    pub group: usize,
    /// … `stranger_box.db`.
    pub stranger_box: usize,
    /// … `undefined.db` (skipped with this counted log line).
    pub undefined: usize,
    /// … anything else.
    pub other: usize,
    /// Index.db table count — the one real count Index.db offers
    /// (`sqlite_master WHERE type='table'`), not the old fake
    /// `LIKE '%conv%'` name matching.
    pub index_tables: usize,
    /// The cipher profile that verified against Index.db.
    pub profile: Option<CipherProfile>,
    /// sha256-12 of the D7 passphrase — the only key info ever printed.
    pub key_sha12: String,
}

impl Summary {
    /// The one output line of a dry run (F4).
    pub fn line(&self) -> String {
        format!(
            "one_to_one={} group={} stranger_box={} undefined={} other={} \
             index_tables={} profile={} key_sha12={}",
            self.one_to_one,
            self.group,
            self.stranger_box,
            self.undefined,
            self.other,
            self.index_tables,
            self.profile.map(CipherProfile::name).unwrap_or("undetected"),
            self.key_sha12
        )
    }
}

/// The account dir inside the snapshot: a snapshot of the Desktop uid
/// dir (audit 2.1) has `Core\` at its root; a snapshot of the whole
/// `_production` tree keeps the uid child dirs.
fn resolve_uid_dir(from: &Path, account: &str) -> Option<PathBuf> {
    if from.join("Core").is_dir() {
        return Some(from.to_path_buf());
    }
    let direct = from.join(account);
    if direct.is_dir() {
        return Some(direct);
    }
    for entry in std::fs::read_dir(from).ok()?.flatten() {
        let name = entry.file_name().to_string_lossy().into_owned();
        if !name.is_empty() && name.bytes().all(|b| b.is_ascii_digit()) {
            return Some(entry.path());
        }
    }
    None
}

/// Index.db table count (F4).
fn table_count(conn: &Connection) -> usize {
    conn.query_row(
        "SELECT count(*) FROM sqlite_master WHERE type='table'",
        [],
        |r| r.get::<_, i64>(0),
    )
    .map(|n| n as usize)
    .unwrap_or(0)
}

/// Dry-run inventory of a cold snapshot (F3/F4). `--apply` stays
/// fail-closed (P2 item 2.5 wires the writer later).
pub fn run(a: &ImportArgs) -> Result<Summary, String> {
    // KQ4: nothing runs until the snapshot guard passes.
    validate_snapshot(&a.from_snapshot)?;

    let uid_dir = resolve_uid_dir(&a.from_snapshot, &a.account).ok_or_else(|| {
        format!("no account directory under --from-snapshot {:?}", a.from_snapshot)
    })?;

    // F2: the key arrives only via the D7 file, unwrapped in RAM,
    // verified against --uin-hash, zeroized on drop.
    let key_path = a
        .key_file
        .as_deref()
        .ok_or("missing --key-file (D7 capture): the Desktop key is never passed as text")?;
    let passphrase = load_d7_key(key_path)?;
    let key_sha12 = sha12(passphrase.as_bytes());
    if key_sha12 != a.uin_hash {
        return Err(format!(
            "key/uin-hash mismatch: --key-file hashes to {key_sha12}, --uin-hash says {}",
            a.uin_hash
        ));
    }

    let index = uid_dir.join("Core").join("Index.db");
    if !index.is_file() {
        return Err(format!("missing {} — broken snapshot?", index.display()));
    }

    // F3/2.2: detect (or verify the forced) cipher profile against
    // Index.db, then take the one real count it offers.
    let (profile, index_tables) = match a.cipher_compat {
        Some(p) => {
            let conn = open_desktop_db(&index, &passphrase, p)?;
            (p, table_count(&conn))
        }
        None => {
            let p = try_profiles(&index, &passphrase)?;
            let conn = open_desktop_db(&index, &passphrase, p)?;
            (p, table_count(&conn))
        }
    };

    let mut s = Summary {
        index_tables,
        profile: Some(profile),
        key_sha12,
        ..Summary::default()
    };

    // F4/M2-4: classify every Core\Message\*.db; `undefined.db` is
    // counted and skipped; `-wal`/`-shm` sidecars are not DBs.
    let msg_dir = uid_dir.join("Core").join("Message");
    if !msg_dir.is_dir() {
        return Err(format!("missing {} — broken snapshot?", msg_dir.display()));
    }
    for entry in std::fs::read_dir(&msg_dir)
        .map_err(|e| format!("{}: {e}", msg_dir.display()))?
        .flatten()
    {
        let name = entry.file_name().to_string_lossy().into_owned();
        if !name.ends_with(".db") {
            continue;
        }
        match classify_message_db(&name) {
            DbKind::OneToOne(_) => s.one_to_one += 1,
            DbKind::Group(_) => s.group += 1,
            DbKind::StrangerBox => s.stranger_box += 1,
            DbKind::Undefined => s.undefined += 1, // counted, skipped
            DbKind::Other => s.other += 1,
        }
    }

    if a.apply {
        return Err("--apply not wired in this rebuild phase yet (dry-run only, fail-closed)".into());
    }
    Ok(s)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::migrate::sqlcipher;
    use serde_json::json;

    static SEQ: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);

    /// A fresh unique temp dir (synthetic fixtures only — never the
    /// live Desktop tree, never the live shadow DB).
    fn temp_dir(tag: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "zr-import-{tag}-{}-{}-{}",
            std::process::id(),
            super::super::schema::now_ms(),
            SEQ.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
        ));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    /// Sorted file names in `dir` (sidecar-proof asserts).
    fn listing(dir: &Path) -> Vec<String> {
        let mut names: Vec<String> = std::fs::read_dir(dir)
            .unwrap()
            .flatten()
            .map(|e| e.file_name().to_string_lossy().into_owned())
            .collect();
        names.sort();
        names
    }

    /// A fake Desktop-style SQLCipher DB keyed by a PASSPHRASE
    /// (string pragma → KDF, M2-3) with the given profile. `compat`
    /// None = the build's own defaults (SQLCipher 4).
    fn make_cipher_db(path: &Path, pass: &str, compat: Option<u32>) {
        let conn = Connection::open_with_flags(
            path,
            rusqlite::OpenFlags::SQLITE_OPEN_READ_WRITE
                | rusqlite::OpenFlags::SQLITE_OPEN_CREATE,
        )
        .unwrap();
        apply_passphrase_key(&conn, pass).unwrap();
        if let Some(c) = compat {
            conn.execute_batch(&format!("PRAGMA cipher_compatibility = {c};"))
                .unwrap();
        }
        conn.execute_batch(
            "CREATE TABLE conv (id INTEGER PRIMARY KEY, v TEXT);
             INSERT INTO conv (v) VALUES ('one');
             INSERT INTO conv (v) VALUES ('two');",
        )
        .unwrap();
        conn.close().map_err(|(_, e)| e).unwrap();
    }

    /// Same, but journal_mode=WAL, closed cleanly: the sidecars are
    /// gone yet the header stays WAL — the exact state of a snapshot
    /// copy after the (later, in Rust) checkpoint step.
    fn make_cipher_db_wal(path: &Path, pass: &str) {
        let conn = Connection::open_with_flags(
            path,
            rusqlite::OpenFlags::SQLITE_OPEN_READ_WRITE
                | rusqlite::OpenFlags::SQLITE_OPEN_CREATE,
        )
        .unwrap();
        apply_passphrase_key(&conn, pass).unwrap();
        conn.execute_batch("PRAGMA journal_mode = WAL;").unwrap();
        conn.execute_batch(
            "CREATE TABLE conv (id INTEGER PRIMARY KEY, v TEXT);
             INSERT INTO conv (v) VALUES ('w');",
        )
        .unwrap();
        conn.close().map_err(|(_, e)| e).unwrap();
    }

    fn write_manifest_json(dir: &Path, json: String) {
        std::fs::write(dir.join(SNAPSHOT_MANIFEST), json).unwrap();
    }

    fn valid_manifest_json() -> String {
        json!({
            "created": 1763600000000i64,
            "source_root_sha12": "aaaaaaaaaaaa",
            "files": [
                { "rel": "Core\\Index.db", "size": 4096u64, "mtime": 1700000000000i64 }
            ]
        })
        .to_string()
    }

    /// A FAKE D7 key file: the same JSON shape as the real capture
    /// (M2-2) with a synthetic 32-char passphrase, DPAPI-wrapped with
    /// NO entropy via `save_key` (the D7 wrap form, M2-1).
    #[cfg(windows)]
    fn fake_d7_key_file(path: &Path, pass: &str) {
        let payload = json!({
            "date": "2026-11-20T00:00:00Z",
            "target_sha12": sha12(pass.as_bytes()),
            "value_len": pass.len() as u64,
            "value": pass,
        });
        sqlcipher::save_key(payload.to_string().as_bytes(), path).unwrap();
    }

    /// A full synthetic snapshot (Windows: with a D7 key file).
    /// Returns the key file path.
    #[cfg(windows)]
    fn synthetic_snapshot(dir: &Path, pass: &str, compat: Option<u32>) -> PathBuf {
        write_manifest_json(dir, valid_manifest_json());
        let core = dir.join("Core");
        std::fs::create_dir_all(core.join("Message")).unwrap();
        make_cipher_db(&core.join("Index.db"), pass, compat);
        for name in ["123.db", "g456.db", "stranger_box.db", "undefined.db", "weird.db"] {
            std::fs::write(core.join("Message").join(name), b"fake").unwrap();
        }
        let key = dir.join("d7.bin");
        fake_d7_key_file(&key, pass);
        key
    }

    fn args_for(from: &Path, uin_hash: &str, key: Option<&Path>) -> ImportArgs {
        ImportArgs {
            from_snapshot: from.to_path_buf(),
            account: "default".into(),
            uin_hash: uin_hash.into(),
            key_file: key.map(|p| p.to_path_buf()),
            cipher_compat: None,
            apply: false,
            help: false,
        }
    }

    // --- F2 ----------------------------------------------------------------

    #[test]
    fn parse_d7_plaintext_accepts_the_capture_shape() {
        // The audit's measured shape, with a FAKE 32-char value.
        let pass = "fakefakefakefakefakefakefake1234";
        let json = json!({
            "date": 1763600000000i64,
            "target_sha12": sha12(pass.as_bytes()),
            "value_len": pass.len() as u64,
            "value": pass,
        });
        let got = parse_d7_plaintext(json.to_string().as_bytes()).unwrap();
        assert_eq!(got.as_str(), pass);
        // Extra/missing informational fields don't matter.
        let minimal = json!({
            "target_sha12": sha12(pass.as_bytes()),
            "value_len": pass.len() as u64,
            "value": pass,
        });
        assert_eq!(
            parse_d7_plaintext(minimal.to_string().as_bytes()).unwrap().as_str(),
            pass
        );
    }

    #[test]
    fn parse_d7_plaintext_rejects_value_len_mismatch() {
        let pass = "fakefakefakefakefakefakefake1234";
        let json = json!({
            "target_sha12": sha12(pass.as_bytes()),
            "value_len": 31u64,
            "value": pass,
        });
        let e = parse_d7_plaintext(json.to_string().as_bytes()).unwrap_err();
        assert!(e.contains("value_len says 31"), "{e}");
    }

    #[test]
    fn parse_d7_plaintext_rejects_target_sha_mismatch() {
        let json = json!({
            "target_sha12": "000000000000",
            "value_len": 32u64,
            "value": "fakefakefakefakefakefakefake1234",
        });
        let e = parse_d7_plaintext(json.to_string().as_bytes()).unwrap_err();
        assert!(e.contains("target_sha12 is 000000000000"), "{e}");
        assert!(!e.contains("fakefake"), "never echo the passphrase: {e}");
    }

    #[test]
    fn parse_d7_plaintext_rejects_missing_or_mistyped_value() {
        for bad in [
            json!({ "value_len": 32u64, "target_sha12": "aaaaaaaaaaaa" }).to_string(),
            json!({ "value": 32u64, "value_len": 32u64, "target_sha12": "aaaaaaaaaaaa" })
                .to_string(),
            json!({ "value": "x", "target_sha12": "aaaaaaaaaaaa" }).to_string(),
            json!({ "value": "x", "value_len": "1", "target_sha12": "aaaaaaaaaaaa" }).to_string(),
            String::from("this is not json"),
            String::from("[1,2,3]"),
        ] {
            assert!(
                parse_d7_plaintext(bad.as_bytes()).is_err(),
                "must reject {bad}"
            );
        }
    }

    #[test]
    fn load_d7_key_missing_file_is_an_error() {
        let dir = temp_dir("d7miss");
        let e = load_d7_key(&dir.join("nope.bin")).unwrap_err();
        assert!(e.contains("--key-file") && e.contains("nope.bin"), "{e}");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    #[cfg(windows)]
    fn load_d7_key_round_trips_a_fake_dpapi_capture() {
        // Synthetic secret only: the test wraps a FAKE payload with
        // CryptProtectData (no entropy) on this machine and unwraps it
        // through the exact D7 path.
        let dir = temp_dir("d7rt");
        let pass = "fakefakefakefakefakefakefake1234";
        let key = dir.join("d7.bin");
        fake_d7_key_file(&key, pass);
        let got = load_d7_key(&key).unwrap();
        assert_eq!(got.as_str(), pass);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    #[cfg(windows)]
    fn load_d7_key_rejects_a_garbage_blob() {
        let dir = temp_dir("d7bad");
        let key = dir.join("d7.bin");
        std::fs::write(&key, b"definitely not a dpapi blob").unwrap();
        let e = load_d7_key(&key).unwrap_err();
        assert!(e.contains("DPAPI unwrap failed"), "{e}");
        let _ = std::fs::remove_dir_all(&dir);
    }

    // --- F3: profiles + immutable open ------------------------------------

    #[test]
    fn try_profiles_detects_compat4() {
        let dir = temp_dir("p4");
        let db = dir.join("Index.db");
        make_cipher_db(&db, "fakefakefakefakefakefakefake1234", None);
        assert_eq!(
            try_profiles(&db, "fakefakefakefakefakefakefake1234").unwrap(),
            CipherProfile::Compat4
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn try_profiles_detects_compat3() {
        let dir = temp_dir("p3");
        let db = dir.join("Index.db");
        make_cipher_db(&db, "fakefakefakefakefakefakefake1234", Some(3));
        assert_eq!(
            try_profiles(&db, "fakefakefakefakefakefakefake1234").unwrap(),
            CipherProfile::Compat3
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn try_profiles_wrong_passphrase_fails() {
        let dir = temp_dir("pwrong");
        let db = dir.join("Index.db");
        make_cipher_db(&db, "fakefakefakefakefakefakefake1234", None);
        let e = try_profiles(&db, "fakefakefakefakefakefakefake5678").unwrap_err();
        assert!(e.contains("no cipher profile opened the DB"), "{e}");
        assert!(!e.contains("fakefake"), "never echo the passphrase: {e}");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn open_desktop_db_wrong_profile_fails() {
        // A compat-4 DB forced open as compat-3 must not verify.
        let dir = temp_dir("pmix");
        let db = dir.join("Index.db");
        make_cipher_db(&db, "fakefakefakefakefakefakefake1234", None);
        let e = open_desktop_db(&db, "fakefakefakefakefakefakefake1234", CipherProfile::Compat3)
            .unwrap_err();
        assert!(e.contains("verify failed"), "{e}");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn open_desktop_db_reads_data_immutable() {
        let dir = temp_dir("pread");
        let db = dir.join("Index.db");
        let pass = "fakefakefakefakefakefakefake1234";
        make_cipher_db(&db, pass, None);
        let conn = open_desktop_db(&db, pass, CipherProfile::Compat4).unwrap();
        let n: i64 = conn
            .query_row("SELECT count(*) FROM conv", [], |r| r.get(0))
            .unwrap();
        assert_eq!(n, 2, "the data written before the snapshot is readable");
        let tables: i64 = conn
            .query_row(
                "SELECT count(*) FROM sqlite_master WHERE type='table'",
                [],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(tables, 1);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn immutable_open_leaves_no_sidecar_files() {
        // M2-6 immutable proof: after a full open+read+close the dir
        // contains NO new -wal/-shm/-journal files.
        let dir = temp_dir("imm");
        let db = dir.join("Index.db");
        let pass = "fakefakefakefakefakefakefake1234";
        make_cipher_db(&db, pass, None);
        let before = listing(&dir);
        assert_eq!(before, vec!["Index.db".to_string()]);
        let conn = open_desktop_db(&db, pass, CipherProfile::Compat4).unwrap();
        let _: i64 = conn
            .query_row("SELECT count(*) FROM sqlite_master", [], |r| r.get(0))
            .unwrap();
        drop(conn);
        let after = listing(&dir);
        assert_eq!(after, before, "immutable=1 must create nothing");
        for suffix in ["-wal", "-shm", "-journal"] {
            assert!(
                !db.with_file_name(format!("Index.db{suffix}")).exists(),
                "no {suffix} may appear"
            );
        }
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn immutable_open_on_a_wal_header_db_leaves_no_sidecars() {
        // The real Desktop DBs are WAL; after the snapshot's (later,
        // in-Rust) checkpoint the copy's header still says WAL. Prove
        // the immutable open handles that state without creating -shm.
        let dir = temp_dir("immwal");
        let db = dir.join("Index.db");
        let pass = "fakefakefakefakefakefakefake1234";
        make_cipher_db_wal(&db, pass);
        let before = listing(&dir);
        assert_eq!(before, vec!["Index.db".to_string()], "clean close removed sidecars");
        let conn = open_desktop_db(&db, pass, CipherProfile::Compat4).unwrap();
        let n: i64 = conn
            .query_row("SELECT count(*) FROM conv", [], |r| r.get(0))
            .unwrap();
        assert_eq!(n, 1, "WAL-header DB is readable through immutable=1");
        drop(conn);
        let after = listing(&dir);
        assert_eq!(after, before, "immutable=1 must not create -wal/-shm/-journal");
        let _ = std::fs::remove_dir_all(&dir);
    }

    // --- F3: the snapshot guard ---------------------------------------------

    #[test]
    fn validate_snapshot_requires_the_manifest() {
        let dir = temp_dir("guard");
        let e = validate_snapshot(&dir).unwrap_err();
        assert!(e.contains("snapshot-manifest.json"), "{e}");
        assert!(e.contains("missing"), "{e}");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn validate_snapshot_rejects_invalid_json() {
        let dir = temp_dir("guardjson");
        write_manifest_json(&dir, String::from("this is not json"));
        let e = validate_snapshot(&dir).unwrap_err();
        assert!(e.contains("not valid JSON"), "{e}");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn validate_snapshot_rejects_wrong_shapes() {
        let cases: Vec<(String, &str)> = vec![
            (
                json!({ "source_root_sha12": "aaaaaaaaaaaa", "files": [] }).to_string(),
                "'created'",
            ),
            (
                json!({ "created": 1i64, "source_root_sha12": "aaaaaaaaaaa", "files": [] })
                    .to_string(),
                "'source_root_sha12'",
            ),
            (
                json!({ "created": 1i64, "source_root_sha12": "aaaaaaaaaaaa" }).to_string(),
                "'files'",
            ),
            (
                json!({ "created": 1i64, "source_root_sha12": "aaaaaaaaaaaa", "files": {} })
                    .to_string(),
                "'files'",
            ),
            (
                json!({ "created": 1i64, "source_root_sha12": "aaaaaaaaaaaa",
                        "files": [ { "rel": "x.db" } ] }).to_string(),
                ".size",
            ),
            (
                json!({ "created": 1i64, "source_root_sha12": "aaaaaaaaaaaa",
                        "files": [ { "rel": "C:\\x.db", "size": 1u64, "mtime": 2i64 } ] })
                    .to_string(),
                "relative",
            ),
        ];
        for (bad, needle) in cases {
            let dir = temp_dir("guardshape");
            write_manifest_json(&dir, bad);
            let e = validate_snapshot(&dir).unwrap_err();
            assert!(e.contains(needle), "expected {needle:?} in {e}");
            let _ = std::fs::remove_dir_all(&dir);
        }
    }

    #[test]
    fn validate_snapshot_accepts_a_valid_manifest() {
        let dir = temp_dir("guardok");
        write_manifest_json(&dir, valid_manifest_json());
        validate_snapshot(&dir).unwrap();
        // A UTF-8 BOM is tolerated (the jsonfile convention).
        std::fs::write(
            dir.join(SNAPSHOT_MANIFEST),
            format!("\u{feff}{}", valid_manifest_json()),
        )
        .unwrap();
        validate_snapshot(&dir).unwrap();
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn validate_snapshot_refuses_zalo_data_paths() {
        // Belt-and-braces (KQ4): the live Desktop dir is refused by
        // name, whatever the case, before anything is read.
        for bad in [
            r"D:\Zalo Data\snapshot",
            r"D:\zalo data\snapshot",
            r"E:\sub\ZALO DATA\x",
        ] {
            let e = validate_snapshot(Path::new(bad)).unwrap_err();
            assert!(e.contains("Zalo Data"), "{bad} -> {e}");
        }
        // An exact component matters: "ZaloData" is NOT the live tree;
        // the guard then falls through to the manifest check.
        let e = validate_snapshot(Path::new(r"D:\ZaloData\x")).unwrap_err();
        assert!(e.contains("snapshot-manifest.json"), "{e}");
        // The Zalo-Data refusal fires before the manifest check.
        let e = validate_snapshot(Path::new(r"D:\Zalo Data\does-not-exist")).unwrap_err();
        assert!(e.contains("Zalo Data"), "{e}");
    }

    #[test]
    fn run_refuses_a_dir_without_a_manifest() {
        let dir = temp_dir("runguard");
        let e = run(&args_for(&dir, "dca62c394a68", None)).unwrap_err();
        assert!(e.contains("snapshot-manifest.json"), "{e}");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn run_fails_closed_without_a_key_file() {
        let dir = temp_dir("runnokey");
        std::fs::create_dir_all(dir.join("Core")).unwrap();
        write_manifest_json(&dir, valid_manifest_json());
        let e = run(&args_for(&dir, "dca62c394a68", None)).unwrap_err();
        assert!(e.contains("missing --key-file"), "{e}");
        let _ = std::fs::remove_dir_all(&dir);
    }

    // --- F4 ----------------------------------------------------------------

    #[test]
    fn classify_message_db_shapes() {
        use DbKind::*;
        assert_eq!(classify_message_db("123456789.db"), OneToOne(123456789));
        assert_eq!(classify_message_db("0.db"), OneToOne(0));
        assert_eq!(classify_message_db("g456.db"), Group(456));
        assert_eq!(classify_message_db("stranger_box.db"), StrangerBox);
        assert_eq!(classify_message_db("undefined.db"), Undefined);
        for other in [
            "g.db", "123x.db", "G1.db", "x123.db", "backup.db", "123.db-wal",
            "123.db-shm", "123.db-journal", ".db", "",
        ] {
            assert_eq!(classify_message_db(other), Other, "{other}");
        }
    }

    // --- the full dry run (Windows: DPAPI parts) ---------------------------

    #[test]
    #[cfg(windows)]
    fn run_dry_run_inventories_a_synthetic_snapshot() {
        let dir = temp_dir("run");
        let pass = "fakefakefakefakefakefakefake1234";
        let key = synthetic_snapshot(&dir, pass, None);
        let uin = sha12(pass.as_bytes());
        let s = run(&args_for(&dir, &uin, Some(&key))).unwrap();
        assert_eq!(s.profile, Some(CipherProfile::Compat4));
        assert_eq!(s.key_sha12, uin);
        assert_eq!(s.index_tables, 1);
        assert_eq!(s.one_to_one, 1);
        assert_eq!(s.group, 1);
        assert_eq!(s.stranger_box, 1);
        assert_eq!(s.undefined, 1);
        assert_eq!(s.other, 1);
        // The output line carries counts, profile, key sha12 — only.
        let line = s.line();
        assert!(line.contains("profile=compat4"), "{line}");
        assert!(line.contains(&format!("key_sha12={uin}")), "{line}");
        assert!(!line.contains(pass), "never the passphrase");
        // Immutable proof: the only entries under Core\ are the fixture
        // DB and the Message dir — no sidecars were created.
        assert_eq!(
            listing(&dir.join("Core")),
            vec!["Index.db".to_string(), "Message".to_string()]
        );
        for suffix in ["-wal", "-shm", "-journal"] {
            assert!(
                !dir.join("Core").join(format!("Index.db{suffix}")).exists(),
                "no {suffix} may appear"
            );
        }
        // The CLI exit-code path on the same fixture: success → 0.
        let argv = vec![
            "--from-snapshot".to_string(),
            dir.to_string_lossy().into_owned(),
            "--account".to_string(),
            "default".to_string(),
            "--uin-hash".to_string(),
            uin,
            "--key-file".to_string(),
            key.to_string_lossy().into_owned(),
        ];
        assert_eq!(crate::shadow::cli::main(&argv), 0);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    #[cfg(windows)]
    fn run_rejects_a_key_that_hashes_wrong() {
        let dir = temp_dir("runhash");
        let pass = "fakefakefakefakefakefakefake1234";
        let key = synthetic_snapshot(&dir, pass, None);
        let wrong_uin = sha12("fakefakefakefakefakefakefake5678".as_bytes());
        let e = run(&args_for(&dir, &wrong_uin, Some(&key))).unwrap_err();
        assert!(e.contains("key/uin-hash mismatch"), "{e}");
        assert!(!e.contains(pass), "never the passphrase: {e}");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    #[cfg(windows)]
    fn run_forced_cipher_compat_must_match_the_db() {
        let dir = temp_dir("runcompat");
        let pass = "fakefakefakefakefakefakefake1234";
        let key = synthetic_snapshot(&dir, pass, Some(3));
        let mut a = args_for(&dir, &sha12(pass.as_bytes()), Some(&key));
        a.cipher_compat = Some(CipherProfile::Compat4); // wrong on purpose
        let e = run(&a).unwrap_err();
        assert!(e.contains("verify failed"), "{e}");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    #[cfg(windows)]
    fn run_apply_stays_fail_closed() {
        let dir = temp_dir("runapply");
        let pass = "fakefakefakefakefakefakefake1234";
        let key = synthetic_snapshot(&dir, pass, None);
        let mut a = args_for(&dir, &sha12(pass.as_bytes()), Some(&key));
        a.apply = true;
        let e = run(&a).unwrap_err();
        assert!(e.contains("--apply not wired"), "{e}");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    #[cfg(windows)]
    fn run_reads_a_snapshot_made_by_snapshot_ps1() {
        // F5 ↔ F3 contract end to end: everything the PowerShell script
        // writes is exactly what the import accepts. Synthetic data
        // only — Source and Dest both live under the OS temp dir.
        let base = temp_dir("ps1");
        let source = base.join("Source");
        let dest = base.join("Dest");
        let msg = source.join("Core").join("Message");
        std::fs::create_dir_all(&msg).unwrap();
        let pass = "fakefakefakefakefakefakefake1234";
        make_cipher_db(&source.join("Core").join("Index.db"), pass, None);
        for name in ["123.db", "g456.db", "stranger_box.db", "undefined.db", "weird.db"] {
            std::fs::write(msg.join(name), b"fake").unwrap();
        }
        // sidecars must be copied too
        std::fs::write(source.join("Core").join("Index.db-wal"), b"fake-wal").unwrap();
        std::fs::write(source.join("Core").join("Index.db-shm"), b"fake-shm").unwrap();

        let script = PathBuf::from(std::env::var("CARGO_MANIFEST_DIR").unwrap())
            .parent()
            .unwrap()
            .join("tools")
            .join("snapshot.ps1");
        assert!(script.is_file(), "tools/snapshot.ps1 is missing");
        // -Force: a synthetic run while the user's real Zalo Desktop
        // may be running (it is never touched or quit by tests).
        let out = std::process::Command::new("powershell")
            .args([
                "-NoProfile",
                "-NonInteractive",
                "-ExecutionPolicy",
                "Bypass",
                "-File",
                &script.to_string_lossy(),
                "-Source",
                &source.to_string_lossy(),
                "-Dest",
                &dest.to_string_lossy(),
                "-Force",
            ])
            .output()
            .expect("powershell must start");
        assert!(
            out.status.success(),
            "snapshot.ps1 failed:\nstdout: {}\nstderr: {}",
            String::from_utf8_lossy(&out.stdout),
            String::from_utf8_lossy(&out.stderr)
        );

        // The copied snapshot imports through the exact CLI path.
        let key = base.join("d7.bin");
        fake_d7_key_file(&key, pass);
        let s = run(&args_for(&dest, &sha12(pass.as_bytes()), Some(&key))).unwrap();
        assert_eq!(s.profile, Some(CipherProfile::Compat4));
        assert_eq!(s.index_tables, 1);
        assert_eq!(s.one_to_one, 1);
        assert_eq!(s.group, 1);
        assert_eq!(s.stranger_box, 1);
        assert_eq!(s.undefined, 1);
        assert_eq!(s.other, 1);
        // Everything, sidecars included, was copied.
        assert!(dest.join("Core").join("Index.db-wal").is_file());
        assert!(dest.join("Core").join("Index.db-shm").is_file());
        assert!(dest.join(SNAPSHOT_MANIFEST).is_file());
        // Immutable proof on the script's own output: the only entries
        // under Core\ are the copied DB, the copied sidecars and the
        // Message dir — nothing new appeared during the import.
        let names = listing(&dest.join("Core"));
        assert_eq!(
            names,
            vec![
                "Index.db".to_string(),
                "Index.db-shm".to_string(),
                "Index.db-wal".to_string(),
                "Message".to_string()
            ]
        );
        assert!(!dest.join("Core").join("Index.db-journal").exists());
        let _ = std::fs::remove_dir_all(&base);
    }
}
