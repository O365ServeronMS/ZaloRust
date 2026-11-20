//! Zalo Desktop DB import (P2 — dry-run skeleton; audit §4 items
//! 2.0–2.4, batch 6 F2–F4; batch 12 adds the L1 inventory, the L2
//! mapping dry run and the L4 delta groundwork — see
//! `import_map.rs` and `docs/import-mapping.md`).
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
use super::import_map;
use super::Write;

/// Batch 12 L1: shape-only schema inventory (`--inventory`).
pub mod inventory;

/// Batch 14 N1: the whitelisted `--distinct` code-column probe —
/// privacy-guarded by construction (whitelist → fixed aggregation →
/// code-shape-only rendering), unit-tested against synthetic DBs.
pub mod distinct;

/// The snapshot manifest file (F5 writes it, `run` requires it):
/// proof that `--from-snapshot` is a cold, byte-verified copy.
pub const SNAPSHOT_MANIFEST: &str = "snapshot-manifest.json";

/// sha256 of `bytes`, first 12 hex chars — the only key fingerprint
/// ever printed (brief: "only its length and sha256-12"). Batch 16:
/// `pub(crate)` because the apply step's fixtures build the same fake
/// D7 captures.
pub(crate) fn sha12(bytes: &[u8]) -> String {
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

// --- batch 15 O4: own-uid for the import extraction (KQ2 applied) -------

/// The pure own-uid decision for an import run: the env override
/// `ZR_OWN_UID` (validated with `account::valid_uid`) wins over the
/// settings file's `shadow.own_uid`; a candidate that fails the
/// shape check behaves as absent (the account.rs rule — a badly
/// shaped config never becomes a sender). Unit-tested with FAKE uids.
pub fn own_uid_decision(env_uid: Option<&str>, settings_uid: Option<&str>) -> Option<String> {
    env_uid
        .filter(|u| super::account::valid_uid(u))
        .or_else(|| settings_uid.filter(|u| super::account::valid_uid(u)))
        .map(str::to_string)
}

/// Resolve the import's own uid (batch 15 O4): `ZR_OWN_UID` first,
/// else `settings.shadow.own_uid` read through the settings loader
/// when `use_settings` (`--own-uid-from-settings`). The uid is NEVER
/// printed or logged — callers report only `own_uid set: true/false`.
/// The import CLI runs before Tauri exists, so the settings file is
/// loaded by path (`settings::load_at`, same `jsonfile::read` +
/// `sanitized()` semantics as the app loader, zero writes).
pub fn resolve_own_uid(use_settings: bool) -> Option<String> {
    let env_uid = std::env::var("ZR_OWN_UID").ok();
    let settings_uid = if use_settings {
        crate::settings::path_without_app()
            .map(|p| crate::settings::load_at(&p))
            .and_then(|s| s.shadow.own_uid)
    } else {
        None
    };
    own_uid_decision(env_uid.as_deref(), settings_uid.as_deref())
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
/// Batch 16: `pub(crate)` so the apply step's synthetic fixtures can
/// key their fake Desktop DBs the same way.
pub(crate) fn apply_passphrase_key(conn: &Connection, passphrase: &str) -> Result<(), String> {
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

/// Everything a run mode needs after the batch-6 guards: the account
/// dir, the zeroized passphrase (never printed, never logged), the
/// verified cipher profile and the key sha12 (the only key fact that
/// may appear in output).
pub struct Prepared {
    pub uid_dir: PathBuf,
    pub passphrase: Zeroizing<String>,
    pub profile: CipherProfile,
    pub key_sha12: String,
}

/// The batch-6 guards + key load + profile detection (KQ4/M2), shared
/// by every import mode: refuse anything that is not a cold snapshot
/// (`validate_snapshot`), load the D7 key file (the key is never on
/// argv), cross-check it against `--uin-hash`, then detect — or
/// verify a forced — cipher profile against `Core\Index.db`.
pub fn prepare(a: &ImportArgs) -> Result<Prepared, String> {
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
    // Index.db.
    let profile = match a.cipher_compat {
        Some(p) => {
            open_desktop_db(&index, &passphrase, p)?;
            p
        }
        None => try_profiles(&index, &passphrase)?,
    };
    Ok(Prepared {
        uid_dir,
        passphrase,
        profile,
        key_sha12,
    })
}

/// Dry-run inventory of a cold snapshot (F3/F4). `--apply` stays
/// fail-closed (P2 item 2.5 wires the writer later).
pub fn run(a: &ImportArgs) -> Result<Summary, String> {
    let p = prepare(a)?;
    let index = p.uid_dir.join("Core").join("Index.db");
    let conn = open_desktop_db(&index, p.passphrase.as_str(), p.profile)?;
    let index_tables = table_count(&conn);
    drop(conn);

    let mut s = Summary {
        index_tables,
        profile: Some(p.profile),
        key_sha12: p.key_sha12,
        ..Summary::default()
    };

    // F4/M2-4: classify every Core\Message\*.db; `undefined.db` is
    // counted and skipped; `-wal`/`-shm` sidecars are not DBs.
    for (_name, kind) in message_db_names(&p.uid_dir)? {
        match kind {
            DbKind::OneToOne(_) => s.one_to_one += 1,
            DbKind::Group(_) => s.group += 1,
            DbKind::StrangerBox => s.stranger_box += 1,
            DbKind::Undefined => s.undefined += 1, // counted, skipped
            DbKind::Other => s.other += 1,
        }
    }

    if a.apply {
        return Err(
            "--apply is dispatched by the CLI before this point (cli::main routes it to \
             import_apply::run_apply with its preconditions); this default inventory \
             mode never writes".into(),
        );
    }
    Ok(s)
}

// --- batch 12: the inventory + mapping-dry-run modes (L1/L2/L4) ----------

/// The snapshot's `Core\Message\*.db` entries, sorted by file name,
/// with their kind (M2-4). Sidecars never match. Shared by the dry
/// run, `--distinct --all-dbs` and the batch-15 probes.
pub fn message_db_names(uid_dir: &Path) -> Result<Vec<(String, DbKind)>, String> {
    let msg_dir = uid_dir.join("Core").join("Message");
    if !msg_dir.is_dir() {
        return Err(format!("missing {} — broken snapshot?", msg_dir.display()));
    }
    let mut names: Vec<String> = std::fs::read_dir(&msg_dir)
        .map_err(|e| format!("{}: {e}", msg_dir.display()))?
        .flatten()
        .map(|e| e.file_name().to_string_lossy().into_owned())
        .filter(|n| n.ends_with(".db"))
        .collect();
    names.sort();
    Ok(names
        .into_iter()
        .map(|n| {
            let kind = classify_message_db(&n);
            (n, kind)
        })
        .collect())
}

/// The snapshot inventory set (L1): `Core\Index.db` plus ONE sample
/// per message-DB kind (first 1-1, first group, stranger_box by
/// sorted file name). A sample that refuses to open is REPORTED, not
/// fatal — the inventory is a report tool; one broken DB among 1 471
/// must not block it.
pub struct GatheredInventories {
    pub inv: inventory::SnapshotInventories,
    /// (file name, error) per sample DB that existed but did not open.
    pub failed_samples: Vec<(String, String)>,
    /// The F4 enumeration counts.
    pub one_to_one: usize,
    pub group: usize,
    pub stranger_box: usize,
    pub undefined: usize,
    pub other: usize,
}

pub fn gather_inventories(p: &Prepared) -> Result<GatheredInventories, String> {
    let index_path = p.uid_dir.join("Core").join("Index.db");
    let conn = open_desktop_db(&index_path, p.passphrase.as_str(), p.profile)?;
    let inv = inventory::inventory_db(&conn)?;
    drop(conn);
    let mut g = GatheredInventories {
        inv: inventory::SnapshotInventories {
            index: Some(inventory::KindInventory {
                source_rel: "Core/Index.db".into(),
                inventory: inv,
            }),
            one_to_one: None,
            group: None,
            stranger_box: None,
        },
        failed_samples: Vec::new(),
        one_to_one: 0,
        group: 0,
        stranger_box: 0,
        undefined: 0,
        other: 0,
    };
    for (name, kind) in message_db_names(&p.uid_dir)? {
        match kind {
            DbKind::OneToOne(_) => g.one_to_one += 1,
            DbKind::Group(_) => g.group += 1,
            DbKind::StrangerBox => g.stranger_box += 1,
            DbKind::Undefined => g.undefined += 1,
            DbKind::Other => g.other += 1,
        }
        let sample_free = match kind {
            DbKind::OneToOne(_) => g.inv.one_to_one.is_none(),
            DbKind::Group(_) => g.inv.group.is_none(),
            DbKind::StrangerBox => g.inv.stranger_box.is_none(),
            _ => false,
        };
        if !sample_free {
            continue;
        }
        let path = p.uid_dir.join("Core").join("Message").join(&name);
        let sampled: Result<inventory::DbInventory, (String, String)> = (|| {
            let conn = open_desktop_db(&path, p.passphrase.as_str(), p.profile)
                .map_err(|e| (name.clone(), e))?;
            inventory::inventory_db(&conn).map_err(|e| (name.clone(), e))
        })();
        match sampled {
            Ok(inv) => {
                let ki = inventory::KindInventory {
                    source_rel: format!("Core/Message/{name}"),
                    inventory: inv,
                };
                match kind {
                    DbKind::OneToOne(_) => g.inv.one_to_one = Some(ki),
                    DbKind::Group(_) => g.inv.group = Some(ki),
                    DbKind::StrangerBox => g.inv.stranger_box = Some(ki),
                    _ => unreachable!("only these kinds sample"),
                }
            }
            Err((n, e)) => g.failed_samples.push((n, e)),
        }
    }
    Ok(g)
}

/// The `--inventory` mode (L1, dry-run only — parse refuses `--apply`
/// with it): shape-only inventory of `Core\Index.db` + one sample per
/// message-DB kind, as lines for the CLI to print, and the same as
/// JSON to `--out` when given. Nothing writes to the snapshot; every
/// DB opens `mode=ro&immutable=1`.
pub fn run_inventory(a: &ImportArgs) -> Result<Vec<String>, String> {
    let p = prepare(a)?;
    let g = gather_inventories(&p)?;
    let mut lines = Vec::new();

    let idx = g
        .inv
        .index
        .as_ref()
        .expect("gather_inventories always inventories Index.db");
    lines.push(format!(
        "inventory: Core/Index.db ({} table(s))",
        idx.inventory.tables.len()
    ));
    for t in &idx.inventory.tables {
        lines.push(t.line());
    }
    for (title, ki) in [
        ("sample one2one", g.inv.one_to_one.as_ref()),
        ("sample group", g.inv.group.as_ref()),
        ("sample stranger_box", g.inv.stranger_box.as_ref()),
    ] {
        match ki {
            Some(ki) => {
                lines.push(format!(
                    "inventory: {title} {} ({} table(s))",
                    ki.source_rel,
                    ki.inventory.tables.len()
                ));
                for t in &ki.inventory.tables {
                    lines.push(t.line());
                }
            }
            None => lines.push(format!("inventory: {title}: none found in the snapshot")),
        }
    }
    for (name, err) in &g.failed_samples {
        lines.push(format!("inventory: sample {name}: skipped (open failed: {err})"));
    }
    lines.push(format!(
        "inventory: message DBs: one_to_one={} group={} stranger_box={} undefined={} other={}",
        g.one_to_one, g.group, g.stranger_box, g.undefined, g.other
    ));
    if let Some(out) = &a.out {
        let json = serde_json::to_string_pretty(&g.inv)
            .map_err(|e| format!("--out {}: serializing the inventory failed: {e}", out.display()))?;
        std::fs::write(out, json)
            .map_err(|e| format!("--out {}: {e}", out.display()))?;
        lines.push(format!("inventory: wrote JSON to {}", out.display()));
    }
    Ok(lines)
}

/// The `--distinct` mode (batch 14 N1, dry-run only — parse refuses
/// `--apply`): whitelisted code-column distinct values. Without
/// `--all-dbs` it reads the first sample DB of each requested kind
/// (`--inventory`'s samples); with `--all-dbs` (batch 15 O2, message
/// kinds only) it runs the SAME fixed aggregation in EVERY DB of the
/// kind and sums the per-DB counts. Every spec is validated against
/// the inventory BEFORE any row is read; all violations are listed at
/// once (the `plan` convention). Nothing writes to the snapshot;
/// every DB opens `mode=ro&immutable=1`.
pub fn run_distinct(a: &ImportArgs) -> Result<Vec<String>, String> {
    use import_map::MapDb;
    use rusqlite::types::Value as SV;

    let p = prepare(a)?;
    let g = gather_inventories(&p)?;

    // Validate every spec first: sample, table, column, whitelist.
    // The whitelist refusal names the rule (the N1 hard rule: the
    // tool must be unable to print content, so content-bearing
    // columns never reach the aggregation).
    let mut errs = Vec::new();
    for spec in &a.distinct {
        let who = format!("--distinct {}", distinct::spec_str(spec));
        let Some(kinv) = sample_inventory(&g.inv, spec.kind) else {
            errs.push(format!(
                "{who}: the snapshot has no {} sample DB to read",
                spec.kind.name()
            ));
            continue;
        };
        let Some(tinfo) = kinv.inventory.table(&spec.table) else {
            errs.push(format!(
                "{who}: table {:?} does not exist (inventory {})",
                spec.table, kinv.source_rel
            ));
            continue;
        };
        if !tinfo.columns.iter().any(|c| c.name == spec.column) {
            errs.push(format!(
                "{who}: column {:?} does not exist in table {:?} (inventory {})",
                spec.column, spec.table, kinv.source_rel
            ));
            continue;
        }
        if !distinct::is_code_column(&spec.column) {
            errs.push(format!(
                "{who}: column {:?} is not on the code-column whitelist — refused \
                 (rule: {}, case-insensitive; content-bearing columns can never \
                 be probed by this tool)",
                spec.column, distinct::CODE_COLUMN_RULE
            ));
        }
    }
    if !errs.is_empty() {
        return Err(format!(
            "--distinct validation ({} error(s)):\n  - {}",
            errs.len(),
            errs.join("\n  - ")
        ));
    }

    // Batch 15 O2: --all-dbs runs the SAME fixed aggregation in every
    // DB of the requested message kind and sums the counts. Open and
    // query failures are COUNTED, not printed one by one (1 472 DBs —
    // the report is an aggregate).
    if a.all_dbs {
        let msg_dir = p.uid_dir.join("Core").join("Message");
        let names = message_db_names(&p.uid_dir)?;
        let mut lines = Vec::new();
        for spec in &a.distinct {
            let mut dbs = 0usize;
            let mut opened = 0usize;
            let mut failed = 0usize;
            let mut per_db: Vec<Vec<(SV, i64)>> = Vec::new();
            for (name, k) in &names {
                let map_kind = match k {
                    DbKind::OneToOne(_) => MapDb::OneToOne,
                    DbKind::Group(_) => MapDb::Group,
                    DbKind::StrangerBox => MapDb::Stranger,
                    // `undefined.db` and unknown names stay skipped.
                    DbKind::Undefined | DbKind::Other => continue,
                };
                if map_kind != spec.kind {
                    continue;
                }
                dbs += 1;
                match open_desktop_db(&msg_dir.join(name), p.passphrase.as_str(), p.profile) {
                    Ok(conn) => match distinct::group_counts(&conn, &spec.table, &spec.column) {
                        Ok(rows) => {
                            opened += 1;
                            per_db.push(rows);
                        }
                        Err(_) => failed += 1,
                    },
                    Err(_) => failed += 1,
                }
            }
            lines.extend(distinct::all_dbs_report(spec, dbs, opened, failed, &per_db));
        }
        return Ok(lines);
    }

    // All specs valid: read the samples, one open per kind.
    let mut lines = Vec::new();
    let mut conns: std::collections::BTreeMap<MapDb, Connection> = Default::default();
    for spec in &a.distinct {
        if !conns.contains_key(&spec.kind) {
            let kinv = sample_inventory(&g.inv, spec.kind).expect("validated above");
            let path = sample_db_path(&p, &kinv.source_rel);
            let conn = open_desktop_db(&path, p.passphrase.as_str(), p.profile)
                .map_err(|e| format!("--distinct {}: {e}", distinct::spec_str(spec)))?;
            conns.insert(spec.kind, conn);
        }
        let conn = conns.get(&spec.kind).expect("opened above");
        let kinv = sample_inventory(&g.inv, spec.kind).expect("validated above");
        let out = distinct::distinct_report(conn, spec, &kinv.source_rel)
            .map_err(|e| format!("--distinct {}: {e}", distinct::spec_str(spec)))?;
        lines.extend(out);
    }
    Ok(lines)
}

/// The inventory sample of one DB kind (`run_distinct`'s lookup —
/// the same samples `--inventory` reports).
fn sample_inventory<'a>(
    inv: &'a inventory::SnapshotInventories,
    kind: import_map::MapDb,
) -> Option<&'a inventory::KindInventory> {
    match kind {
        import_map::MapDb::Index => inv.index.as_ref(),
        import_map::MapDb::OneToOne => inv.one_to_one.as_ref(),
        import_map::MapDb::Group => inv.group.as_ref(),
        import_map::MapDb::Stranger => inv.stranger_box.as_ref(),
    }
}

/// The absolute path of a sample's `source_rel` (the forward-slash
/// relative path inside the snapshot, e.g. `Core/Message/123.db` —
/// built by `gather_inventories`, never raw user input).
fn sample_db_path(p: &Prepared, source_rel: &str) -> PathBuf {
    let mut path = p.uid_dir.clone();
    path.extend(source_rel.split('/'));
    path
}

/// The `--mapping`/`--shadow-copy` dry-run mode (L2, dry-run only):
/// plan the mapping against the snapshot inventory, extract every DB
/// of the mapped kinds into `Write`s, and classify each write
/// READ-ONLY against a temp COPY of the shadow store when
/// `--shadow-copy` is given. No writes anywhere; `--apply` stays
/// fail-closed (2.5 is a later, user-approved step).
pub fn run_mapping_dry(a: &ImportArgs) -> Result<Vec<String>, String> {
    use import_map::{EntityCounters, ExtractOpts, MapDb};

    let p = prepare(a)?;
    let mapping = match &a.mapping {
        Some(f) => import_map::load_mapping_file(f)?,
        None => import_map::Mapping::skeleton(),
    };
    let g = gather_inventories(&p)?;
    let plan = import_map::plan(&mapping, &g.inv).map_err(|errs| {
        format!(
            "mapping failed validation ({} error(s)):\n  - {}",
            errs.len(),
            errs.join("\n  - ")
        )
    })?;

    let mut lines = vec![
        format!(
            "import dry-run: mapping={}",
            match &a.mapping {
                Some(f) => f.display().to_string(),
                None => "<built-in skeleton: maps nothing>".to_string(),
            }
        ),
        format!("import dry-run: plan OK ({})", plan.summary_line()),
        format!(
            "import dry-run: snapshot: profile={} one_to_one={} group={} stranger_box={} undefined={} other={}",
            p.profile.name(),
            g.one_to_one,
            g.group,
            g.stranger_box,
            g.undefined,
            g.other
        ),
    ];
    for (name, err) in &g.failed_samples {
        lines.push(format!(
            "import dry-run: sample {name}: skipped (open failed: {err})"
        ));
    }

    // Batch 15 O4 (KQ2 on the import path): the self-sent sender
    // substitution seed — `ZR_OWN_UID`, else `--own-uid-from-settings`.
    // The value is never printed; only whether one was resolved.
    let own_uid = resolve_own_uid(a.own_uid_from_settings);
    lines.push(format!("import dry-run: own_uid set: {}", own_uid.is_some()));

    // The shadow target: a temp COPY opened read-only, never the live
    // store. Without --shadow-copy the classification is skipped and
    // only extraction counts are reported.
    let shadow = match &a.shadow_copy {
        Some(dir) => {
            let (conn, tmp) = import_map::open_shadow_copy(dir)?;
            lines.push(format!(
                "import dry-run: shadow target: temp copy of {} at {} (read-only)",
                dir.display(),
                tmp.display()
            ));
            Some(conn)
        }
        None => {
            lines.push("import dry-run: classification: skipped (no --shadow-copy)".into());
            None
        }
    };

    let (mut c_conv, mut c_contact, mut c_group, mut c_msg) = (
        EntityCounters::default(),
        EntityCounters::default(),
        EntityCounters::default(),
        EntityCounters::default(),
    );
    let mut msg_by_kind: std::collections::BTreeMap<&'static str, usize> =
        std::collections::BTreeMap::new();
    let mut attachment_rows: i64 = 0;
    let (mut dbs_opened, mut dbs_failed) = (0usize, 0usize);

    // Index.db: the account-wide entities (+ attachment refs if the
    // mapping points them at the index kind).
    let index_entities = [
        plan.conversation.as_ref(),
        plan.contact.as_ref(),
        plan.group.as_ref(),
        plan.attachment.as_ref(),
    ]
    .into_iter()
    .flatten()
    .any(|e| e.db.contains(&MapDb::Index));
    if index_entities {
        let index_path = p.uid_dir.join("Core").join("Index.db");
        match open_desktop_db(&index_path, p.passphrase.as_str(), p.profile) {
            Ok(conn) => {
                dbs_opened += 1;
                let opts = ExtractOpts { kind: MapDb::Index, db_id: None, cursor: None, own_uid: own_uid.as_deref() };
                match import_map::extract(&conn, &plan, &opts) {
                    Ok((writes, skips)) => {
                        c_conv.skipped += skips.conversation;
                        c_contact.skipped += skips.contact;
                        c_group.skipped += skips.group;
                        for w in &writes {
                            let verdict = shadow
                                .as_ref()
                                .map(|s| import_map::classify_write(s, w))
                                .transpose()?;
                            match w {
                                Write::Conversation { .. } => {
                                    c_conv.extracted += 1;
                                    if let Some(v) = verdict {
                                        c_conv.bump(v);
                                    }
                                }
                                Write::Contact { .. } => {
                                    c_contact.extracted += 1;
                                    if let Some(v) = verdict {
                                        c_contact.bump(v);
                                    }
                                }
                                Write::Group { .. } => {
                                    c_group.extracted += 1;
                                    if let Some(v) = verdict {
                                        c_group.bump(v);
                                    }
                                }
                                _ => {}
                            }
                        }
                        if let Some(ap) = &plan.attachment {
                            if ap.db.contains(&MapDb::Index) {
                                attachment_rows += import_map::count_rows(&conn, ap)?;
                            }
                        }
                    }
                    Err(e) => {
                        dbs_failed += 1;
                        lines.push(format!("import dry-run: Core/Index.db: extract failed: {e}"));
                    }
                }
            }
            Err(e) => {
                dbs_failed += 1;
                lines.push(format!("import dry-run: Core/Index.db: open failed: {e}"));
            }
        }
    }

    // The message DBs of the mapped kinds.
    let msg_dir = p.uid_dir.join("Core").join("Message");
    for (name, kind) in message_db_names(&p.uid_dir)? {
        let (map_kind, db_id) = match kind {
            DbKind::OneToOne(id) => (MapDb::OneToOne, Some(id)),
            DbKind::Group(id) => (MapDb::Group, Some(id)),
            DbKind::StrangerBox => (MapDb::Stranger, None),
            // `undefined.db` and unknown names stay counted, skipped.
            DbKind::Undefined | DbKind::Other => continue,
        };
        let applies = plan
            .message
            .as_ref()
            .is_some_and(|e| e.db.contains(&map_kind))
            || plan
                .attachment
                .as_ref()
                .is_some_and(|e| e.db.contains(&map_kind));
        if !applies {
            continue;
        }
        let rel = format!("Core/Message/{name}");
        let conn = match open_desktop_db(&msg_dir.join(&name), p.passphrase.as_str(), p.profile) {
            Ok(c) => {
                dbs_opened += 1;
                c
            }
            Err(e) => {
                dbs_failed += 1;
                lines.push(format!("import dry-run: {rel}: open failed: {e}"));
                continue;
            }
        };
        // L4 --delta: read this DB's cursor from the shadow COPY
        // (read-only; never written).
        let cursor = if a.delta {
            match &shadow {
                Some(s) => import_map::read_import_cursor(s, &rel)?,
                None => None, // no shadow copy: assume a fresh import
            }
        } else {
            None
        };
        let opts = ExtractOpts { kind: map_kind, db_id, cursor, own_uid: own_uid.as_deref() };
        let mut extracted_here = 0usize;
        match import_map::extract(&conn, &plan, &opts) {
            Ok((writes, skips)) => {
                c_msg.skipped += skips.message;
                extracted_here = writes.len();
                *msg_by_kind.entry(map_kind.name()).or_default() += writes.len();
                for w in &writes {
                    let verdict = shadow
                        .as_ref()
                        .map(|s| import_map::classify_write(s, w))
                        .transpose()?;
                    if let Write::Message { .. } = w {
                        c_msg.extracted += 1;
                        if let Some(v) = verdict {
                            c_msg.bump(v);
                        }
                    }
                }
                if let Some(ap) = &plan.attachment {
                    if ap.db.contains(&map_kind) {
                        attachment_rows += import_map::count_rows(&conn, ap)?;
                    }
                }
            }
            Err(e) => {
                dbs_failed += 1;
                lines.push(format!("import dry-run: {rel}: extract failed: {e}"));
            }
        }
        if a.delta {
            let total = plan
                .message
                .as_ref()
                .map(|ep| import_map::count_rows(&conn, ep))
                .transpose()?
                .unwrap_or(0);
            let next = plan
                .message
                .as_ref()
                .map(|ep| import_map::next_cursor(&conn, ep))
                .transpose()?
                .flatten();
            let cur = cursor.map(import_map::encode_cursor).unwrap_or_else(|| "none".into());
            let nxt = next
                .map(import_map::encode_cursor)
                .unwrap_or_else(|| "none".into());
            lines.push(format!(
                "import delta: {rel} cursor={cur} total_rows={total} would_extract={extracted_here} next_cursor={nxt}"
            ));
        }
    }

    if plan.conversation.is_some() {
        lines.push(format!("import dry-run: conversations: {}", c_conv.line()));
    }
    if plan.contact.is_some() {
        lines.push(format!("import dry-run: contacts: {}", c_contact.line()));
    }
    if plan.group.is_some() {
        lines.push(format!("import dry-run: groups: {}", c_group.line()));
    }
    if plan.message.is_some() {
        let by_kind: Vec<String> = msg_by_kind
            .iter()
            .map(|(k, n)| format!("{k}={n}"))
            .collect();
        let by_kind = if by_kind.is_empty() {
            String::from("-")
        } else {
            by_kind.join(" ")
        };
        lines.push(format!(
            "import dry-run: messages: {} by_kind={}",
            c_msg.line(),
            by_kind
        ));
    }
    if plan.attachment.is_some() {
        lines.push(format!(
            "import dry-run: attachment refs: rows={attachment_rows} (counted only — no Write in this batch; the writer derives refs from message payloads at apply time)"
        ));
    }
    lines.push(format!(
        "import dry-run: dbs opened={dbs_opened} failed={dbs_failed}"
    ));
    lines.push(
        "import dry-run: no writes performed (dry-run; --apply is a separate, guarded step \
         — P2 item 2.5, docs/import-mapping.md)"
            .into(),
    );
    Ok(lines)
}

// --- batch 16 P2: media hardlink PREP (item 2.6, dry-run only) --------------

/// One media-metadata table the plan considered (shape only: names,
/// never values).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MediaTablePlan {
    /// `Core/Index.db` | `Core/Media.db`.
    pub source: String,
    pub table: String,
    pub path_column: String,
}

/// The 2.6 dry-run report — counts only, the brief's exact fields.
/// NO hashing happens anywhere in this plan (sha256 is a later,
/// apply-step concern); NO hardlink is ever created.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct MediaPlanReport {
    /// The tables rows were read from (a table qualifies when it
    /// carries a column whose name contains "path", case-insensitive).
    pub tables: Vec<MediaTablePlan>,
    /// Rows whose path column held a non-empty ABSOLUTE local path
    /// (drive letter or UNC — urls and relative values are not rows).
    pub rows: usize,
    /// Present files (`std::fs::metadata` says a regular file exists).
    pub present: usize,
    /// Everything else (missing, a directory, unreadable).
    pub missing: usize,
    /// Sum of the present files' sizes.
    pub total_bytes: u64,
    /// Present files on the store's volume (drive-letter comparison —
    /// the KQ9/D9 rule: hardlinks need one volume; an unresolvable
    /// drive counts as same, the established `same_volume` semantics).
    pub same_volume: usize,
    /// Present files on another volume.
    pub other_volume: usize,
    /// Bytes hardlinking would save vs copying: the present,
    /// same-volume bytes (those are exactly the files a hardlink
    /// could deduplicate).
    pub bytes_saved_vs_copy: u64,
    /// DBs that exist but could not be read (counted, never fatal —
    /// the plan is a report).
    pub dbs_failed: usize,
}

/// A path value that could be a local FILE path: an absolute drive
/// path (`D:\…`) or a UNC root. Everything else (urls, relatives,
/// empties) is not a media row. Used internally ONLY — a value that
/// passes is read with `std::fs::metadata` and never printed.
fn is_local_absolute(p: &str) -> bool {
    let b = p.as_bytes();
    (b.len() >= 3 && b[0].is_ascii_alphabetic() && b[1] == b':' && (b[2] == b'\\' || b[2] == b'/'))
        || p.starts_with(r"\\")
}

/// One DB's media tables. `named` restricts to a fixed table-name set
/// (the Index.db rule: `image`, `file`, `media`); `None` considers
/// every table (the `Core/Media.db` rule — a separate Core DB whose
/// tables are all media-metadata candidates). A table qualifies when
/// it carries a column whose name contains "path"
/// (case-insensitive); the read is exactly that column. Table and
/// column NAMES are shape (printable); PATH VALUES are internal.
fn plan_db(
    conn: &Connection,
    source: &str,
    named: Option<&[&str]>,
    store_root: &Path,
    report: &mut MediaPlanReport,
) -> Result<(), String> {
    let inv = inventory::inventory_db(conn)?;
    for t in &inv.tables {
        if let Some(names) = named {
            if !names.contains(&t.name.to_ascii_lowercase().as_str()) {
                continue;
            }
        }
        let Some(path_col) = t
            .columns
            .iter()
            .find(|c| c.name.to_ascii_lowercase().contains("path"))
        else {
            continue; // no path column: not a media-path table
        };
        let qt = inventory::quote_ident(&t.name)?;
        let qc = inventory::quote_ident(&path_col.name)?;
        let mut st = conn
            .prepare(&format!("SELECT {qc} FROM {qt}"))
            .map_err(|e| format!("{source} {}.{}: {e}", t.name, path_col.name))?;
        let values = st
            .query_map([], |r| r.get::<_, Option<String>>(0))
            .map_err(|e| format!("{source} {}.{}: {e}", t.name, path_col.name))?;
        for v in values.flatten().flatten() {
            if !is_local_absolute(&v) {
                continue; // url/relative/empty: not a media row
            }
            report.rows += 1;
            // Metadata only (the brief's rule): existence, size, and
            // the volume of the PATH — no content is ever read, and
            // hashing is a later apply step, not this plan.
            match std::fs::metadata(&v) {
                Ok(m) if m.is_file() => {
                    report.present += 1;
                    report.total_bytes += m.len();
                    if super::settings_check::same_volume(Path::new(&v), store_root) {
                        report.same_volume += 1;
                        report.bytes_saved_vs_copy += m.len();
                    } else {
                        report.other_volume += 1;
                    }
                }
                _ => report.missing += 1,
            }
        }
        report.tables.push(MediaTablePlan {
            source: source.to_string(),
            table: t.name.clone(),
            path_column: path_col.name.clone(),
        });
    }
    Ok(())
}

/// The 2.6 dry run (PLAN ONLY): for each Desktop media row with a
/// local file path — Index.db tables named `image`/`file`/`media`,
/// plus every `Core/Media.db` table when that DB is present — compute
/// whether the file exists (`std::fs::metadata`, no content read), its
/// size, and whether its path is on the same volume as `store_root`.
/// Counts only; no sha256 anywhere here; no hardlink is created.
pub fn media_plan(p: &Prepared, store_root: &Path) -> Result<MediaPlanReport, String> {
    let mut report = MediaPlanReport::default();
    // Index.db: only the three names the inventory knowledge calls
    // media metadata.
    let index_path = p.uid_dir.join("Core").join("Index.db");
    let index = open_desktop_db(&index_path, p.passphrase.as_str(), p.profile)?;
    plan_db(
        &index,
        "Core/Index.db",
        Some(&["image", "file", "media"]),
        store_root,
        &mut report,
    )?;
    drop(index);
    // Core/Media.db if present: every table with a path column. An
    // unreadable Media.db is counted, not fatal (the plan is a report).
    let media_db = p.uid_dir.join("Core").join("Media.db");
    if media_db.is_file() {
        match open_desktop_db(&media_db, p.passphrase.as_str(), p.profile) {
            Ok(conn) => {
                plan_db(&conn, "Core/Media.db", None, store_root, &mut report)?;
            }
            Err(_) => report.dbs_failed += 1,
        }
    }
    Ok(report)
}

/// The `--media-plan` mode (2.6, dry-run only): counts only. The store
/// root is resolved exactly the way the media worker resolves it —
/// `settings.shadow.media_store`, else the documented default — read
/// read-only through the settings loader; the path itself is never
/// printed, and the snapshot is opened with the usual immutable
/// guards. Nothing is written anywhere.
pub fn run_media_plan(a: &ImportArgs) -> Result<Vec<String>, String> {
    let p = prepare(a)?;
    let settings = crate::settings::path_without_app()
        .map(|path| crate::settings::load_at(&path))
        .unwrap_or_default();
    let store_root = super::media::media_store_root(&settings.shadow);
    let report = media_plan(&p, &store_root)?;
    let mut lines = vec![
        "media plan: dry-run — no hashing, no hardlinks, nothing written".to_string(),
    ];
    for t in &report.tables {
        lines.push(format!(
            "media plan: {} table {} (path column {:?})",
            t.source, t.table, t.path_column
        ));
    }
    lines.push(format!(
        "media plan: rows={} present={} missing={} total_bytes={} same_volume=yes:{} no:{} \
         bytes_hardlinking_saves_vs_copy={} media_dbs_failed={}",
        report.rows,
        report.present,
        report.missing,
        report.total_bytes,
        report.same_volume,
        report.other_volume,
        report.bytes_saved_vs_copy,
        report.dbs_failed
    ));
    Ok(lines)
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
            inventory: false,
            out: None,
            mapping: None,
            shadow_copy: None,
            delta: false,
            distinct: Vec::new(),
            all_dbs: false,
            own_uid_from_settings: false,
            apply: false,
            i_have_a_backup_plan: false,
            target: None,
            unmapped_as_raw: false,
            media_plan: false,
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
        assert!(e.contains("dispatched by the CLI"), "{e}");
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

    // --- batch 12: --inventory and the mapping dry run (L1/L2/L4) -------

    /// A synthetic Desktop-style cipher DB with ARBITRARY SQL (the
    /// fake schema the mapping tests iterate on). Fake passphrase,
    /// temp dir — never a real DB.
    #[cfg(windows)]
    fn make_cipher_db_sql(path: &Path, pass: &str, sql: &str) {
        let conn = Connection::open_with_flags(
            path,
            rusqlite::OpenFlags::SQLITE_OPEN_READ_WRITE
                | rusqlite::OpenFlags::SQLITE_OPEN_CREATE,
        )
        .unwrap();
        apply_passphrase_key(&conn, pass).unwrap();
        conn.execute_batch(sql).unwrap();
        conn.close().map_err(|(_, e)| e).unwrap();
    }

    /// The fake Desktop message schema + rows (the same shape the
    /// import_map unit tests use, so the CLI path and the pure path
    /// are pinned to one contract).
    #[cfg(windows)]
    const MSG_DB_SQL: &str = "CREATE TABLE msg (
        id INTEGER PRIMARY KEY, cliId TEXT, fromUid TEXT, toUid TEXT,
        ts INTEGER, type TEXT, content TEXT
      );
      INSERT INTO msg (id, cliId, fromUid, toUid, ts, type, content) VALUES
        (101, 'c101', 'u1', 'u2', 1690000000, 'chat.text.v2', 'hello there'),
        (102, 'c102', 'u2', 'u1', 1690000001, 'chat.photo',
         '{\"href\":\"https://fake-photo-stal.zdn.vn/x.jpg\",\"thumb\":\"https://fake/t.jpg\"}'),
        (103, 'c103', '0',   'u9', 1690000002, 'webchat', 'self sent'),
        (104, 'c104', 'u1', 'g77', 1690000003, 'chat.text.v2', 'group hello');";

    /// A full synthetic snapshot whose message DBs are REAL cipher
    /// DBs (the inventory + dry run open them). Returns the key path.
    #[cfg(windows)]
    fn synthetic_snapshot_rich(dir: &Path, pass: &str) -> PathBuf {
        write_manifest_json(dir, valid_manifest_json());
        let core = dir.join("Core");
        std::fs::create_dir_all(core.join("Message")).unwrap();
        make_cipher_db(&core.join("Index.db"), pass, None);
        make_cipher_db_sql(&core.join("Message").join("111.db"), pass, MSG_DB_SQL);
        make_cipher_db_sql(&core.join("Message").join("g222.db"), pass, MSG_DB_SQL);
        make_cipher_db_sql(&core.join("Message").join("stranger_box.db"), pass, MSG_DB_SQL);
        for name in ["undefined.db", "weird.db"] {
            std::fs::write(core.join("Message").join(name), b"fake").unwrap();
        }
        let key = dir.join("d7.bin");
        fake_d7_key_file(&key, pass);
        key
    }

    /// A FAKE shadow STORE dir (never the live one): default.db with
    /// the shadow schema applied + default.key. Returns the open
    /// connection so the test can seed rows, then drop it.
    #[cfg(windows)]
    fn fake_shadow_store(dir: &Path) -> Connection {
        let key = sqlcipher::generate_key().unwrap();
        sqlcipher::save_key(&key, &super::super::key_file(dir)).unwrap();
        let conn = sqlcipher::open_with_key(&super::super::db_file(dir), &key).unwrap();
        super::super::schema::apply(&conn).unwrap();
        conn
    }

    fn file_sha256(path: &Path) -> String {
        let mut h = Sha256::new();
        h.update(std::fs::read(path).unwrap());
        format!("{:x}", h.finalize())
    }

    #[test]
    #[cfg(windows)]
    fn run_inventory_prints_and_writes_the_shape_only_report() {
        let dir = temp_dir("inv");
        let pass = "fakefakefakefakefakefakefake1234";
        let key = synthetic_snapshot_rich(&dir, pass);
        let uin = sha12(pass.as_bytes());
        let out = dir.parent().unwrap().join(format!(
            "zr-inv-out-{}-{}.json",
            std::process::id(),
            super::super::schema::now_ms()
        ));
        let mut a = args_for(&dir, &uin, Some(&key));
        a.inventory = true;
        a.out = Some(out.clone());
        let lines = run_inventory(&a).unwrap();
        let joined = lines.join("\n");
        // Index.db (the batch-6 fixture's `conv` table) + one sample
        // per message kind — names/types/counts only.
        assert!(joined.contains("inventory: Core/Index.db (1 table(s))"), "{joined}");
        assert!(joined.contains("conv: rows=2 cols=(id:INTEGER pk,v:TEXT)"), "{joined}");
        assert!(joined.contains("inventory: sample one2one Core/Message/111.db (1 table(s))"), "{joined}");
        assert!(joined.contains("inventory: sample group Core/Message/g222.db (1 table(s))"), "{joined}");
        assert!(joined.contains("inventory: sample stranger_box Core/Message/stranger_box.db (1 table(s))"), "{joined}");
        assert!(joined.contains("msg: rows=4 cols=(id:INTEGER pk,cliId:TEXT,fromUid:TEXT"), "{joined}");
        assert!(
            joined.contains("message DBs: one_to_one=1 group=1 stranger_box=1 undefined=1 other=1"),
            "{joined}"
        );
        assert!(joined.contains(&format!("wrote JSON to {}", out.display())), "{joined}");
        // The out file parses back as the inventory set and matches.
        let back: inventory::SnapshotInventories =
            serde_json::from_str(&std::fs::read_to_string(&out).unwrap()).unwrap();
        let idx = back.index.as_ref().unwrap();
        assert_eq!(idx.source_rel, "Core/Index.db");
        assert_eq!(idx.inventory.tables.len(), 1);
        let o2o = back.one_to_one.as_ref().unwrap();
        assert_eq!(o2o.inventory.table("msg").unwrap().row_count, 4);
        assert!(back.stranger_box.is_some());
        // Nothing was ever written to the snapshot: immutable proof.
        let names = listing(&dir.join("Core").join("Message"));
        assert_eq!(
            names,
            vec![
                "111.db".to_string(),
                "g222.db".to_string(),
                "stranger_box.db".to_string(),
                "undefined.db".to_string(),
                "weird.db".to_string()
            ]
        );
        // The CLI exit-code path prints the same lines and exits 0.
        let argv = vec![
            "--from-snapshot".to_string(),
            dir.to_string_lossy().into_owned(),
            "--account".to_string(),
            "default".to_string(),
            "--uin-hash".to_string(),
            uin,
            "--key-file".to_string(),
            key.to_string_lossy().into_owned(),
            "--inventory".to_string(),
            "--out".to_string(),
            out.to_string_lossy().into_owned(),
        ];
        assert_eq!(crate::shadow::cli::main(&argv), 0);
        let _ = std::fs::remove_dir_all(&dir);
        let _ = std::fs::remove_file(&out);
    }

    #[test]
    #[cfg(windows)]
    fn run_inventory_reports_a_missing_sample_kind() {
        let dir = temp_dir("invmiss");
        let pass = "fakefakefakefakefakefakefake1234";
        let key = synthetic_snapshot_rich(&dir, pass);
        // Drop the group DB: the report says so and still succeeds.
        std::fs::remove_file(dir.join("Core").join("Message").join("g222.db")).unwrap();
        let mut a = args_for(&dir, &sha12(pass.as_bytes()), Some(&key));
        a.inventory = true;
        let lines = run_inventory(&a).unwrap();
        let joined = lines.join("\n");
        assert!(joined.contains("inventory: sample group: none found in the snapshot"), "{joined}");
        assert!(joined.contains("message DBs: one_to_one=1 group=0"), "{joined}");
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// The mapping used by the dry-run test (message over one2one,
    /// the fake msg schema, s_to_ms, a msgType table entry).
    #[cfg(windows)]
    const DRY_MAPPING_JSON: &str = r#"{
      "msgType": { "chat.text.v2": "webchat" },
      "entities": {
        "message": {
          "db": ["one2one"],
          "table": "msg",
          "columns": {
            "msgId": "id",
            "uidFrom": "fromUid",
            "idTo": "toUid",
            "ts": { "expr": "s_to_ms", "of": "ts" },
            "msgType": "type",
            "content": "content",
            "cliMsgId": "cliId"
          }
        }
      }
    }"#;

    #[test]
    #[cfg(windows)]
    fn run_mapping_dry_with_the_skeleton_maps_nothing() {
        let dir = temp_dir("dryskel");
        let pass = "fakefakefakefakefakefakefake1234";
        let key = synthetic_snapshot_rich(&dir, pass);
        let store = dir.join("shadow-store");
        std::fs::create_dir_all(&store).unwrap();
        drop(fake_shadow_store(&store));
        let before = (
            file_sha256(&super::super::db_file(&store)),
            file_sha256(&super::super::key_file(&store)),
        );
        let mut a = args_for(&dir, &sha12(pass.as_bytes()), Some(&key));
        a.shadow_copy = Some(store.clone());
        let lines = run_mapping_dry(&a).unwrap();
        let joined = lines.join("\n");
        assert!(
            joined.contains("mapping=<built-in skeleton: maps nothing>"),
            "{joined}"
        );
        assert!(joined.contains("plan OK (nothing mapped (skeleton))"), "{joined}");
        assert!(!joined.contains("classification: skipped (no --shadow-copy)"), "{joined}");
        assert!(joined.contains("shadow target: temp copy of"), "{joined}");
        assert!(joined.contains("dbs opened=0 failed=0"), "{joined}");
        assert!(joined.contains("no writes performed"), "{joined}");
        // No entity lines when nothing is mapped.
        assert!(!joined.contains("import dry-run: messages:"), "{joined}");
        // The store files never changed (only file-copied).
        assert_eq!(
            (file_sha256(&super::super::db_file(&store)), file_sha256(&super::super::key_file(&store))),
            before
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    #[cfg(windows)]
    fn run_mapping_dry_classifies_against_a_copied_store() {
        let dir = temp_dir("drymap");
        let pass = "fakefakefakefakefakefakefake1234";
        let key = synthetic_snapshot_rich(&dir, pass);
        // The mapping file.
        let map_path = dir.join("mapping.json");
        std::fs::write(&map_path, DRY_MAPPING_JSON).unwrap();
        // A FAKE shadow store seeded like the writer would leave it:
        // m101 capture WITH text, m102 capture cipher-only (NULL text
        // AND NULL sender).
        let store = dir.join("shadow-store");
        std::fs::create_dir_all(&store).unwrap();
        {
            let conn = fake_shadow_store(&store);
            super::super::writer::apply(
                &conn,
                &Write::Message {
                    msg_id: "101".into(),
                    conv_id: "u1".into(),
                    sender_id: Some("u1".into()),
                    ts: 1_690_000_000_000,
                    kind: 1,
                    text: Some("cap-text".into()),
                    payload: r#"{"msgId":"101","uidFrom":"u1","idTo":"u2","ts":1690000000000,"msgType":"webchat","content":"cap-text"}"#.into(),
                    source: "capture",
                    is_group: Some(false),
                },
            )
            .unwrap();
            super::super::writer::apply(
                &conn,
                &Write::Message {
                    msg_id: "102".into(),
                    conv_id: "u1".into(),
                    sender_id: None,
                    ts: 1_690_000_001_000,
                    kind: 2,
                    text: None,
                    payload: r#"{"msgId":"102","uidFrom":"u1","idTo":"u2","ts":1690000001000,"msgType":"chat.photo"}"#.into(),
                    source: "capture",
                    is_group: Some(false),
                },
            )
            .unwrap();
        }
        let before = (
            file_sha256(&super::super::db_file(&store)),
            file_sha256(&super::super::key_file(&store)),
        );

        let mut a = args_for(&dir, &sha12(pass.as_bytes()), Some(&key));
        a.mapping = Some(map_path.clone());
        a.shadow_copy = Some(store.clone());
        a.delta = true;
        let lines = run_mapping_dry(&a).unwrap();
        let joined = lines.join("\n");
        assert!(joined.contains(&format!("mapping={}", map_path.display())), "{joined}");
        assert!(joined.contains("plan OK (msgType entries=1, message[one2one]table=msg)"), "{joined}");
        // The four rows of 111.db: 101 ignored (capture has it),
        // 102 fill_null (NULL cells), 103+104 new. The g222/stranger
        // DBs are not in the mapping's kinds — never opened.
        assert!(
            joined.contains(
                "import dry-run: messages: extracted=4 new=2 fill_null=1 ignored=1 \
                 update_import=0 skipped=0 by_kind=one2one=4"
            ),
            "{joined}"
        );
        // The delta line: no cursor yet (nothing applied ever), the
        // raw-table totals, and the cursor an apply would write. Note
        // rowid: `id INTEGER PRIMARY KEY` IS the rowid alias here, so
        // max(rowid) is 104, not 4.
        assert!(
            joined.contains(
                "import delta: Core/Message/111.db cursor=none total_rows=4 \
                 would_extract=4 next_cursor=1690000003:104"
            ),
            "{joined}"
        );
        assert!(joined.contains("dbs opened=1 failed=0"), "{joined}");
        assert!(joined.contains("no writes performed"), "{joined}");
        // The shadow store files never changed.
        assert_eq!(
            (file_sha256(&super::super::db_file(&store)), file_sha256(&super::super::key_file(&store))),
            before
        );
        // The snapshot was never touched either (immutable proof).
        let names = listing(&dir.join("Core").join("Message"));
        assert_eq!(
            names,
            vec![
                "111.db".to_string(),
                "g222.db".to_string(),
                "stranger_box.db".to_string(),
                "undefined.db".to_string(),
                "weird.db".to_string()
            ]
        );
        // CLI exit-code path with the same flags: 0.
        let argv = vec![
            "--from-snapshot".to_string(),
            dir.to_string_lossy().into_owned(),
            "--account".to_string(),
            "default".to_string(),
            "--uin-hash".to_string(),
            sha12(pass.as_bytes()),
            "--key-file".to_string(),
            key.to_string_lossy().into_owned(),
            "--mapping".to_string(),
            map_path.to_string_lossy().into_owned(),
            "--shadow-copy".to_string(),
            store.to_string_lossy().into_owned(),
            "--delta".to_string(),
        ];
        assert_eq!(crate::shadow::cli::main(&argv), 0);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    #[cfg(windows)]
    fn run_mapping_dry_plan_errors_name_the_missing_column() {
        let dir = temp_dir("dryplan");
        let pass = "fakefakefakefakefakefakefake1234";
        let key = synthetic_snapshot_rich(&dir, pass);
        // A mapping referencing a column the fake schema does not
        // have: the dry run fails closed, listing exactly that.
        let bad = DRY_MAPPING_JSON.replace("\"msgId\": \"id\",", "\"msgId\": \"nope\",");
        let map_path = dir.join("mapping.json");
        std::fs::write(&map_path, bad).unwrap();
        let mut a = args_for(&dir, &sha12(pass.as_bytes()), Some(&key));
        a.mapping = Some(map_path);
        let e = run_mapping_dry(&a).unwrap_err();
        assert!(
            e.contains("mapping failed validation (1 error(s))"),
            "{e}"
        );
        assert!(
            e.contains("columns.msgId: column \"nope\" does not exist in table \"msg\""),
            "{e}"
        );
        // The CLI exit-code path: exit 1 with the same message.
        let argv = vec![
            "--from-snapshot".to_string(),
            dir.to_string_lossy().into_owned(),
            "--account".to_string(),
            "default".to_string(),
            "--uin-hash".to_string(),
            sha12(pass.as_bytes()),
            "--key-file".to_string(),
            key.to_string_lossy().into_owned(),
            "--mapping".to_string(),
            dir.join("mapping.json").to_string_lossy().into_owned(),
        ];
        assert_eq!(crate::shadow::cli::main(&argv), 1);
        let _ = std::fs::remove_dir_all(&dir);
    }

    // --- batch 14 N1: --distinct (end to end on synthetic snapshots) ----

    /// The fake Index.db schema for the --distinct fixture: one
    /// conversation-ish table with a whitelisted `isGroup` column.
    #[cfg(windows)]
    const INDEX_DB_SQL: &str = "CREATE TABLE conv (
        id INTEGER PRIMARY KEY, v TEXT, isGroup INTEGER
      );
      INSERT INTO conv (id, v, isGroup) VALUES (11, 'a', 0), (12, 'b', 1);";

    /// The fake Desktop message schema for the --distinct fixture:
    /// code columns carrying mixed INTEGER/TEXT/BLOB/NULL values,
    /// plus the content columns (`content`, `message`) the whitelist
    /// must refuse. Synthetic data only.
    #[cfg(windows)]
    const CODES_DB_SQL: &str = "CREATE TABLE message (
        msgId TEXT PRIMARY KEY, msgType INTEGER, status INTEGER,
        src INTEGER, cmd INTEGER, isLocalMsgId INTEGER, content TEXT, message TEXT
      );
      INSERT INTO message (msgId, msgType, status, src, cmd, isLocalMsgId, content, message) VALUES
        ('m1', 1, 0, 1, 0, 0, 'plain words here', 'plain words here'),
        ('m2', 1, 0, 1, 0, 0, 'more words here', 'more words here'),
        ('m3', 2, 1, 1, 551, 1, 'sentences have spaces', 'sentences have spaces'),
        ('m4', NULL, 0, NULL, NULL, NULL, 'x', 'x'),
        ('m5', 'chat.photo', 0, 1, 0, 0, 'y', 'y');
      INSERT INTO message (msgId, msgType, status) VALUES ('m6', x'00', 0);";

    /// A second one2one fixture with a DIFFERENT code distribution, so
    /// the `--all-dbs` sum is observable (batch 15 O2).
    #[cfg(windows)]
    const CODES_DB_SQL2: &str = "CREATE TABLE message (
        msgId TEXT PRIMARY KEY, msgType INTEGER, status INTEGER,
        src INTEGER, cmd INTEGER, isLocalMsgId INTEGER, content TEXT, message TEXT
      );
      INSERT INTO message (msgId, msgType, status, src, cmd, isLocalMsgId, content, message) VALUES
        ('n1', 1, 0, 1, 0, 0, 'aa', 'aa'),
        ('n2', 3, 0, 1, 0, 0, 'bb', 'bb'),
        ('n3', 3, 0, 1, 0, 0, 'cc', 'cc');";

    /// A synthetic snapshot whose Index.db and every message-DB kind
    /// carry the code-column fixture. Returns the key path.
    #[cfg(windows)]
    fn synthetic_snapshot_codes(dir: &Path, pass: &str) -> PathBuf {
        write_manifest_json(dir, valid_manifest_json());
        let core = dir.join("Core");
        std::fs::create_dir_all(core.join("Message")).unwrap();
        make_cipher_db_sql(&core.join("Index.db"), pass, INDEX_DB_SQL);
        for name in ["111.db", "g222.db", "stranger_box.db"] {
            make_cipher_db_sql(&core.join("Message").join(name), pass, CODES_DB_SQL);
        }
        for name in ["undefined.db", "weird.db"] {
            std::fs::write(core.join("Message").join(name), b"fake").unwrap();
        }
        let key = dir.join("d7.bin");
        fake_d7_key_file(&key, pass);
        key
    }

    /// ImportArgs with parsed `--distinct` specs for a synthetic snapshot.
    #[cfg(windows)]
    fn distinct_args(from: &Path, uin: &str, key: &Path, specs: &[&str]) -> ImportArgs {
        let mut a = args_for(from, uin, Some(key));
        a.distinct = specs
            .iter()
            .map(|s| super::distinct::parse_spec(s).unwrap())
            .collect();
        a
    }

    #[test]
    #[cfg(windows)]
    fn run_distinct_prints_code_values_only_and_writes_nothing() {
        let dir = temp_dir("dst");
        let pass = "fakefakefakefakefakefakefake1234";
        let key = synthetic_snapshot_codes(&dir, pass);
        let uin = sha12(pass.as_bytes());
        let a = distinct_args(
            &dir,
            &uin,
            &key,
            &[
                "one2one:message.msgType",
                "group:message.msgType",
                "stranger:message.status",
                "index:conv.isGroup",
            ],
        );
        let lines = run_distinct(&a).unwrap();
        let joined = lines.join("\n");
        // Headers name the kind, the column and the sample source (a
        // relative path — not data).
        assert!(
            joined.contains("distinct: one2one:message.msgType source=Core/Message/111.db"),
            "{joined}"
        );
        assert!(
            joined.contains("distinct: group:message.msgType source=Core/Message/g222.db"),
            "{joined}"
        );
        assert!(
            joined
                .contains("distinct: stranger:message.status source=Core/Message/stranger_box.db"),
            "{joined}"
        );
        assert!(
            joined.contains("distinct: index:conv.isGroup source=Core/Index.db"),
            "{joined}"
        );
        // msgType (mixed types in one column): the integer counts
        // first (count order), then the singles — the code-shaped TEXT
        // prints as the token, the blob prints its length only.
        assert!(joined.contains("  1 x 2"), "{joined}");
        for needle in [
            "  2 x 1", "  NULL x 1", "  chat.photo x 1", "  blob(len=1) x 1",
        ] {
            assert!(joined.contains(needle), "{needle} missing: {joined}");
        }
        // status: 0 x 5, 1 x 1. conv.isGroup: 0/1 only.
        assert!(joined.contains("  0 x 5"), "{joined}");
        assert!(joined.contains("  1 x 1"), "{joined}");
        // Privacy (the N1 point): the sentence content of `content`/
        // `message` never appears — those columns were never read, and
        // the only TEXT printed is the code-shaped one.
        assert!(!joined.contains("sentences"), "{joined}");
        assert!(!joined.contains("words"), "{joined}");
        // Immutable proof: nothing was created in the snapshot.
        let names = listing(&dir.join("Core").join("Message"));
        assert_eq!(
            names,
            vec![
                "111.db".to_string(),
                "g222.db".to_string(),
                "stranger_box.db".to_string(),
                "undefined.db".to_string(),
                "weird.db".to_string(),
            ]
        );
        // The CLI exit-code path: success → 0.
        let mut argv = vec![
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
        // A refused column through the same path: exit 1.
        argv.push("--distinct".into());
        argv.push("one2one:message.content".into());
        assert_eq!(crate::shadow::cli::main(&argv), 1);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    #[cfg(windows)]
    fn run_distinct_refuses_content_columns_naming_the_rule() {
        let dir = temp_dir("dstrf");
        let pass = "fakefakefakefakefakefakefake1234";
        let key = synthetic_snapshot_codes(&dir, pass);
        let uin = sha12(pass.as_bytes());
        // `content` and `message` are content-bearing: refused with
        // the rule quoted; no row is read.
        let a = distinct_args(&dir, &uin, &key, &["one2one:message.content"]);
        let e = run_distinct(&a).unwrap_err();
        assert!(e.contains("--distinct validation (1 error(s))"), "{e}");
        assert!(
            e.contains("column \"content\" is not on the code-column whitelist"),
            "{e}"
        );
        assert!(
            e.contains(&format!("rule: {}", super::distinct::CODE_COLUMN_RULE)),
            "{e}"
        );
        // Every violation at once (the plan convention): two refused
        // columns, a missing column, a missing table.
        let a = distinct_args(
            &dir,
            &uin,
            &key,
            &[
                "one2one:message.content",
                "group:message.message",
                "group:message.noCol",
                "stranger:zzz.msgType",
            ],
        );
        let e = run_distinct(&a).unwrap_err();
        assert!(e.contains("(4 error(s))"), "{e}");
        assert!(e.contains("column \"message\" is not on the code-column whitelist"), "{e}");
        assert!(e.contains("column \"noCol\" does not exist in table \"message\""), "{e}");
        assert!(e.contains("table \"zzz\" does not exist"), "{e}");
        assert!(
            e.contains("inventory Core/Message/g222.db") || e.contains("g222.db"),
            "{e}"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    // --- batch 15 O2: --distinct --all-dbs (end to end) -------------------

    #[test]
    #[cfg(windows)]
    fn run_distinct_all_dbs_sums_every_db_of_the_kind() {
        let dir = temp_dir("dstall");
        let pass = "fakefakefakefakefakefakefake1234";
        // Index + TWO one2one DBs with different distributions, one
        // group DB, one stranger DB, plus the skipped non-DBs.
        write_manifest_json(&dir, valid_manifest_json());
        let core = dir.join("Core");
        std::fs::create_dir_all(core.join("Message")).unwrap();
        make_cipher_db_sql(&core.join("Index.db"), pass, INDEX_DB_SQL);
        make_cipher_db_sql(&core.join("Message").join("111.db"), pass, CODES_DB_SQL);
        make_cipher_db_sql(&core.join("Message").join("112.db"), pass, CODES_DB_SQL2);
        make_cipher_db_sql(&core.join("Message").join("g222.db"), pass, CODES_DB_SQL);
        make_cipher_db_sql(&core.join("Message").join("stranger_box.db"), pass, CODES_DB_SQL);
        for name in ["undefined.db", "weird.db"] {
            std::fs::write(core.join("Message").join(name), b"fake").unwrap();
        }
        let key = dir.join("d7.bin");
        fake_d7_key_file(&key, pass);
        let uin = sha12(pass.as_bytes());

        let mut a = distinct_args(
            &dir,
            &uin,
            &key,
            &["one2one:message.msgType", "group:message.msgType"],
        );
        a.all_dbs = true;
        let lines = run_distinct(&a).unwrap();
        let joined = lines.join("\n");
        // one2one has TWO DBs: the header says so and the counts are
        // the SUM (111.db: 1 x 2, 2 x 1, NULL x 1, chat.photo x 1,
        // blob x 1; 112.db: 1 x 1, 3 x 2).
        assert!(
            joined.contains(
                "distinct: one2one:message.msgType source=ALL dbs=2 opened=2 failed=0"
            ),
            "{joined}"
        );
        assert!(joined.contains("  1 x 3"), "the summed count: {joined}");
        assert!(joined.contains("  3 x 2"), "{joined}");
        assert!(joined.contains("  2 x 1"), "{joined}");
        assert!(joined.contains("  chat.photo x 1"), "{joined}");
        // group has ONE DB: dbs=1, the same counts as the sample.
        assert!(
            joined.contains("distinct: group:message.msgType source=ALL dbs=1 opened=1 failed=0"),
            "{joined}"
        );
        assert!(joined.contains("  1 x 2"), "{joined}");
        // `undefined.db`/`weird.db` are never counted as DBs of a kind.
        assert!(!joined.contains("dbs=3"), "{joined}");
        // Privacy: the content columns were never read.
        assert!(!joined.contains("sentences"), "{joined}");
        assert!(!joined.contains("words"), "{joined}");
        // Immutable proof: nothing was created in the snapshot.
        let names = listing(&dir.join("Core").join("Message"));
        assert_eq!(
            names,
            vec![
                "111.db".to_string(),
                "112.db".to_string(),
                "g222.db".to_string(),
                "stranger_box.db".to_string(),
                "undefined.db".to_string(),
                "weird.db".to_string(),
            ]
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    // --- batch 15 O4: own-uid on the import path --------------------------

    #[test]
    fn own_uid_decision_env_wins_and_shapes_are_validated() {
        const FAKE_UID: &str = "1234567890123456789"; // never a real one
        // A valid env uid wins over any settings uid (per-run override).
        assert_eq!(
            own_uid_decision(Some(FAKE_UID), Some("9876543210987654321")).as_deref(),
            Some(FAKE_UID)
        );
        // Without env, the settings uid is used.
        assert_eq!(
            own_uid_decision(None, Some("9876543210987654321")).as_deref(),
            Some("9876543210987654321")
        );
        // A badly shaped candidate behaves as absent — account.rs's
        // rule: a bad config never becomes a sender.
        assert_eq!(
            own_uid_decision(Some("nope"), Some(FAKE_UID)).as_deref(),
            Some(FAKE_UID)
        );
        assert_eq!(own_uid_decision(Some("nope"), Some("1234")), None);
        assert_eq!(own_uid_decision(None, Some("")), None);
        assert_eq!(own_uid_decision(None, Some("bad-shape")), None);
        assert_eq!(own_uid_decision(None, None), None);
    }

    #[test]
    #[cfg(windows)]
    fn run_mapping_dry_reports_own_uid_shape_only() {
        let dir = temp_dir("dryown");
        let pass = "fakefakefakefakefakefakefake1234";
        let key = synthetic_snapshot_rich(&dir, pass);
        let map_path = dir.join("mapping.json");
        std::fs::write(&map_path, DRY_MAPPING_JSON).unwrap();
        let mut a = args_for(&dir, &sha12(pass.as_bytes()), Some(&key));
        a.mapping = Some(map_path);
        let lines = run_mapping_dry(&a).unwrap();
        let joined = lines.join("\n");
        // The own-uid line reports ONLY whether one was resolved —
        // the value never appears, whatever the environment carries.
        assert!(
            joined.contains("import dry-run: own_uid set: true")
                || joined.contains("import dry-run: own_uid set: false"),
            "{joined}"
        );
        assert!(!joined.contains("1234567890123456789"), "{joined}");
        let _ = std::fs::remove_dir_all(&dir);
    }

    // --- batch 16 P2: --media-plan (item 2.6, plan only) ------------------

    /// A synthetic Desktop-style cipher DB (cross-platform: the
    /// passphrase key needs no DPAPI).
    fn make_cipher_db_sql_any(path: &Path, pass: &str, sql: &str) {
        let conn = Connection::open_with_flags(
            path,
            rusqlite::OpenFlags::SQLITE_OPEN_READ_WRITE
                | rusqlite::OpenFlags::SQLITE_OPEN_CREATE,
        )
        .unwrap();
        apply_passphrase_key(&conn, pass).unwrap();
        conn.execute_batch(sql).unwrap();
        conn.close().map_err(|(_, e)| e).unwrap();
    }

    /// The media-plan fixture: Index.db with the three named media
    /// tables (+ a `conv` table that must be ignored) and a
    /// `Core/Media.db`, all carrying FAKE local paths that point at
    /// files under the OS temp dir. Returns (Prepared, files dir).
    fn media_fixture(dir: &Path, files: &Path) -> Prepared {
        let pass = "fakefakefakefakefakefakefake1234";
        std::fs::create_dir_all(files).unwrap();
        std::fs::write(files.join("a.jpg"), vec![0u8; 10]).unwrap();
        std::fs::write(files.join("b.mp4"), vec![0u8; 20]).unwrap();
        std::fs::create_dir_all(files.join("subdir")).unwrap(); // a dir, not a file
        let a = files.join("a.jpg").to_string_lossy().into_owned();
        let b = files.join("b.mp4").to_string_lossy().into_owned();
        let gone = files.join("gone.jpg").to_string_lossy().into_owned();
        let sub = files.join("subdir").to_string_lossy().into_owned();
        let core = dir.join("Core");
        std::fs::create_dir_all(&core).unwrap();
        let index_sql = format!(
            "CREATE TABLE image (id INTEGER PRIMARY KEY, filePath TEXT, thumbUrl TEXT);
             INSERT INTO image (id, filePath) VALUES
               (1, '{a}'), (2, '{gone}'), (3, 'https://fake-cdn.example/x.jpg'), (4, NULL);
             CREATE TABLE file (id INTEGER PRIMARY KEY, localPath TEXT);
             INSERT INTO file (id, localPath) VALUES (1, '{b}');
             CREATE TABLE media (id INTEGER PRIMARY KEY, path TEXT);
             INSERT INTO media (id, path) VALUES (1, 'relative/x.jpg'), (2, '{sub}');
             CREATE TABLE conv (id INTEGER PRIMARY KEY, name TEXT);",
        );
        make_cipher_db_sql_any(&core.join("Index.db"), pass, &index_sql);
        let media_sql = format!(
            "CREATE TABLE mediaItem (itemId INTEGER PRIMARY KEY, filePath TEXT);
             INSERT INTO mediaItem (itemId, filePath) VALUES (1, '{gone}');",
        );
        make_cipher_db_sql_any(&core.join("Media.db"), pass, &media_sql);
        Prepared {
            uid_dir: dir.to_path_buf(),
            passphrase: Zeroizing::new(pass.to_string()),
            profile: CipherProfile::Compat4,
            key_sha12: sha12(pass.as_bytes()),
        }
    }

    #[test]
    fn media_plan_counts_rows_files_volumes_and_savings() {
        let dir = temp_dir("mediaplan");
        let files = dir.join("files");
        let p = media_fixture(&dir, &files);
        // The store root on the SAME volume as the fake files (the
        // temp dir): every present file is hardlinkable, so the saved
        // bytes equal the total bytes.
        let store = dir.join("store-root");
        std::fs::create_dir_all(&store).unwrap();
        let r = media_plan(&p, &store).unwrap();
        // image: 2 rows (a.jpg present, gone missing; the url and the
        // NULL are not rows). file: 1 row (b.mp4 present). media: 1
        // row (the subdir — exists but is NOT a file → missing; the
        // relative path is not a row). Media.db mediaItem: 1 row
        // (missing). conv: ignored (not a media name, no Index rule).
        assert_eq!(r.rows, 5, "{r:?}");
        assert_eq!(r.present, 2);
        assert_eq!(r.missing, 3);
        assert_eq!(r.total_bytes, 30);
        assert_eq!(r.same_volume, 2, "the temp store shares the files' volume");
        assert_eq!(r.other_volume, 0);
        assert_eq!(r.bytes_saved_vs_copy, 30);
        assert_eq!(r.dbs_failed, 0);
        let tables: Vec<String> = r.tables.iter().map(|t| t.table.clone()).collect();
        // inventory_db lists tables name-sorted.
        assert_eq!(tables, vec!["file", "image", "media", "mediaItem"], "{r:?}");
        assert!(r.tables[1].source == "Core/Index.db");
        assert!(r.tables[3].source == "Core/Media.db");
        // A store root on ANOTHER drive (pure drive-letter comparison,
        // no FS access needed): every present file is on the other
        // volume, so hardlinking would save nothing.
        let r2 = media_plan(&p, Path::new(r"Q:\fake-store-root")).unwrap();
        assert_eq!(r2.rows, 5);
        assert_eq!(r2.present, 2);
        assert_eq!(r2.total_bytes, 30, "bytes do not depend on the store");
        assert_eq!(r2.same_volume, 0);
        assert_eq!(r2.other_volume, 2);
        assert_eq!(r2.bytes_saved_vs_copy, 0);
        // No Media.db at all: only the Index tables, no failure.
        std::fs::remove_file(dir.join("Core").join("Media.db")).unwrap();
        let r3 = media_plan(&p, &store).unwrap();
        assert_eq!(r3.rows, 4);
        assert_eq!(r3.tables.len(), 3);
        assert_eq!(r3.dbs_failed, 0);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    #[cfg(windows)]
    fn run_media_plan_prints_counts_only() {
        // The CLI path: manifest + D7 key + the usual guards, then the
        // same counts (the store root is resolved from the settings —
        // only the volume split is machine-dependent, so the asserted
        // prefix stops before it).
        let dir = temp_dir("mediarun");
        let files = dir.join("files");
        let p = media_fixture(&dir, &files);
        // The manifest the snapshot guard requires + the D7 key for
        // the fixture passphrase.
        write_manifest_json(&dir, valid_manifest_json());
        let pass = p.passphrase.as_str().to_string();
        fake_d7_key_file(&dir.join("d7.bin"), &pass);
        let mut a = args_for(&dir, &sha12(pass.as_bytes()), Some(&dir.join("d7.bin")));
        a.media_plan = true;
        let lines = run_media_plan(&a).unwrap();
        let joined = lines.join("\n");
        assert!(
            joined.contains("media plan: dry-run — no hashing, no hardlinks, nothing written"),
            "{joined}"
        );
        assert!(
            joined.contains("media plan: Core/Index.db table image (path column \"filePath\")"),
            "{joined}"
        );
        assert!(
            joined.contains("media plan: Core/Media.db table mediaItem (path column \"filePath\")"),
            "{joined}"
        );
        assert!(
            joined.contains("media plan: rows=5 present=2 missing=3 total_bytes=30 same_volume=yes:"),
            "{joined}"
        );
        // PRIVACY: no path value, no file name, no url ever printed.
        assert!(!joined.contains("a.jpg"), "{joined}");
        assert!(!joined.contains("b.mp4"), "{joined}");
        assert!(!joined.contains("fake-cdn"), "{joined}");
        assert!(!joined.contains(dir.to_string_lossy().as_ref()), "{joined}");
        // The snapshot was never touched (immutable proof).
        let names = listing(&dir.join("Core"));
        assert_eq!(names, vec!["Index.db".to_string(), "Media.db".to_string()]);
        // The CLI exit-code path: 0.
        let argv = vec![
            "--from-snapshot".to_string(),
            dir.to_string_lossy().into_owned(),
            "--account".to_string(),
            "default".to_string(),
            "--uin-hash".to_string(),
            sha12(pass.as_bytes()),
            "--key-file".to_string(),
            dir.join("d7.bin").to_string_lossy().into_owned(),
            "--media-plan".to_string(),
        ];
        assert_eq!(crate::shadow::cli::main(&argv), 0);
        let _ = std::fs::remove_dir_all(&dir);
    }
}
