//! Process-wide shadow state and the single writer thread (rebuild).
//!
//! Layout (unchanged from the lost implementation; the surviving probes
//! depend on it):
//! ```text
//! %LOCALAPPDATA%\com.o365serveronms.zalors\shadow\
//!   default.db        SQLCipher shadow DB (WAL)
//!   default.key       DPAPI-wrapped 32-byte key (raw mode)
//!   default.uin       account marker (legacy file, kept untouched)
//!   default.keymode.json     passphrase-mode marker, batch 18 (no secrets)
//!   default.pass.dpapi       DPAPI "remember on this machine" wrap, batch 18
//!   default.key.pre-passphrase  the renamed raw key after a conversion
//! ```
//!
//! Delivery paths (all end on the SAME mpsc queue; the flusher thread is
//! the only DB writer):
//! - `capture::deliver_ws` / `deliver_rest` — CDP network events.
//! - `deliver_e2ee` — the bridge tap's plaintext (command
//!   `shadow_e2ee_message`, ACL chat.zalo.me, 512 KB cap).
//! - `set_rest_key` — the bridge handshake (`shadow_handshake`) handing
//!   over the page's REST decode key; it lives in RAM only.
//! - `Job::MediaDone` — the media thread's download outcomes (T3/A5:
//!   the media connection is READ-ONLY; only the flusher writes).
//! - `Job::Backup` — the backup thread's scheduled request (batch 8
//!   H4): the flusher runs the DB export on its own connection (A5)
//!   and reports the outcome back on a one-shot channel.
//!
//! The WS per-connection AES key is harvested from frame `cmd=1 subCmd=1`
//! the same way and never touches disk (redacted before `raw_events`).
//! Since audit M4 (batch 4) keys are PER-CONNECTION, keyed by the CDP
//! requestId tag the capture layer attaches to every frame — the tag
//! lives in RAM only, is never logged or stored, and its key is wiped
//! when the connection closes (`Job::WsClosed`, D2).

use std::path::PathBuf;
use std::sync::mpsc::{channel, Receiver, Sender};
use std::time::Duration;

use serde_json::Value;
use tauri::Manager;
use zeroize::{Zeroize, Zeroizing};

use super::account::{self, UidEvent};
use super::bounded::{BoundedMap, Inserted};
use super::passphrase::StoreKeyMode;
use super::pipeline;
use super::rest_stats::{self, RestStage};
use super::ws_stats::{self, WsStage};
use super::{schema, wire, writer};
use crate::migrate::sqlcipher;
use crate::settings::{ShadowSettings, Settings};

/// Managed state: just the queue handle (Send + Sync).
pub struct Shadow {
    tx: Sender<Job>,
}

/// Jobs on the single writer queue. `MediaDone` carries the media
/// thread's download outcomes back to the flusher (T3/A5: the media
/// thread holds a READ-ONLY connection and never writes the DB itself).
///
/// D2 (audit M4): WS frames carry a connection tag — the CDP
/// requestId string. It stays in RAM, is never logged or stored, and
/// keys the flusher's per-connection decode map; `WsClosed` drops that
/// connection's key.
///
/// `Backup` (batch 8 H4, audit 4.1): the backup thread asks the
/// flusher to run the DB export on the ONLY RW connection (A5); the
/// outcome comes back on the one-shot `respond` channel, so the backup
/// thread can log the run's single line and do the media half itself
/// (batch 10 J4: the on-exit backup drives the same variant through
/// `runtime::request_backup`).
///
/// The four `Passphrase*` jobs (batch 18, brief R2/R3) run the store's
/// key-mode conversions on the flusher — it is the single writer, so a
/// rekey is naturally serialized with every batch write. The passwords
/// ride the queue in `Zeroizing<String>` (RAM only), the replies are
/// kind-only error strings, and a wrong password never gets this far
/// (the command layer proves it first). On a SUCCESSFUL set/change/
/// remove the flusher also publishes the new key into the shared key
/// cell (F2, `shadow::passphrase::publish_key`) so the media thread's
/// next cycle and the archive window's cached session re-open with it.
pub(crate) enum Job {
    WsFrame { bytes: Vec<u8>, conn: String, direction: &'static str },
    /// A tracked WS connection closed: wipe its per-connection key.
    WsClosed { conn: String },
    RestBody { endpoint: String, body: Vec<u8>, direction: &'static str },
    E2ee { payload: String },
    Handshake { key_b64: String, uid: Option<String> },
    MediaDone { rowid: i64, outcome: writer::MediaOutcome },
    /// Run one DB backup on the flusher's connection (H4). The flusher
    /// already holds the shadow dir (it is a `flusher` parameter) and
    /// reloads the key file itself; the outcome comes back on the
    /// one-shot `respond` channel.
    Backup { respond: Sender<super::backup::DbBackupOutcome> },
    /// Convert the store raw → passphrase (batch 18 R3). Requires raw
    /// mode + a running flusher; the engine pre-backs-up with the OLD
    /// raw key, journals down, rekeys, verifies, then flips the marker.
    PassphraseSet {
        passphrase: Zeroizing<String>,
        remember: bool,
        respond: Sender<Result<(), String>>,
    },
    /// Change the passphrase. The command layer already proved `old`
    /// opens the DB; `old` rides along for the engine's recovery path.
    PassphraseChange {
        old: Zeroizing<String>,
        new: Zeroizing<String>,
        remember: bool,
        respond: Sender<Result<(), String>>,
    },
    /// Remove the password: rekey back to a fresh random raw key.
    PassphraseRemove {
        current: Zeroizing<String>,
        respond: Sender<Result<(), String>>,
    },
    /// "Nhớ trên máy này" toggle: save (needs the flusher's RAM copy of
    /// the passphrase) or delete the remember file.
    PassphraseRemember {
        on: bool,
        respond: Sender<Result<(), String>>,
    },
}

/// Resolve the shadow directory for this install.
///
/// LEGACY-COMPAT (verified 2026-11-19): the pre-rebuild DB, the surviving
/// probes and the handoff all use
/// `%LOCALAPPDATA%\com.o365serveronms.zalors\shadow`. Tauri v2's
/// `app_data_dir()` resolves to **Roaming** on Windows, which silently
/// created a second DB there during the first live run — so the path is
/// pinned to LOCALAPPDATA explicitly.
pub fn shadow_dir(app: &tauri::AppHandle) -> PathBuf {
    let _ = app; // kept for signature stability; the path is OS-fixed
    let local = std::env::var_os("LOCALAPPDATA").unwrap_or_default();
    PathBuf::from(local).join("com.o365serveronms.zalors/shadow")
}

/// Boot the pipeline if enabled in settings. Idempotent: a second call is
/// a no-op (the running state is already managed).
///
/// Batch 18 (R2): raw mode is unchanged. In passphrase mode the store
/// boots only when the remember file exists AND opens the DB; otherwise
/// the pipeline does NOT start — the log says the store is locked and
/// the shadow-unlock window asks for the password (capture while locked
/// is dropped by design: without a DB there is nowhere to land).
pub fn start(app: &tauri::AppHandle) {
    if app.try_state::<Shadow>().is_some() {
        return;
    }
    let s = crate::settings::load(app);
    if !s.shadow.enabled {
        crate::dlog::log("shadow: disabled in settings");
        return;
    }
    let dir = shadow_dir(app);
    match open_db(&dir, &s.shadow) {
        Ok(Some(opened)) => boot_pipeline(app, dir, s, opened),
        Ok(None) => {
            crate::dlog::log("shadow: store locked (passphrase mode) — waiting for unlock");
            crate::window::open_shadow_unlock_window(app);
        }
        Err(e) => {
            crate::dlog::log(&format!("shadow: FAILED to start ({e})"));
        }
    }
}

/// Boot the pipeline after a successful `shadow_unlock` (R2). The
/// command layer already PROVED `passphrase` opens the DB; this opens it
/// again as the flusher's connection, optionally saving the remember
/// file first, and reuses every start step (media, backup thread,
/// managed state). Idempotent like [`start`].
pub fn start_unlocked(
    app: &tauri::AppHandle,
    passphrase: Zeroizing<String>,
    remember: bool,
) -> Result<(), String> {
    if app.try_state::<Shadow>().is_some() {
        return Ok(());
    }
    let s = crate::settings::load(app);
    if !s.shadow.enabled {
        return Err("disabled".into());
    }
    let dir = shadow_dir(app);
    if super::passphrase::read_mode(&dir) != StoreKeyMode::Passphrase {
        // Someone removed the password while the prompt was open, or
        // the marker vanished: refuse rather than open a store whose
        // mode disagrees with the prompt.
        return Err("not-passphrase".into());
    }
    if remember {
        super::passphrase::save_remembered(&dir, &passphrase)
            .map_err(|_| "remember".to_string())?;
    }
    let db_path = super::db_file(&dir);
    let conn = sqlcipher::open_with_passphrase(&db_path, &passphrase)
        .map_err(|e| e.to_string())?;
    schema::apply(&conn).map_err(|e| e.to_string())?;
    boot_pipeline(
        app,
        dir,
        s,
        OpenedDb { conn, pass_ram: Some(passphrase) },
    );
    Ok(())
}

/// Everything after the DB is open (identical for both key modes): the
/// flusher thread, the media downloader, the managed queue handle, the
/// optional backup thread.
fn boot_pipeline(app: &tauri::AppHandle, dir: PathBuf, s: Settings, opened: OpenedDb) {
    let (tx, rx) = channel::<Job>();
    let media_cfg = s.shadow.clone();
    // H4 (batch 8): the backup thread starts ONLY when the user
    // turned backups on AND chose a folder — the feature is
    // OFF by default (`backup_enabled: false`).
    let backup_cfg = s.shadow.clone();
    let flusher_dir = dir.clone();
    let flusher_pass = opened.pass_ram.clone();
    let flusher_cfg = s.shadow.clone();
    std::thread::Builder::new()
        .name("shadow-flusher".into())
        .spawn(move || flusher(opened.conn, flusher_dir, flusher_pass, rx, flusher_cfg))
        .ok();
    let media_tx = tx.clone();
    let backup_tx = tx.clone();
    app.manage(Shadow { tx });
    // P1b/T3: media auto-download on a READ-ONLY connection;
    // every status flip it triggers flows back through the same
    // job queue so the flusher stays the only DB writer. F2 (batch
    // 18 review): the thread opens its connection per CYCLE with the
    // shared key cell's CURRENT value — after a set/change/remove it
    // picks the new key up without an app restart.
    super::media::start(dir.clone(), media_cfg, media_tx);
    // P4/H4: scheduled backups — the flusher owns the only RW
    // connection (A5), so the DB half arrives as `Job::Backup`
    // and the media half runs on the backup thread (read-only
    // on the store).
    if backup_cfg.backup_enabled && backup_cfg.backup_dir.is_some() {
        super::backup::start_backup_thread(backup_cfg, backup_tx);
        crate::dlog::log("shadow: backup thread started");
    }
    crate::dlog::log(if opened.pass_ram.is_some() {
        "shadow: pipeline started (capture mode cdp, passphrase mode)"
    } else {
        "shadow: pipeline started (capture mode cdp)"
    });
}

/// An open shadow DB plus the RAM copy of the passphrase when the mode
/// is `passphrase` (the flusher keeps it for backups and the remember
/// toggle; raw mode wipes its key bytes after open per L4/D4).
struct OpenedDb {
    conn: rusqlite::Connection,
    pass_ram: Option<Zeroizing<String>>,
}

/// Open (or create) the encrypted shadow DB and apply the schema.
///
/// `Ok(None)` = passphrase mode with no usable remember file: the store
/// is LOCKED (the caller logs and shows the unlock prompt). Raw mode is
/// byte-for-byte the pre-batch-18 path.
fn open_db(dir: &PathBuf, cfg: &ShadowSettings) -> Result<Option<OpenedDb>, String> {
    let _ = std::fs::create_dir_all(dir);
    // KQ10: every path through the shadow store goes through the
    // account helpers — nothing hardcodes "default" here anymore.
    let db_path = super::db_file(dir);
    let key_path = super::key_file(dir);
    if !cfg.encrypt {
        let conn = rusqlite::Connection::open(&db_path).map_err(|e| e.to_string())?;
        // H3: every connection waits instead of erroring on a busy DB.
        conn.busy_timeout(Duration::from_millis(sqlcipher::BUSY_TIMEOUT_MS))
            .map_err(|e| e.to_string())?;
        schema::apply(&conn).map_err(|e| e.to_string())?;
        return Ok(Some(OpenedDb { conn, pass_ram: None }));
    }
    match super::passphrase::read_mode(dir) {
        StoreKeyMode::Raw => {
            if !key_path.exists() {
                // L4/D4: the generated key bytes are wiped after the
                // DPAPI wrap; the wrapped file never holds the raw key.
                let key = Zeroizing::new(
                    sqlcipher::generate_key().map_err(|e| e.to_string())?,
                );
                sqlcipher::save_key(&key, &key_path).map_err(|e| e.to_string())?;
            }
            // L4/D4: the loaded key bytes are wiped once the connection
            // holds them (SQLCipher keeps its own copy; the Rust-side Vec
            // must not linger).
            let key =
                Zeroizing::new(sqlcipher::load_key(&key_path).map_err(|e| e.to_string())?);
            let conn = sqlcipher::open_with_key(&db_path, &key).map_err(|e| e.to_string())?;
            schema::apply(&conn).map_err(|e| e.to_string())?;
            Ok(Some(OpenedDb { conn, pass_ram: None }))
        }
        StoreKeyMode::Passphrase => {
            // R2: the remember file is the only unattended source. A
            // missing file or one that no longer opens (the password
            // changed) is the same user situation: locked, ask again.
            let pw = match super::passphrase::load_remembered(dir) {
                Ok(p) => p,
                Err(_) => return Ok(None),
            };
            match sqlcipher::open_with_passphrase(&db_path, &pw) {
                Ok(conn) => {
                    schema::apply(&conn).map_err(|e| e.to_string())?;
                    Ok(Some(OpenedDb { conn, pass_ram: Some(pw) }))
                }
                // A stale remember wrap behaves like no remember file.
                Err(sqlcipher::KeyError::WrongPassword) => Ok(None),
                Err(e) => Err(e.to_string()),
            }
        }
        StoreKeyMode::Unknown => Err("unknown key mode marker".into()),
    }
}

/// Cap for the per-connection key map (D2/M4): keys are keyed by the
/// CDP requestId, so overlapping reconnects each get their own. The
/// map is bounded — past the cap the OLDEST entry is evicted (never
/// the newest, never a wholesale drain; every evicted key is
/// zeroized). R1 (batch 4 review) fixed the comment that used to
/// claim "a connection re-arms its key on its next cmd=1 subCmd=1
/// frame": the WS key is sent ONCE per connection (cmd=1 subCmd=1 at
/// connect), so an evicted connection stays undecoded until it
/// reconnects — evictions are counted (`ws_stats::KeysEvicted`) to
/// make that visible instead of silent.
const WS_KEYS_CAP: usize = 16;

/// The flusher thread: owns the DB connection and both runtime keys.
/// `dir` is the shadow store dir (the `Job::Backup` handler needs it
/// for the DPAPI key file — batch 8 H4). `pass_ram` (batch 18) is the
/// RAM copy of the passphrase in passphrase mode — held only for
/// passphrase-mode backups and the remember toggle, never logged, and
/// wiped on shutdown with every other key.
fn flusher(
    conn: rusqlite::Connection,
    dir: PathBuf,
    pass_ram_init: Option<Zeroizing<String>>,
    rx: Receiver<Job>,
    cfg: ShadowSettings,
) {
    // Batch 18: the passphrase the flusher holds in RAM (None in raw
    // mode; set on unlock, kept in step with the conversion jobs).
    let mut pass_ram = pass_ram_init;
    // F2 (batch-18 review): publish the boot key into the process-wide
    // shared key cell. The cell is written ONLY on this thread (the
    // single writer): here at boot — which covers the unlock path,
    // `start_unlocked` boots through here — and after every successful
    // conversion below. Every publish bumps the epoch, so the media
    // cycle and the archive window re-open with the CURRENT key.
    super::passphrase::publish_key(pass_ram.clone());
    // D2 (audit M4): one key PER CONNECTION, not one global —
    // overlapping reconnects used to decode with the wrong key.
    // R1: insertion-ordered bounded map — the OLDEST key is evicted
    // at the cap, never the live one, never the whole map.
    let mut ws_keys: BoundedMap<String, [u8; 16]> = BoundedMap::new(WS_KEYS_CAP);
    let mut rest_key: Option<[u8; 16]> = None;
    // D1 (KQ2): the own uid is configuration, not a guess — seed it
    // from settings; the handshake only cross-checks afterwards.
    let mut own_uid: Option<String> = None;
    match cfg.own_uid.as_deref() {
        Some(u) if account::valid_uid(u) => {
            own_uid = Some(u.to_string());
            crate::dlog::log(&format!("shadow: own uid configured (len {})", u.len()));
        }
        Some(_) => {
            crate::dlog::log("shadow: own uid config rejected (bad shape)");
        }
        None => {}
    }
    // D1 (KQ2/KQ10): fill the `accounts` row once at start, inside its
    // own small transaction. A uid without a uin_hash skips the row —
    // a hash is never invented.
    if let Some(uid) = own_uid.as_deref() {
        match cfg.own_uin_hash.as_deref().filter(|h| account::valid_uin_hash(h)) {
            Some(h) => seed_account_row(&conn, uid, h),
            None => {
                crate::dlog::log("shadow: accounts row skipped (uin_hash not configured)");
            }
        }
    }
    // D1: `shadow: own uid mismatch (configured kept)` fires at most
    // once per process, whatever the handshake keeps offering.
    let mut uid_mismatch_logged = false;
    let batch_ms = Duration::from_millis(cfg.batch_ms.max(20));
    'outer: loop {
        let first = match rx.recv_timeout(batch_ms) {
            Ok(j) => j,
            Err(std::sync::mpsc::RecvTimeoutError::Timeout) => continue,
            Err(std::sync::mpsc::RecvTimeoutError::Disconnected) => break 'outer,
        };
        let mut jobs: Vec<Job> = vec![first];
        while jobs.len() < cfg.batch_max {
            match rx.recv_timeout(Duration::from_millis(1)) {
                Ok(j) => jobs.push(j),
                Err(_) => break,
            }
        }
        // Handshakes first (they arm the decode keys for the rest).
        let mut items: Vec<pipeline::Incoming> = Vec::with_capacity(jobs.len());
        // T3: media outcomes are applied inside the same batch
        // transaction (the flusher is the single writer).
        let mut media: Vec<(i64, writer::MediaOutcome)> = Vec::new();
        for job in jobs {
            match job {
                Job::Handshake { key_b64, uid } => {
                    // L4/D4: the b64 form of the key is key material
                    // too — wiped once the decode is done.
                    let key_b64 = zeroize::Zeroizing::new(key_b64);
                    if let Some(k) = wire::decode_key_field(&key_b64) {
                        // L4/D4: a replaced key is wiped, not dropped.
                        if let Some(mut old) = rest_key.replace(k) {
                            old.zeroize();
                        }
                        crate::dlog::log("shadow: rest decode key armed (len 16)");
                    } else {
                        crate::dlog::log("shadow: handshake key rejected (bad shape)");
                    }
                    // D1 (KQ2): a configured uid ALWAYS wins; the
                    // handshake's uid only cross-checks.
                    let (resolved, ev) = account::resolve_own_uid(
                        cfg.own_uid.as_deref(),
                        own_uid.as_deref(),
                        uid.as_deref(),
                    );
                    match ev {
                        UidEvent::Learned => {
                            own_uid = resolved;
                            crate::dlog::log(&format!(
                                "shadow: own uid learned (len {})",
                                own_uid.as_deref().map_or(0, |u| u.len())
                            ));
                        }
                        UidEvent::Mismatch => {
                            own_uid = resolved;
                            if !uid_mismatch_logged {
                                uid_mismatch_logged = true;
                                // No values, ever (H-rule).
                                crate::dlog::log("shadow: own uid mismatch (configured kept)");
                            }
                        }
                        UidEvent::Same => {}
                    }
                }
                Job::WsFrame { bytes, conn: ws_conn, direction } => {
                    let Some(frame) = wire::parse_ws_frame(&bytes) else {
                        continue;
                    };
                    if let Some(k) = wire::ws_frame_key(&frame) {
                        // D2/M4 + L4/D4 + R1: per-connection key,
                        // insertion-ordered bounded map — the OLDEST
                        // key is evicted (and wiped), never the live
                        // connection's, never the whole map.
                        match ws_keys.insert(ws_conn.clone(), k) {
                            Inserted::Kept => {}
                            // L4/D4: a replaced key is wiped, not dropped.
                            Inserted::Replaced(mut old) => old.zeroize(),
                            Inserted::Evicted(_, mut old) => {
                                old.zeroize();
                                ws_stats::bump(WsStage::KeysEvicted);
                            }
                        }
                        ws_stats::set_keys(ws_keys.len() as u64);
                        crate::dlog::log("shadow: ws connection key armed (len 16)");
                    }
                    // The conn tag keys the lookup ONLY — it never
                    // reaches `endpoint` or the stored envelope.
                    let mut decoded = wire::decode_ws_frame(&frame, ws_keys.get(&ws_conn));
                    if let wire::WsDecoded::Envelope(ref mut env) = decoded {
                        wire::redact_key_in_envelope(env);
                    }
                    items.push(pipeline::Incoming {
                        kind: "ws",
                        direction,
                        endpoint: format!("ws:{}/{}", frame.cmd, frame.sub_cmd),
                        env: decoded.stored_value(),
                    });
                }
                Job::WsClosed { conn: ws_conn } => {
                    // D2/M4 + L4/D4: the connection is gone — its key
                    // is wiped, not just dropped.
                    if let Some(mut old) = ws_keys.remove(&ws_conn) {
                        old.zeroize();
                        ws_stats::set_keys(ws_keys.len() as u64);
                    }
                }
                Job::RestBody { endpoint, body, direction } => {
                    let outer: Value = match serde_json::from_slice(&body) {
                        Ok(v) => v,
                        Err(_) => {
                            // C2 (batch 3): this used to `continue`
                            // silently — audit H2 had no way to tell
                            // which stage dropped the bodies. Counted,
                            // never logged per item.
                            rest_stats::bump(RestStage::OuterJsonErr);
                            continue;
                        }
                    };
                    let env = wire::rest_envelope(&endpoint, &outer, rest_key.as_ref());
                    // C2: decoded / undecoded / no-key buckets from the
                    // envelope's `undecoded` flag (counts only).
                    rest_stats::bump_rest_decode(&outer, &env);
                    items.push(pipeline::Incoming {
                        kind: "rest",
                        direction,
                        endpoint: super::capture::safe_endpoint(&endpoint),
                        env,
                    });
                }
                Job::E2ee { payload } => {
                    let Ok(v) = serde_json::from_str::<Value>(&payload) else {
                        continue;
                    };
                    items.push(pipeline::Incoming {
                        kind: "e2ee",
                        direction: "in",
                        endpoint: "e2ee:bridge".into(),
                        env: v,
                    });
                }
                Job::MediaDone { rowid, outcome } => media.push((rowid, outcome)),
                // H4 (batch 8, audit 4.1): the DB export runs on THIS
                // thread — it owns the only RW connection (A5) —
                // serialized with every batch write. The media half of
                // the run is the backup thread's (read-only on the
                // store); the outcome goes back on the one-shot channel
                // so that thread can log the run's single line.
                // Batch 18: in passphrase mode the export key is the
                // flusher's RAM passphrase (backup = portable, opened
                // by the password alone).
                Job::Backup { respond } => {
                    let outcome = super::backup::run_db_backup(
                        &conn,
                        &dir,
                        &cfg,
                        pass_ram.as_ref().map(|p| p.as_str()),
                    );
                    let _ = respond.send(outcome);
                }
                // Batch 18 R3: the key-mode conversions run here (the
                // single writer) — batch writes simply queue behind the
                // job. Replies are kind-only; the passwords themselves
                // never reach a log line or an error string.
                Job::PassphraseSet { passphrase, remember, respond } => {
                    let now = schema::now_ms();
                    let outcome = super::passphrase::set_passphrase(
                        &conn,
                        &dir,
                        &passphrase,
                        remember,
                        now,
                    );
                    if outcome.is_ok() {
                        pass_ram = Some(passphrase);
                        // F2: the epoch bump makes every in-process
                        // reader re-open with the new key.
                        super::passphrase::publish_key(pass_ram.clone());
                    }
                    let _ = respond.send(outcome);
                }
                Job::PassphraseChange { old, new, remember, respond } => {
                    // `old` (the flusher's own RAM copy, handed back by
                    // the command for exactly this) is the recovery key
                    // the engine rekeys back to when verification fails.
                    let outcome = super::passphrase::change_passphrase(
                        &conn,
                        &dir,
                        Some(old.as_str()),
                        &new,
                        remember,
                    );
                    if outcome.is_ok() {
                        pass_ram = Some(new);
                        super::passphrase::publish_key(pass_ram.clone());
                    }
                    let _ = respond.send(outcome);
                }
                Job::PassphraseRemove { current, respond } => {
                    let outcome =
                        super::passphrase::remove_passphrase(&conn, &dir, &current);
                    if outcome.is_ok() {
                        pass_ram = None;
                        // F2: raw mode is the cell's None value — the
                        // media cycle's next open reads default.key.
                        super::passphrase::publish_key(None);
                    }
                    let _ = respond.send(outcome);
                }
                Job::PassphraseRemember { on, respond } => {
                    let outcome = if on {
                        match pass_ram.as_deref() {
                            Some(pw) => {
                                super::passphrase::save_remembered(&dir, pw)
                                    .map_err(|_| "remember".to_string())
                            }
                            // No RAM copy (raw mode, or locked): the
                            // toggle cannot save what it does not hold.
                            None => Err("not-running".to_string()),
                        }
                    } else {
                        super::passphrase::forget_remembered(&dir)
                            .map_err(|_| "forget".to_string())
                    };
                    let _ = respond.send(outcome);
                }
            }
        }
        if items.is_empty() && media.is_empty() {
            continue;
        }
        let s = pipeline::process_batch(&conn, &items, &media, cfg.raw_events_days, own_uid.as_deref());
        if s.raw_events > 0 {
            crate::dlog::log(&format!(
                "shadow batch: raw={} msgs={} convs={} groups={} contacts={} other={}",
                s.raw_events, s.messages, s.conversations, s.groups, s.contacts, s.other_writes
            ));
        }
        // T2/H3: per-item write failures are no longer swallowed — log
        // the count and the failing write kind + rusqlite error code
        // only (no SQL params, no payload, ever). F3: the kinds are
        // aggregated (kind → count), so even a 500-failure batch logs
        // one bounded line.
        if s.write_errors > 0 {
            crate::dlog::log(&format!(
                "shadow write errors: {} (kinds: {})",
                s.write_errors,
                s.format_error_kinds()
            ));
        }
    }
    // L4/D4: shutdown wipes every live key instead of leaving them in
    // freed heap (BoundedMap hands every entry back via IntoIterator).
    for (_, mut k) in ws_keys {
        k.zeroize();
    }
    if let Some(mut k) = rest_key.take() {
        k.zeroize();
    }
    // Batch 18: the RAM passphrase dies with the flusher, wiped.
    if let Some(mut p) = pass_ram.take() {
        p.zeroize();
    }
    let _ = conn.execute_batch("PRAGMA wal_checkpoint(TRUNCATE);");
}

/// D1 (KQ2/KQ10): the flusher-start `accounts` upsert, in its own
/// small transaction.
///
/// R3 (batch 4 review): COMMIT only when `BEGIN IMMEDIATE` succeeded
/// (the old code ignored the BEGIN result and committed regardless —
/// after a failed BEGIN the COMMIT landed someone ELSE's open
/// transaction), and on an upsert error ROLLBACK instead of COMMIT.
/// Logs the write kind only (H-rule): sqlite messages can quote SQL
/// params, so the error text itself never reaches the log.
fn seed_account_row(conn: &rusqlite::Connection, uid: &str, uin_hash: &str) {
    if conn.execute_batch("BEGIN IMMEDIATE").is_err() {
        // No transaction of ours is open: committing here would land
        // a foreign one. Kind only, no params (H-rule).
        crate::dlog::log("shadow: accounts upsert failed (begin)");
        return;
    }
    match account::upsert_account(conn, uid, uin_hash) {
        Ok(()) => {
            let _ = conn.execute_batch("COMMIT");
        }
        Err(e) => {
            // Kind only (H-rule): sqlite messages can quote params.
            crate::dlog::log(&format!(
                "shadow: accounts upsert failed ({})",
                pipeline::sqlite_kind(&e)
            ));
            let _ = conn.execute_batch("ROLLBACK");
        }
    }
}

/// Deliver a raw WS frame (CDP) for connection `conn` — the CDP
/// requestId string. It rides the job queue in RAM only, keys the
/// flusher's per-connection decode map, and is never logged or stored
/// (D2/M4). Binary bytes exactly as seen on the wire.
pub fn deliver_ws(app: &tauri::AppHandle, bytes: Vec<u8>, conn: String, direction: &'static str) {
    if let Some(sh) = app.try_state::<Shadow>() {
        let _ = sh.tx.send(Job::WsFrame { bytes, conn, direction });
    }
}

/// A tracked WS connection closed (CDP `Network.webSocketClosed`): the
/// flusher drops — and wipes — that connection's decode key (D2/M4).
/// `conn` is the CDP requestId; RAM only, never logged or stored.
pub fn ws_closed(app: &tauri::AppHandle, conn: String) {
    if let Some(sh) = app.try_state::<Shadow>() {
        let _ = sh.tx.send(Job::WsClosed { conn });
    }
}

/// Deliver a raw REST response body (CDP) with its URL as endpoint.
pub fn deliver_rest(
    app: &tauri::AppHandle,
    endpoint: String,
    body: Vec<u8>,
    direction: &'static str,
) {
    if let Some(sh) = app.try_state::<Shadow>() {
        let _ = sh.tx.send(Job::RestBody { endpoint, body, direction });
    }
}

/// Deliver one E2EE plaintext message from the bridge tap. The command
/// layer already enforced the ACL and the 512 KB cap.
pub fn deliver_e2ee(app: &tauri::AppHandle, payload: String) {
    if let Some(sh) = app.try_state::<Shadow>() {
        let _ = sh.tx.send(Job::E2ee { payload });
    }
}

/// Arm the REST decode key from the bridge handshake, and learn the
/// logged-in account's uid for self-sent sender substitution. Neither
/// value ever enters logs or the DB. Since D1 (KQ2) the learned uid is
/// only a cross-check: a uid configured in settings always wins.
pub fn set_rest_key(app: &tauri::AppHandle, key_b64: String, uid: Option<String>) {
    if let Some(sh) = app.try_state::<Shadow>() {
        let _ = sh.tx.send(Job::Handshake { key_b64, uid });
    }
}

/// Settings snapshot helper for the CLI/import side (no app needed there).
pub fn cfg_from(settings: &Settings) -> ShadowSettings {
    settings.shadow.clone()
}

/// J4 (batch 10, audit §4 4.1 follow-up): send one `Job::Backup` to
/// the flusher and hand back its reply channel — the exit path
/// (`backup::on_exit`) uses this so app exit can run one DB backup on
/// the ONLY RW connection (A5). `None` when the pipeline is not
/// running (no `Shadow` state) or the flusher's queue is already gone
/// (shutdown race): the caller logs and continues exiting.
pub(crate) fn request_backup(
    app: &tauri::AppHandle,
) -> Option<std::sync::mpsc::Receiver<super::backup::DbBackupOutcome>> {
    let sh = app.try_state::<Shadow>()?;
    let (rtx, rrx) = std::sync::mpsc::channel();
    sh.tx.send(Job::Backup { respond: rtx }).ok()?;
    Some(rrx)
}

/// Batch 18: send one `Passphrase*` job to the flusher and hand back the
/// reply receiver (the command awaits it off its own thread with a
/// generous timeout — a conversion of a large store is a full rekey).
/// `None` when the pipeline is not running (locked, disabled, or the
/// shutdown race): the caller translates that into its own clean
/// refusal, never a password prompt of the CLI's.
pub(crate) fn send_passphrase(
    app: &tauri::AppHandle,
    build: impl FnOnce(Sender<Result<(), String>>) -> Job,
) -> Option<std::sync::mpsc::Receiver<Result<(), String>>> {
    let sh = app.try_state::<Shadow>()?;
    let (rtx, rrx) = std::sync::mpsc::channel();
    sh.tx.send(build(rtx)).ok()?;
    Some(rrx)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::migrate::sqlcipher;

    /// FAKE values of the documented shapes — never a real uid/hash.
    const FAKE_UID: &str = "1234567890123456789";
    const FAKE_HASH: &str = "abc123def456";

    fn mem_db() -> rusqlite::Connection {
        let key = sqlcipher::generate_key().unwrap();
        let conn = sqlcipher::open_in_memory(&key).unwrap();
        super::super::schema::apply(&conn).unwrap();
        conn
    }

    #[test]
    fn seed_account_row_happy_path_commits() {
        let conn = mem_db();
        seed_account_row(&conn, FAKE_UID, FAKE_HASH);
        assert!(
            conn.is_autocommit(),
            "a successful seed must leave no transaction open"
        );
        let n: i64 = conn
            .query_row("SELECT COUNT(*) FROM accounts", [], |r| r.get(0))
            .unwrap();
        assert_eq!(n, 1, "the row landed");
    }

    #[test]
    fn seed_account_row_upsert_error_rolls_back_never_commits() {
        let conn = mem_db();
        // Force the upsert itself to fail: the table is gone, but the
        // BEGIN still succeeds — the fix must ROLLBACK, not COMMIT.
        conn.execute_batch("DROP TABLE accounts").unwrap();
        seed_account_row(&conn, FAKE_UID, FAKE_HASH);
        assert!(
            conn.is_autocommit(),
            "an upsert error must end in ROLLBACK, never COMMIT"
        );
    }

    #[test]
    fn seed_account_row_failed_begin_never_commits_a_foreign_transaction() {
        // R3: the old code ignored the BEGIN IMMEDIATE result and ran
        // COMMIT anyway — with a transaction already open (here: this
        // test's), that COMMIT landed SOMEONE ELSE's transaction. The
        // fixed code must not touch it: the outer transaction stays
        // open, under this test's control.
        let conn = mem_db();
        conn.execute_batch("BEGIN").unwrap();
        seed_account_row(&conn, FAKE_UID, FAKE_HASH);
        assert!(
            !conn.is_autocommit(),
            "a failed BEGIN must not COMMIT the caller's open transaction"
        );
        conn.execute_batch("ROLLBACK").unwrap();
        assert!(conn.is_autocommit());
        let n: i64 = conn
            .query_row("SELECT COUNT(*) FROM accounts", [], |r| r.get(0))
            .unwrap();
        assert_eq!(n, 0, "nothing may land through a failed BEGIN");
    }

    #[test]
    fn ws_keys_bounded_map_never_drops_the_live_connection_key() {
        // R1 at the flusher's data structure: the WS key is sent ONCE
        // per connection, so an eviction must never take the NEWEST
        // key while older ones exist — a connection armed just now
        // survives every cap eviction until it is itself the oldest.
        let mut ws_keys: BoundedMap<String, [u8; 16]> = BoundedMap::new(WS_KEYS_CAP);
        for i in 0..WS_KEYS_CAP {
            assert!(matches!(
                ws_keys.insert(format!("old-{i}"), [2; 16]),
                Inserted::Kept
            ));
        }
        let live = "live-conn".to_string();
        // Filling the last slot evicts the OLDEST old key, not the
        // incoming live one.
        assert!(matches!(
            ws_keys.insert(live.clone(), [1; 16]),
            Inserted::Evicted(_, _)
        ));
        // The live key is the NEWEST: further connections evict the
        // OLDEST old-* keys first, never the live one.
        let mut evicted_live = false;
        for i in 0..(WS_KEYS_CAP - 1) {
            if let Inserted::Evicted(k, _) = ws_keys.insert(format!("new-{i}"), [3; 16]) {
                if k == live {
                    evicted_live = true;
                }
            }
        }
        assert!(
            !evicted_live,
            "the live key must never be the evicted one while older keys exist"
        );
        assert_eq!(ws_keys.get(&live), Some(&[1; 16]));
        // A close hands the key back for zeroizing (the flusher wipes
        // it) and frees the slot.
        assert_eq!(ws_keys.remove(&live), Some([1; 16]));
        assert!(ws_keys.get(&live).is_none());
    }
}

