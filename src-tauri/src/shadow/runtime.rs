//! Process-wide shadow state and the single writer thread (rebuild).
//!
//! Layout (unchanged from the lost implementation; the surviving probes
//! depend on it):
//! ```text
//! %LOCALAPPDATA%\com.o365serveronms.zalors\shadow\
//!   default.db        SQLCipher shadow DB (WAL)
//!   default.key       DPAPI-wrapped 32-byte key
//!   default.uin       account marker (legacy file, kept untouched)
//! ```
//!
//! Delivery paths (all end on the SAME mpsc queue; the flusher thread is
//! the only DB writer):
//! - `capture::deliver_ws` / `deliver_rest` — CDP network events.
//! - `deliver_e2ee` — the bridge tap's plaintext (command
//!   `shadow_e2ee_message`, ACL chat.zalo.me, 512 KB cap).
//! - `set_rest_key` — the bridge handshake (`shadow_handshake`) handing
//!   over the page's REST decode key; it lives in RAM only.
//!
//! The WS per-connection AES key is harvested from frame `cmd=1 subCmd=1`
//! the same way and never touches disk (redacted before `raw_events`).

use std::path::PathBuf;
use std::sync::mpsc::{channel, Receiver, Sender};
use std::time::Duration;

use serde_json::Value;
use tauri::Manager;

use super::{pipeline, schema, wire};
use crate::migrate::sqlcipher;
use crate::settings::{ShadowSettings, Settings};

/// Managed state: just the queue handle (Send + Sync).
pub struct Shadow {
    tx: Sender<Job>,
}

enum Job {
    WsFrame { bytes: Vec<u8>, direction: &'static str },
    RestBody { endpoint: String, body: Vec<u8>, direction: &'static str },
    E2ee { payload: String },
    Handshake { key_b64: String, uid: Option<String> },
}

impl Job {
    fn kind(&self) -> &'static str {
        match self {
            Job::WsFrame { .. } => "ws",
            Job::RestBody { .. } => "rest",
            Job::E2ee { .. } => "e2ee",
            Job::Handshake { .. } => "handshake",
        }
    }
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
    let (tx, rx) = channel::<Job>();
    match open_db(&dir, &s.shadow) {
        Ok(conn) => {
            let media_cfg = s.shadow.clone();
            std::thread::Builder::new()
                .name("shadow-flusher".into())
                .spawn(move || flusher(conn, rx, s.shadow))
                .ok();
            app.manage(Shadow { tx });
            // P1b: media auto-download (own connection, rate-limited).
            super::media::start(dir.clone(), media_cfg);
            crate::dlog::log("shadow: pipeline started (capture mode cdp)");
        }
        Err(e) => {
            crate::dlog::log(&format!("shadow: FAILED to start ({e})"));
        }
    }
}

/// Open (or create) the encrypted shadow DB and apply the schema.
fn open_db(dir: &PathBuf, cfg: &ShadowSettings) -> Result<rusqlite::Connection, String> {
    let _ = std::fs::create_dir_all(dir);
    let db_path = dir.join("default.db");
    let key_path = dir.join("default.key");
    if cfg.encrypt {
        if !key_path.exists() {
            let key = sqlcipher::generate_key().map_err(|e| e.to_string())?;
            sqlcipher::save_key(&key, &key_path).map_err(|e| e.to_string())?;
        }
        let key = sqlcipher::load_key(&key_path).map_err(|e| e.to_string())?;
        let conn = sqlcipher::open_with_key(&db_path, &key).map_err(|e| e.to_string())?;
        schema::apply(&conn).map_err(|e| e.to_string())?;
        Ok(conn)
    } else {
        let conn = rusqlite::Connection::open(&db_path).map_err(|e| e.to_string())?;
        schema::apply(&conn).map_err(|e| e.to_string())?;
        Ok(conn)
    }
}

/// The flusher thread: owns the DB connection and both runtime keys.
fn flusher(conn: rusqlite::Connection, rx: Receiver<Job>, cfg: ShadowSettings) {
    let mut ws_key: Option<[u8; 16]> = None;
    let mut rest_key: Option<[u8; 16]> = None;
    let mut own_uid: Option<String> = None;
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
        for job in jobs {
            match job {
                Job::Handshake { key_b64, uid } => {
                    if let Some(k) = wire::decode_key_field(&key_b64) {
                        rest_key = Some(k);
                        crate::dlog::log("shadow: rest decode key armed (len 16)");
                    } else {
                        crate::dlog::log("shadow: handshake key rejected (bad shape)");
                    }
                    if let Some(u) = uid {
                        if u.len() >= 5 && u.len() <= 32 && u.bytes().all(|b| b.is_ascii_digit()) {
                            own_uid = Some(u);
                            crate::dlog::log("shadow: own uid learned (len)");
                        }
                    }
                }
                Job::WsFrame { bytes, direction } => {
                    let Some(frame) = wire::parse_ws_frame(&bytes) else {
                        continue;
                    };
                    if let Some(k) = wire::ws_frame_key(&frame) {
                        ws_key = Some(k);
                        crate::dlog::log("shadow: ws connection key armed (len 16)");
                    }
                    let mut decoded = wire::decode_ws_frame(&frame, ws_key.as_ref());
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
                Job::RestBody { endpoint, body, direction } => {
                    let outer: Value = match serde_json::from_slice(&body) {
                        Ok(v) => v,
                        Err(_) => continue,
                    };
                    let env = wire::rest_envelope(&endpoint, &outer, rest_key.as_ref());
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
            }
        }
        if items.is_empty() {
            continue;
        }
        let s = pipeline::process_batch(&conn, &items, cfg.raw_events_days, own_uid.as_deref());
        if s.raw_events > 0 {
            crate::dlog::log(&format!(
                "shadow batch: raw={} msgs={} convs={} groups={} contacts={} other={}",
                s.raw_events, s.messages, s.conversations, s.groups, s.contacts, s.other_writes
            ));
        }
    }
    let _ = conn.execute_batch("PRAGMA wal_checkpoint(TRUNCATE);");
}

/// Deliver a raw WS frame (CDP). Binary bytes exactly as seen on the wire.
pub fn deliver_ws(app: &tauri::AppHandle, bytes: Vec<u8>, direction: &'static str) {
    if let Some(sh) = app.try_state::<Shadow>() {
        let _ = sh.tx.send(Job::WsFrame { bytes, direction });
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
/// logged-in account's uid (`getUserId`) for self-sent sender substitution.
/// Neither value ever enters logs or the DB.
pub fn set_rest_key(app: &tauri::AppHandle, key_b64: String, uid: Option<String>) {
    if let Some(sh) = app.try_state::<Shadow>() {
        let _ = sh.tx.send(Job::Handshake { key_b64, uid });
    }
}

/// Settings snapshot helper for the CLI/import side (no app needed there).
pub fn cfg_from(settings: &Settings) -> ShadowSettings {
    settings.shadow.clone()
}
