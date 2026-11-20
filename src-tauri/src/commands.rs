#[cfg(not(windows))]
use crate::accounts::ActiveAccount;
use crate::accounts::{self, UnreadMap};
use crate::applock::{self, AppLockConfig};
use crate::i18n::{tr, trf};
use crate::lock;
use crate::settings::Settings;
use serde::Serialize;
use tauri::Manager;

/// Account-management commands must NOT be reachable from a remote Zalo page.
/// Account windows carry the `wa-<id>` label; the trusted local `settings` window
/// does not. Tauri injects the calling `window`; the remote page cannot forge its
/// label. Zalo pages keep `notify`/`set_unread` (they need them) but are denied
/// every account-management command.
fn is_remote(window: &tauri::Webview) -> bool {
    is_remote_label(window.label()) || !crate::integration::trusted_local(window)
}

/// Pure predicate behind `is_remote`, broken out so it can be unit-tested without a
/// live `tauri::Webview`.
fn is_remote_label(label: &str) -> bool {
    label.starts_with("wa-")
}

/// `icon` is the sender's picture as a small base64 PNG (bridge.js), when
/// Zalo gave one and it could be loaded.
#[tauri::command(async)]
pub fn notify(
    window: tauri::Webview,
    app: tauri::AppHandle,
    title: String,
    body: String,
    icon: Option<String>,
    epoch: Option<u64>,
) {
    if crate::integration::remote(&window).is_err() {
        return;
    }
    // issue #3 diagnostics: confirm the command is actually reached from the
    // injected bridge. No message content is logged (PII).
    crate::dlog::log("commands::notify invoked");
    crate::notify::from_page(&app, window.label(), &title, &body, icon.as_deref(), epoch);
}

/// Diagnostic breadcrumb from the injected page script (bridge.js) into the same
/// file log as the Rust side, so a drag-drop failure can be traced end-to-end on a
/// build with no console. Allowed from the Zalo page; it only appends a short,
/// length-capped string we author in bridge.js — no page-controlled PII.
#[tauri::command]
pub fn dlog(msg: String) {
    let msg: String = msg.chars().take(300).collect();
    crate::dlog::log(&format!("js: {msg}"));
}

/// "Open" on the download toast (issue #21). The page names a download only by
/// the id we gave it; a program or installer is shown in its folder instead of
/// run (see downloads.rs).
#[tauri::command]
pub fn open_download(app: tauri::AppHandle, id: u64) -> Result<(), String> {
    lock::require_unlocked(&app)?;
    let path = app
        .state::<crate::downloads::Downloads>()
        .path(id)
        .ok_or_else(|| tr("Download não encontrado").into_owned())?;
    if crate::downloads::is_risky(&path) {
        crate::dlog::log("download: open refused for a program, revealing instead");
        crate::opener::reveal_file(&app, path);
    } else {
        crate::opener::open_file(&app, path);
    }
    Ok(())
}

/// "Show in folder" on the download toast.
#[tauri::command]
pub fn reveal_download(app: tauri::AppHandle, id: u64) -> Result<(), String> {
    lock::require_unlocked(&app)?;
    let path = app
        .state::<crate::downloads::Downloads>()
        .path(id)
        .ok_or_else(|| tr("Download não encontrado").into_owned())?;
    crate::opener::reveal_file(&app, path);
    Ok(())
}

// --- Shadow DB (feat/shadow-db-rebuild) ---------------------------------------
// Both commands are callable ONLY from the Zalo page (the ACL lives in
// capabilities/main-remote.json; the remote check below is the second
// layer). Neither logs its payload — the E2EE plaintext is the user's own
// message traffic and the handshake key is a secret that must never reach
// the log file.

// D3 (audit M3): rate limiters for the two bridge commands. Page
// scripts on chat.zalo.me are trusted at page level — the same level
// the page itself runs at — and the buckets do not add distrust; they
// only bound abuse, so a runaway loop or a hostile script on that page
// cannot flood the shadow pipeline or spam handshakes. Single
// process: statics behind a Mutex are fine.
//
// Shapes (R2, batch 4 review): e2ee capacity 5000 with 500/s refill.
// Opening a large conversation or the post-login sync decrypts history
// in bursts — hundreds to thousands of messages in seconds — and
// dropping legitimate plaintext is unrecoverable data loss, the exact
// opposite of the capture goal. The old 300/50 shape risked exactly
// that; this one absorbs a full history sync (a real chat session then
// sends ~1/s; audit KQ7 saw 2765 calls in 45 min) and still bounds
// abuse: a runaway loop or a hostile script on that page hits the
// bucket and stalls at 500/s. Handshake burst 5 with 1 token per 60 s
// (the page hands the key over once per (re)load) is unchanged.
static E2EE_LIMITER: std::sync::Mutex<crate::shadow::rate_limit::RateLimiter> =
    std::sync::Mutex::new(crate::shadow::rate_limit::RateLimiter::new(5000.0, 500.0));
static HANDSHAKE_LIMITER: std::sync::Mutex<crate::shadow::rate_limit::RateLimiter> =
    std::sync::Mutex::new(crate::shadow::rate_limit::RateLimiter::new(5.0, 1.0 / 60.0));

/// One E2EE plaintext message forwarded by the bridge tap (bridge.js 0b:
/// a wrapped `decryptMsgFromServer`). 512 KB hard cap; larger payloads are
/// dropped and counted, never stored.
///
/// Trust boundary (audit M3/D3): the ACL limits callers to the Zalo page
/// (`https://chat.zalo.me`), and page scripts are trusted at page level —
/// the same level the page itself runs at. The token bucket on top only
/// bounds abuse: over-limit calls are dropped and counted, nothing more.
#[tauri::command(async)]
pub fn shadow_e2ee_message(window: tauri::Webview, payload: String) {
    if crate::integration::remote(&window).is_err() {
        return;
    }
    use crate::shadow::normalize::{e2ee_admit, E2eeRefusal};
    use std::sync::atomic::{AtomicI64, AtomicU64, Ordering::Relaxed};
    // Counters instead of one log line per call (audit KQ7: 2765 lines in
    // 45 min). Summary at most once a minute; counts only, never content.
    static OK: AtomicU64 = AtomicU64::new(0);
    static NO_ID: AtomicU64 = AtomicU64::new(0);
    static KEYISH: AtomicU64 = AtomicU64::new(0);
    static OTHER: AtomicU64 = AtomicU64::new(0);
    // D3: calls the token bucket refused (cumulative).
    static RATE: AtomicU64 = AtomicU64::new(0);
    static LAST: AtomicI64 = AtomicI64::new(0);
    let now = crate::shadow::schema::now_ms();
    let allowed = E2EE_LIMITER
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .allow(now);
    if !allowed {
        RATE.fetch_add(1, Relaxed);
    } else if payload.len() > 512 * 1024 {
        OTHER.fetch_add(1, Relaxed);
    } else {
        match e2ee_admit(&payload) {
            Ok(_) => {
                OK.fetch_add(1, Relaxed);
                crate::shadow::runtime::deliver_e2ee(&window.app_handle(), payload);
            }
            Err(E2eeRefusal::NoMsgId) => {
                NO_ID.fetch_add(1, Relaxed);
            }
            Err(E2eeRefusal::KeyShaped) => {
                KEYISH.fetch_add(1, Relaxed);
            }
            Err(E2eeRefusal::NotJson) => {
                OTHER.fetch_add(1, Relaxed);
            }
        }
    }
    let last = LAST.load(Relaxed);
    if now - last >= 60_000 && LAST.compare_exchange(last, now, Relaxed, Relaxed).is_ok() {
        crate::dlog::log(&format!(
            "shadow e2ee: delivered={} dropped_no_msgid={} dropped_keyish={} dropped_other={} dropped_rate={} (cumulative)",
            OK.load(Relaxed),
            NO_ID.load(Relaxed),
            KEYISH.load(Relaxed),
            OTHER.load(Relaxed),
            RATE.load(Relaxed)
        ));
    }
}

/// The bridge hands over the page's REST decode key (`getSecretKey()`,
/// base64 of 16 bytes) and, when it can resolve it, the logged-in uid.
/// RAM only — never logged, never stored. Since D1 (KQ2) the uid is
/// only a cross-check: a uid configured in settings always wins.
///
/// Trust boundary (audit M3/D3): the ACL limits callers to the Zalo
/// page, and page scripts are trusted at page level. The bucket only
/// bounds abuse — the key legitimately arrives once per (re)load, so
/// anything faster is dropped and counted.
#[tauri::command(async)]
pub fn shadow_handshake(window: tauri::Webview, key: String, uid: Option<String>) {
    if crate::integration::remote(&window).is_err() {
        return;
    }
    use std::sync::atomic::{AtomicI64, AtomicU64, Ordering::Relaxed};
    // D3: refused handshakes (cumulative count only — never the key).
    static RATE: AtomicU64 = AtomicU64::new(0);
    static LAST: AtomicI64 = AtomicI64::new(0);
    let now = crate::shadow::schema::now_ms();
    let allowed = HANDSHAKE_LIMITER
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .allow(now);
    if !allowed {
        let n = RATE.fetch_add(1, Relaxed) + 1;
        // One throttled line (≤1/min), count only.
        let last = LAST.load(Relaxed);
        if now - last >= 60_000 && LAST.compare_exchange(last, now, Relaxed, Relaxed).is_ok() {
            crate::dlog::log(&format!("shadow handshake: rate limited ({n})"));
        }
        return;
    }
    if key.len() > 256 {
        crate::dlog::log("shadow handshake: dropped oversized key");
        return;
    }
    if let Some(u) = uid.as_deref() {
        if u.len() > 64 {
            crate::dlog::log("shadow handshake: dropped oversized uid");
            return;
        }
    }
    crate::shadow::runtime::set_rest_key(&window.app_handle(), key, uid);
}

// --- Shadow DB passphrase mode (batch 18, brief R1-R3) -----------------------
//
// The store password commands. ACL: the settings window only (`settings`
// label + local URL — the same two-layer rule as the archive commands,
// with the capability in capabilities/settings.json); `shadow_unlock`
// is the one exception, living in the shadow-unlock window's own
// capability and guarded exactly like the app-lock commands.
//
// Passwords arrive as IPC payloads, live in `Zeroizing<String>` for the
// ride to the flusher, and are never: logged, echoed in an error string,
// stored in settings.json, or written anywhere but the DPAPI remember
// file. Every failure the user sees is a generic translated message;
// the flusher's kind strings are for the log file (kinds only).

/// How long a settings command waits for the flusher's conversion reply.
/// A conversion pre-backs-up and then rekeys every page of the store —
/// seconds for the documented store, bounded so the UI can never hang.
const PASSPHRASE_JOB_WAIT: std::time::Duration = std::time::Duration::from_secs(300);

/// The settings-window guard shared by the password commands (R3:
/// "ACL limited to the settings window").
fn shadow_settings_guard(window: &tauri::Webview) -> Result<(), String> {
    if window.label() != "settings" || !crate::integration::trusted_local(window) {
        return Err("forbidden".into());
    }
    Ok(())
}

/// The shadow-unlock window guard (R2, the app-lock pattern: exact label
/// + local URL; the capability grants only `shadow-unlock`).
fn is_shadow_unlock_window(window: &tauri::Webview) -> bool {
    window.label() == crate::window::SHADOW_UNLOCK_LABEL
        && crate::integration::trusted_local(window)
}

/// The store status the shadow settings section shows (R3): which key
/// mode, whether a remember file exists, whether the capture pipeline is
/// running (and therefore whether the store is passphrase-locked).
#[derive(Debug, Clone, Serialize)]
pub struct ShadowPassStatus {
    /// "raw" | "passphrase" | "unknown" — the marker's word, no secrets.
    pub mode: String,
    /// A `default.pass.dpapi` remember file exists on this machine.
    pub remembered: bool,
    /// The capture pipeline booted (the flusher is alive).
    pub running: bool,
    /// Passphrase mode and NOT running: the store waits for an unlock.
    pub locked: bool,
}

/// `ShadowPassStatus` for the settings window (R3). Never reports any
/// secret — the marker is plaintext mode metadata by design.
#[tauri::command]
pub fn shadow_password_status(
    window: tauri::Webview,
    app: tauri::AppHandle,
) -> Result<ShadowPassStatus, String> {
    shadow_settings_guard(&window)?;
    lock::require_unlocked(&app)?;
    use crate::shadow::passphrase::{read_mode, remembered_present, StoreKeyMode};
    let dir = crate::shadow::runtime::shadow_dir(&app);
    let mode = match read_mode(&dir) {
        StoreKeyMode::Raw => "raw",
        StoreKeyMode::Passphrase => "passphrase",
        StoreKeyMode::Unknown => "unknown",
    };
    let running = app.try_state::<crate::shadow::runtime::Shadow>().is_some();
    Ok(ShadowPassStatus {
        mode: mode.into(),
        remembered: remembered_present(&dir),
        running,
        locked: mode == "passphrase" && !running,
    })
}

/// Await one flusher passphrase job off the command's async context.
/// `Err(kind)` messages are already log-safe (kinds only).
async fn await_passphrase_job(
    rx: std::sync::mpsc::Receiver<Result<(), String>>,
) -> Result<(), String> {
    tauri::async_runtime::spawn_blocking(move || {
        rx.recv_timeout(PASSPHRASE_JOB_WAIT)
            .map_err(|_| "flusher-gone".to_string())
            .and_then(|r| r)
    })
    .await
    .map_err(|_| "flusher-gone".to_string())?
}

/// Prove `password` opens the passphrase-mode store at `dir`, under the
/// shared wrong-password throttle (R2: 5 tries, then 30 s).
/// `Ok(())` = proven (throttle reset). `Err(Some(secs))` = blocked.
/// `Err(None)` = wrong password (counted).
fn prove_passphrase(dir: &std::path::Path, password: &str) -> Result<(), Option<u64>> {
    let db_path = crate::shadow::db_file(dir);
    crate::shadow::passphrase::throttled_probe(std::time::Instant::now(), || {
        match crate::migrate::sqlcipher::open_with_passphrase_readonly(&db_path, password) {
            Ok(_) => true,
            Err(crate::migrate::sqlcipher::KeyError::WrongPassword) => false,
            // Any other failure (io, corrupt marker era) is "not
            // proven": fail closed and count it.
            Err(_) => false,
        }
    })
    .map_err(|secs| if secs > 0 { Some(secs) } else { None })
}

/// "Đặt mật khẩu DB" (R3): convert the raw-keyed store to the user's
/// passphrase. The flusher (single writer) pre-backs-up with the OLD raw
/// key, journals down, rekeys, verifies, then flips the marker — any
/// failure leaves the store raw and usable.
#[tauri::command]
pub async fn shadow_set_password(
    window: tauri::Webview,
    app: tauri::AppHandle,
    new: String,
    confirm: String,
    remember: bool,
) -> Result<(), String> {
    // F5 (review): wipe every password copy from the moment it enters
    // Rust — the deserialized String IS the Zeroizing's buffer, so
    // there is exactly one copy and it dies zeroized.
    let new = zeroize::Zeroizing::new(new);
    let confirm = zeroize::Zeroizing::new(confirm);
    shadow_settings_guard(&window)?;
    lock::require_unlocked(&app)?;
    use crate::shadow::passphrase::{read_mode, validate_passphrase, PassInvalid, StoreKeyMode};
    if new.as_str() != confirm.as_str() {
        return Err(tr("As senhas não coincidem.").into());
    }
    match validate_passphrase(new.as_str()) {
        Ok(()) => {}
        Err(PassInvalid::TooShort) => {
            return Err(trf(
                "A senha do banco de dados deve ter pelo menos {0} caracteres.",
                &[&crate::shadow::passphrase::MIN_PASS_LEN],
            ))
        }
        Err(_) => return Err(tr("A senha do banco de dados contém caracteres inválidos.").into()),
    }
    let dir = crate::shadow::runtime::shadow_dir(&app);
    if read_mode(&dir) != StoreKeyMode::Raw {
        return Err(tr("O armazenamento já tem uma senha.").into());
    }
    if !crate::shadow::key_file(&dir).is_file() {
        return Err(tr("Não foi possível abrir o armazenamento de mensagens.").into());
    }
    // F2: the archive window's cached connection holds the OLD key —
    // drop it before the conversion job runs (a reopen racing the job
    // is caught by the conversion's own `store-busy` refusal).
    crate::archive_cmds::drop_cached_conn(&app);
    // The flusher must be running (it is the single writer that rekeys).
    let Some(rx) = crate::shadow::runtime::send_passphrase(&app, |respond| {
        crate::shadow::runtime::Job::PassphraseSet {
            passphrase: new,
            remember,
            respond,
        }
    }) else {
        return Err(tr("O armazenamento shadow está desativado ou bloqueado.").into());
    };
    match await_passphrase_job(rx).await {
        Ok(()) => Ok(()),
        Err(kind) => {
            crate::dlog::log(&format!("shadow: set-password FAILED ({kind})"));
            Err(pass_failure_message(&kind))
        }
    }
}

/// Generic, translated failure for a conversion job (never the kind's
/// internals — kinds are log-only; a couple of specific kinds get their
/// own clearer message).
fn pass_failure_message(kind: &str) -> String {
    if kind.starts_with("backup") {
        tr("O backup antes da alteração falhou; nada foi alterado. Tente novamente.")
            .into_owned()
    } else if kind == "store-busy" {
        // F1: the journal could not leave WAL — another connection
        // (the archive window's cached session reopened, an external
        // tool) still holds the store. Nothing was changed.
        tr("O armazenamento está em uso: feche a janela do arquivo e tente novamente. Nada foi alterado.")
            .into_owned()
    } else if kind == "flusher-gone" {
        tr("O armazenamento shadow está desativado ou bloqueado.").into_owned()
    } else {
        tr("Não foi possível alterar a senha do armazenamento.").into_owned()
    }
}

/// "Đổi mật khẩu" (R3): change the store passphrase. Requires the OLD
/// password (proven here under the throttle), then the flusher rekeys
/// and re-verifies. `remember: Option<bool>` — `None` keeps the
/// current remember state; the UI sends the toggle's state so the
/// remember file is updated atomically with the key.
#[tauri::command]
pub async fn shadow_change_password(
    window: tauri::Webview,
    app: tauri::AppHandle,
    old: String,
    new: String,
    confirm: String,
    remember: Option<bool>,
) -> Result<(), String> {
    // F5 (review): wipe every password copy from entry (until it rides
    // the job queue in the same `Zeroizing`).
    let old = zeroize::Zeroizing::new(old);
    let new = zeroize::Zeroizing::new(new);
    let confirm = zeroize::Zeroizing::new(confirm);
    shadow_settings_guard(&window)?;
    lock::require_unlocked(&app)?;
    use crate::shadow::passphrase::{read_mode, validate_passphrase, PassInvalid, StoreKeyMode};
    let dir = crate::shadow::runtime::shadow_dir(&app);
    if read_mode(&dir) != StoreKeyMode::Passphrase {
        return Err(tr("O armazenamento não tem uma senha.").into());
    }
    if new.as_str() != confirm.as_str() {
        return Err(tr("As senhas não coincidem.").into());
    }
    match validate_passphrase(new.as_str()) {
        Ok(()) => {}
        Err(PassInvalid::TooShort) => {
            return Err(trf(
                "A senha do banco de dados deve ter pelo menos {0} caracteres.",
                &[&crate::shadow::passphrase::MIN_PASS_LEN],
            ))
        }
        Err(_) => return Err(tr("A senha do banco de dados contém caracteres inválidos.").into()),
    }
    // Prove the OLD password under the throttle — one generic message,
    // never which part failed.
    match prove_passphrase(&dir, old.as_str()) {
        Ok(()) => {}
        Err(Some(secs)) => return Err(format!("throttled:{secs}")),
        Err(None) => return Err(tr("A senha atual está incorreta.").into()),
    }
    let remember = remember.unwrap_or_else(|| crate::shadow::passphrase::remembered_present(&dir));
    // F2: the archive window's cached connection holds the OLD key —
    // drop it before the conversion job runs.
    crate::archive_cmds::drop_cached_conn(&app);
    let Some(rx) = crate::shadow::runtime::send_passphrase(&app, |respond| {
        crate::shadow::runtime::Job::PassphraseChange {
            old,
            new,
            remember,
            respond,
        }
    }) else {
        return Err(tr("O armazenamento shadow está desativado ou bloqueado.").into());
    };
    match await_passphrase_job(rx).await {
        Ok(()) => Ok(()),
        Err(kind) => {
            crate::dlog::log(&format!("shadow: change-password FAILED ({kind})"));
            Err(pass_failure_message(&kind))
        }
    }
}

/// "Bỏ mật khẩu (quay về khóa theo máy)" (R3): remove the password,
/// rekeying back to a fresh random raw key saved DPAPI. Requires the
/// current password, proven under the throttle.
#[tauri::command]
pub async fn shadow_remove_password(
    window: tauri::Webview,
    app: tauri::AppHandle,
    current: String,
) -> Result<(), String> {
    // F5 (review): wipe the password copy from entry.
    let current = zeroize::Zeroizing::new(current);
    shadow_settings_guard(&window)?;
    lock::require_unlocked(&app)?;
    use crate::shadow::passphrase::{read_mode, StoreKeyMode};
    let dir = crate::shadow::runtime::shadow_dir(&app);
    if read_mode(&dir) != StoreKeyMode::Passphrase {
        return Err(tr("O armazenamento não tem uma senha.").into());
    }
    match prove_passphrase(&dir, current.as_str()) {
        Ok(()) => {}
        Err(Some(secs)) => return Err(format!("throttled:{secs}")),
        Err(None) => return Err(tr("A senha atual está incorreta.").into()),
    }
    // F2: the archive window's cached connection holds the OLD key —
    // drop it before the conversion job runs.
    crate::archive_cmds::drop_cached_conn(&app);
    let Some(rx) = crate::shadow::runtime::send_passphrase(&app, |respond| {
        crate::shadow::runtime::Job::PassphraseRemove {
            current,
            respond,
        }
    }) else {
        return Err(tr("O armazenamento shadow está desativado ou bloqueado.").into());
    };
    match await_passphrase_job(rx).await {
        Ok(()) => Ok(()),
        Err(kind) => {
            crate::dlog::log(&format!("shadow: remove-password FAILED ({kind})"));
            Err(pass_failure_message(&kind))
        }
    }
}

/// "Nhớ trên máy này" toggle (R3). ON needs the flusher's RAM copy of
/// the passphrase (the pipeline must be running in passphrase mode);
/// OFF only deletes the remember file and works regardless.
#[tauri::command]
pub async fn shadow_set_remember(
    window: tauri::Webview,
    app: tauri::AppHandle,
    remember: bool,
) -> Result<(), String> {
    shadow_settings_guard(&window)?;
    lock::require_unlocked(&app)?;
    let dir = crate::shadow::runtime::shadow_dir(&app);
    if !remember {
        // Deleting never needs the pipeline.
        return crate::shadow::passphrase::forget_remembered(&dir)
            .map_err(|_| tr("Não foi possível esquecer a senha neste computador.").into_owned());
    }
    let Some(rx) = crate::shadow::runtime::send_passphrase(&app, |respond| {
        crate::shadow::runtime::Job::PassphraseRemember { on: true, respond }
    }) else {
        return Err(tr(
            "É preciso abrir o armazenamento primeiro: desbloqueie a senha dele e tente de novo.",
        )
        .into());
    };
    match await_passphrase_job(rx).await {
        Ok(()) => Ok(()),
        Err(kind) => {
            crate::dlog::log(&format!("shadow: set-remember FAILED ({kind})"));
            Err(tr("Não foi possível lembrar a senha neste computador.").into())
        }
    }
}

/// The shadow-unlock prompt (R2, the app-lock window pattern): prove the
/// password under the throttle, optionally write the remember file,
/// boot the pipeline, close the prompt. Works while the app is locked
/// (the store's password is a separate secret). `Ok(false)` = wrong
/// password; `Err("throttled:N")` while rate-limited.
#[tauri::command]
pub async fn shadow_unlock(
    window: tauri::Webview,
    app: tauri::AppHandle,
    password: String,
    remember: bool,
) -> Result<bool, String> {
    if !is_shadow_unlock_window(&window) {
        return Err("forbidden".into());
    }
    let pw = zeroize::Zeroizing::new(password);
    let dir = crate::shadow::runtime::shadow_dir(&app);
    // A stale prompt (the user removed the password while it was open,
    // or the marker vanished): nothing to unlock.
    if crate::shadow::passphrase::read_mode(&dir)
        != crate::shadow::passphrase::StoreKeyMode::Passphrase
    {
        close_shadow_unlock_window(&app);
        return Ok(true);
    }
    match prove_passphrase(&dir, &pw) {
        Ok(()) => {}
        Err(Some(secs)) => return Err(format!("throttled:{secs}")),
        Err(None) => return Ok(false),
    }
    // Proven: boot the pipeline (opens with the passphrase again as the
    // flusher's connection) and close the prompt on the main thread,
    // after this IPC reply is on its way back.
    let boot = crate::shadow::runtime::start_unlocked(&app, pw, remember);
    if let Err(kind) = boot {
        // Kinds only (H-rule) — the user sees one generic line.
        crate::dlog::log(&format!("shadow: unlock FAILED ({kind})"));
        return Err(tr("Não foi possível abrir o armazenamento de mensagens.").into());
    }
    crate::dlog::log("shadow: store unlocked (passphrase mode)");
    close_shadow_unlock_window(&app);
    Ok(true)
}

/// Close the shadow-unlock window from outside its own IPC callback
/// (the lock window's discipline: the reply must return before the
/// webview dies).
fn close_shadow_unlock_window(app: &tauri::AppHandle) {
    let handle = app.clone();
    let _ = tauri::async_runtime::spawn_blocking(move || {
        let inner = handle.clone();
        let _ = handle.run_on_main_thread(move || {
            if let Some(w) = inner.get_webview_window(crate::window::SHADOW_UNLOCK_LABEL) {
                let _ = w.destroy();
            }
        });
    });
}

#[tauri::command(async)]
pub fn set_unread(
    window: tauri::Webview,
    app: tauri::AppHandle,
    title: String,
    settled: Option<bool>,
) {
    if crate::integration::remote(&window).is_err() {
        return;
    }
    let count = crate::unread::parse_unread(&title);
    // A menu-bar panel carries its account's own `wa-<id>` label, so the
    // count is attributed to that account.
    let Some(id) = accounts::id_from_label(window.label()) else {
        return;
    };

    // Update the per-account count and compute the aggregate, then drop all
    // UnreadMap guards BEFORE calling tray::rebuild_menu (which re-locks the map)
    // to avoid a deadlock.
    let (previous, total) = {
        let state = app.state::<UnreadMap>();
        let mut map = crate::lock::guard(&state);
        let previous = map.insert(id.to_string(), count);
        (previous, accounts::aggregate_unread(&map))
    };

    crate::tray::update_badge(&app, total);
    crate::tray::rebuild_menu(&app);
    crate::integration::broadcast(&app);

    // A new unread chat while the window is in the background: make sure the
    // user hears about it even when Zalo raises its own notification where
    // Zalo can't see it (issue #3). Covered by a real notification, this
    // stays silent; see notify::unread_increased. A dismissed menu-bar panel
    // is a hidden window, so `is_visible()` already says nobody is watching.
    let focused = if crate::sessions::enabled() {
        crate::sessions::account_focused(&app, window.label())
    } else {
        window.window().is_focused().unwrap_or(false)
            && window.window().is_visible().unwrap_or(false)
    };
    if !cfg!(windows)
        && crate::notify::fallback_due(previous, count, focused, settled.unwrap_or(false))
    {
        crate::notify::unread_increased(&app, window.label(), count);
    }
}

#[derive(Debug, serde::Serialize)]
pub struct SettingsView {
    /// Flattened, so the UI reads the settings fields directly off the response.
    #[serde(flatten)]
    pub settings: Settings,
    /// The OS this build targets ("macos" | "linux" | "windows").
    /// The settings UI shows the platform-only rows only on macOS.
    pub platform: &'static str,
    /// Whether menu-bar-only mode works on this machine (macOS 14+; see
    /// `menubar::supported`). The UI disables the switch elsewhere rather
    /// than letting the user opt into a mode that would drop the session.
    pub menubar_supported: bool,
    /// The proxy URL the running webviews were created with (`""` = none). When
    /// it differs from the saved settings, a restart is pending.
    pub proxy_in_use: String,
    /// Whether the webview engine can proxy (false on macOS < 14).
    pub proxy_supported: bool,
    /// Whether this run actually hosts all accounts in one window (the saved
    /// `single_window` only applies after a restart).
    pub single_window_active: bool,
    /// Whether the single-window option is offered (not on Windows, where it is
    /// always on; not on macOS < 14, which stays single-account).
    pub single_window_supported: bool,
}

#[tauri::command]
pub fn get_settings(window: tauri::Webview, app: tauri::AppHandle) -> Result<SettingsView, String> {
    if is_remote(&window) {
        return Err("forbidden".into());
    }
    lock::require_unlocked(&app)?;
    Ok(SettingsView {
        settings: crate::settings::load(&app),
        platform: std::env::consts::OS,
        menubar_supported: crate::menubar::supported(),
        proxy_in_use: crate::proxy::in_use(),
        proxy_supported: crate::proxy::engine_supported(),
        single_window_active: crate::sessions::enabled(),
        single_window_supported: !cfg!(windows)
            && crate::window::ensure_isolation_supported().is_ok(),
    })
}

#[tauri::command]
pub fn set_settings(
    window: tauri::Webview,
    app: tauri::AppHandle,
    settings: Settings,
) -> Result<Option<String>, String> {
    if is_remote(&window) {
        return Err("forbidden".into());
    }
    lock::require_unlocked(&app)?;
    let mut settings = settings.sanitized();
    let stored = crate::settings::load(&app);
    // A newly chosen download folder must work now. An unchanged one is not
    // re-checked: if it has since gone away, downloads fall back to Downloads
    // (see downloads::configured_dir) and other settings must still save.
    if settings.download_dir != stored.download_dir {
        if let Some(dir) = &settings.download_dir {
            crate::downloads::validate_dir(std::path::Path::new(dir))?;
        }
    }
    // Shadow store + own identity (audit 1.3/KQ9 + 1.4/KQ2, batch 7 G1):
    // a NEWLY chosen media_store must work now (an unchanged one is not
    // re-checked, the same rule as download_dir — the flusher's own root
    // resolution falls back when a saved folder has gone away); the uid /
    // uin_hash shapes are validated on every save. Error strings are
    // translated and never echo the values.
    {
        let (uid, uin_hash) = crate::shadow::settings_check::validate_own_identity(
            settings.shadow.own_uid.as_deref(),
            settings.shadow.own_uin_hash.as_deref(),
        )?;
        settings.shadow.own_uid = uid;
        settings.shadow.own_uin_hash = uin_hash;
        let media_store =
            crate::shadow::settings_check::normalize_media_store(settings.shadow.media_store.as_deref());
        if media_store != stored.shadow.media_store {
            if let Some(path) = &media_store {
                // KQ9/D9: the same-volume check only applies while the
                // Desktop data root actually exists on this machine.
                let reference = std::path::Path::new(crate::shadow::settings_check::DESKTOP_DATA_ROOT);
                let reference = reference.is_dir().then_some(reference);
                crate::shadow::settings_check::validate_media_store(
                    std::path::Path::new(path),
                    reference,
                )?;
            }
        }
        settings.shadow.media_store = media_store;
        // Batch 8 H4: a NEWLY chosen backup_dir must work now too —
        // exists, writable, NO same-volume rule (the import hardlink
        // constraint does not apply to backups). Unchanged values are
        // not re-checked, and an empty field means "not configured"
        // (the backup thread only starts when a folder is set).
        let backup_dir =
            crate::shadow::settings_check::normalize_backup_dir(settings.shadow.backup_dir.as_deref());
        if backup_dir != stored.shadow.backup_dir {
            if let Some(path) = &backup_dir {
                crate::shadow::settings_check::validate_backup_dir(std::path::Path::new(path))?;
            }
        }
        settings.shadow.backup_dir = backup_dir;
    }
    // The icon is only switched through choose_app_icon / reset_app_icon.
    settings.custom_icon = stored.custom_icon;
    crate::proxy::validate(&mut settings)?;
    crate::settings::save(&app, &settings).map_err(|e| e.to_string())?;
    Ok(crate::settings::apply(&app, &settings))
}

/// Relaunch the app (the proxy applies when webviews are created). Local
/// settings window only, and not while locked.
#[tauri::command]
pub fn restart_app(window: tauri::Webview, app: tauri::AppHandle) -> Result<(), String> {
    if is_remote(&window) {
        return Err("forbidden".into());
    }
    lock::require_unlocked(&app)?;
    app.restart();
}

/// Everything Settings → Updates shows. Local settings window only, and not while locked.
#[tauri::command]
pub fn get_update_status(
    window: tauri::Webview,
    app: tauri::AppHandle,
) -> Result<serde_json::Value, String> {
    if is_remote(&window) {
        return Err("forbidden".into());
    }
    lock::require_unlocked(&app)?;
    Ok(crate::update_service::status_json(&app))
}

/// "Check now": answers at once, the result arrives as a status event.
#[tauri::command]
pub fn check_for_updates(window: tauri::Webview, app: tauri::AppHandle) -> Result<(), String> {
    if is_remote(&window) {
        return Err("forbidden".into());
    }
    lock::require_unlocked(&app)?;
    crate::update_service::check_now(&app);
    Ok(())
}

/// "Download and install" / "Restart and install".
#[tauri::command]
pub fn install_update(window: tauri::Webview, app: tauri::AppHandle) -> Result<(), String> {
    if is_remote(&window) {
        return Err("forbidden".into());
    }
    lock::require_unlocked(&app)?;
    crate::update_service::install_now(&app);
    Ok(())
}

/// "Restart now" after an update replaced the app in place.
#[tauri::command]
pub fn restart_to_update(window: tauri::Webview, app: tauri::AppHandle) -> Result<(), String> {
    if is_remote(&window) {
        return Err("forbidden".into());
    }
    lock::require_unlocked(&app)?;
    crate::update_service::restart(&app)
}

/// Open the release page of the newest version in the browser (the address
/// is never taken from the page).
#[tauri::command]
pub fn open_release_page(window: tauri::Webview, app: tauri::AppHandle) -> Result<(), String> {
    if is_remote(&window) {
        return Err("forbidden".into());
    }
    lock::require_unlocked(&app)?;
    if let Some(url) = crate::update_service::release_page_url(&app) {
        crate::opener::open_url(&app, url);
    }
    Ok(())
}

/// The dialog title for one folder-picker invocation (batch 10 J5).
/// `title_key` is a SEMANTIC key the settings window sends, never a
/// literal title — unknown or absent keys keep the download default,
/// so a stale or hostile caller cannot put arbitrary text in a
/// native dialog. Every language goes through `tr` (PT source, EN/VI
/// via the shared tables).
fn folder_title(title_key: Option<&str>) -> std::borrow::Cow<'_, str> {
    match title_key {
        // The two shadow pickers (batch 7 G1 / batch 8 H4) used to
        // show the download title — each now shows its own.
        Some("media") => tr("Pasta de armazenamento de mídia"),
        Some("backup") => tr("Pasta de backup"),
        _ => tr("Pasta de downloads"),
    }
}

/// Ask for a download folder with the system's folder picker. Returns the
/// chosen path (already checked as writable), or `None` if cancelled. The UI
/// saves it with the other settings. In the Flatpak the picker is the
/// xdg-desktop-portal one, so the folder is exported into the sandbox.
///
/// `title_key` (batch 10 J5, optional): `"media"` / `"backup"` makes the
/// dialog show the media-store / backup-folder title instead of the
/// download one; absent (or unknown) keeps `pick_download_dir`'s
/// behaviour byte-for-byte.
#[tauri::command]
pub async fn pick_download_dir(
    window: tauri::Webview,
    app: tauri::AppHandle,
    title_key: Option<String>,
) -> Result<Option<String>, String> {
    if is_remote(&window) {
        return Err("forbidden".into());
    }
    lock::require_unlocked(&app)?;
    use tauri_plugin_dialog::DialogExt;
    let mut dialog = app.dialog().file().set_title(folder_title(title_key.as_deref()));
    if let Some(dir) = app.path().download_dir().ok().filter(|d| d.is_dir()) {
        dialog = dialog.set_directory(dir);
    }
    let Some(picked) = dialog.set_parent(&window.window()).blocking_pick_folder() else {
        return Ok(None);
    };
    let path = picked.into_path().map_err(|e| e.to_string())?;
    crate::downloads::validate_dir(&path)?;
    Ok(Some(path.to_string_lossy().into_owned()))
}

/// Pick a PNG, validate it, keep a copy and use it as the app icon.
/// `false` means the picker was cancelled.
#[tauri::command]
pub async fn choose_app_icon(
    window: tauri::Webview,
    app: tauri::AppHandle,
) -> Result<bool, String> {
    if is_remote(&window) {
        return Err("forbidden".into());
    }
    lock::require_unlocked(&app)?;
    use tauri_plugin_dialog::DialogExt;
    let Some(picked) = app
        .dialog()
        .file()
        .set_title(tr("Ícone do aplicativo"))
        .add_filter("PNG", &["png"])
        .set_parent(&window.window())
        .blocking_pick_file()
    else {
        return Ok(false);
    };
    let path = picked.into_path().map_err(|e| e.to_string())?;
    // Refuse before reading a huge file into memory.
    let len = std::fs::metadata(&path).map_err(|e| e.to_string())?.len();
    if len > crate::appicon::MAX_BYTES as u64 {
        return Err(tr("A imagem tem mais de 5 MB.").into_owned());
    }
    let bytes = std::fs::read(&path).map_err(|e| e.to_string())?;
    crate::appicon::set_custom(&app, &bytes)?;
    let mut s = crate::settings::load(&app);
    s.custom_icon = true;
    crate::settings::save(&app, &s).map_err(|e| e.to_string())?;
    crate::appicon::apply(&app, true, true);
    Ok(true)
}

/// Go back to the built-in icon and delete the stored copy.
#[tauri::command]
pub fn reset_app_icon(window: tauri::Webview, app: tauri::AppHandle) -> Result<(), String> {
    if is_remote(&window) {
        return Err("forbidden".into());
    }
    lock::require_unlocked(&app)?;
    let mut s = crate::settings::load(&app);
    s.custom_icon = false;
    crate::settings::save(&app, &s).map_err(|e| e.to_string())?;
    crate::appicon::apply(&app, false, true);
    crate::appicon::clear_custom(&app);
    Ok(())
}

// Commands that build a window are `async`. Tauri runs a synchronous command
// inside WebView2's IPC callback, and creating another WebView2 there deadlocks
// on Windows (wry#583); an async command runs on the async runtime instead.
// Keep every window-creating command async.
#[tauri::command]
pub async fn open_settings(window: tauri::Webview, app: tauri::AppHandle) -> Result<(), String> {
    if is_remote(&window) {
        return Err("forbidden".into());
    }
    lock::require_unlocked(&app)?;
    crate::window::open_settings_window(&app);
    Ok(())
}

// ---------------------------------------------------------------------------
// Account-management commands (local-only).
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize)]
pub struct AccountView {
    pub id: String,
    pub name: String,
    pub order: u32,
    pub unread: u32,
    pub open: bool,
    pub is_default: bool,
    pub detached: bool,
}

fn account_views(app: &tauri::AppHandle) -> Vec<AccountView> {
    let f = accounts::load(app);
    let map = app.state::<UnreadMap>();
    let map = crate::lock::guard(&map);
    let mut views: Vec<AccountView> = f
        .accounts
        .iter()
        .map(|a| AccountView {
            id: a.id.clone(),
            name: a.name.clone(),
            order: a.order,
            unread: map.get(&a.id).copied().unwrap_or(0),
            open: app.get_webview(&accounts::window_label(&a.id)).is_some(),
            detached: cfg!(windows)
                && app
                    .get_webview(&accounts::window_label(&a.id))
                    .is_some_and(|v| v.window().label().starts_with("detached-")),
            is_default: accounts::startup_account(&f).is_some_and(|startup| startup.id == a.id),
        })
        .collect();
    views.sort_by_key(|v| v.order);
    views
}

/// Small account list for the Zalo-window switcher. Remote windows may only
/// read display data and request focusing one configured account.
#[derive(Debug, Clone, Serialize)]
pub struct SwitcherAccount {
    pub id: String,
    pub name: String,
    pub unread: u32,
}

#[tauri::command]
pub fn switcher_accounts(
    window: tauri::Webview,
    app: tauri::AppHandle,
) -> Result<Vec<SwitcherAccount>, String> {
    crate::integration::remote(&window)?;
    lock::require_unlocked(&app)?;
    Ok(account_views(&app)
        .into_iter()
        .map(|account| SwitcherAccount {
            id: account.id,
            name: account.name,
            unread: account.unread,
        })
        .collect())
}

/// Zoom shortcuts from the Zalo page (Ctrl/Cmd +/-/0, Ctrl+wheel): step the
/// shared display zoom, persist it and apply it to every account webview. The
/// page only names the action; the new level is computed from the saved value,
/// so a burst of requests cannot drift or leave the range.
#[tauri::command]
pub fn zoom_step(
    window: tauri::Webview,
    app: tauri::AppHandle,
    action: String,
) -> Result<f64, String> {
    crate::integration::remote(&window)?;
    lock::require_unlocked(&app)?;
    let action = crate::settings::ZoomAction::parse(&action).ok_or("bad action")?;
    static SERIAL: std::sync::Mutex<()> = std::sync::Mutex::new(());
    let _g = lock::guard(&SERIAL);
    let mut s = crate::settings::load(&app);
    let zoom = crate::settings::step_zoom(s.zoom, action);
    if zoom != s.zoom {
        s.zoom = zoom;
        crate::settings::save(&app, &s).map_err(|e| e.to_string())?;
    }
    crate::window::apply_zoom_all(&app, zoom);
    Ok(zoom)
}

#[tauri::command]
pub async fn switch_account(
    window: tauri::Webview,
    app: tauri::AppHandle,
    id: String,
) -> Result<(), String> {
    crate::integration::remote(&window)?;
    lock::require_unlocked(&app)?;
    let _guard = accounts::lock_mutations();
    let f = accounts::load(&app);
    let Some(acct) = f.accounts.iter().find(|a| a.id == id) else {
        return Err(tr("Conta não encontrada").into());
    };
    if app.get_webview(&accounts::window_label(&acct.id)).is_none() {
        crate::window::open_account_window(&app, acct, false).map_err(|e| e.to_string())?;
    }
    crate::window::show_account(&app, &accounts::window_label(&acct.id));
    #[cfg(not(windows))]
    if let Some(active) = app.try_state::<ActiveAccount>() {
        *crate::lock::guard(&active) = accounts::window_label(&acct.id);
    }
    Ok(())
}

#[tauri::command]
pub fn list_accounts(
    window: tauri::Webview,
    app: tauri::AppHandle,
) -> Result<Vec<AccountView>, String> {
    if is_remote(&window) {
        return Err("forbidden".into());
    }
    lock::require_unlocked(&app)?;
    Ok(account_views(&app))
}

#[tauri::command]
pub fn set_default_account(
    window: tauri::Webview,
    app: tauri::AppHandle,
    id: String,
) -> Result<(), String> {
    if is_remote(&window) {
        return Err("forbidden".into());
    }
    lock::require_unlocked(&app)?;
    let _guard = accounts::lock_mutations();
    let mut f = accounts::load(&app);
    accounts::set_startup_account(&mut f, &id)?;
    accounts::save(&app, &f).map_err(|e| e.to_string())
}

#[tauri::command]
pub async fn add_account(
    window: tauri::Webview,
    app: tauri::AppHandle,
    name: String,
) -> Result<AccountView, String> {
    if is_remote(&window) {
        return Err("forbidden".into());
    }
    lock::require_unlocked(&app)?;
    // macOS < 14 cannot isolate additional accounts (no data_store_identifier).
    crate::window::ensure_isolation_supported()?;

    let name = name.trim();
    if name.is_empty() {
        return Err("Informe um nome para a conta.".into());
    }

    let _guard = accounts::lock_mutations();
    let mut f = accounts::load(&app);
    let acct = accounts::add(&mut f, name);
    accounts::save(&app, &f).map_err(|e| e.to_string())?;

    // In menu-bar-only mode the window is created hidden and presented as a
    // panel right after, so no full-size window flashes.
    let start_hidden = crate::menubar::enabled(&app);
    if let Err(e) = crate::window::open_account_window(&app, &acct, start_hidden) {
        // Don't leave an account behind that never got a window. The sequence
        // number stays consumed, so a retry gets a fresh profile id.
        f.accounts.retain(|a| a.id != acct.id);
        accounts::save(&app, &f).map_err(|rollback| {
            trf(
                "{0}; e não foi possível restaurar a conta: {1}",
                &[&e, &rollback],
            )
        })?;
        return Err(e.to_string());
    }
    crate::tray::rebuild_menu(&app);
    crate::integration::broadcast(&app);
    // Opens the new account as a panel: also how the user reaches its QR login.
    #[cfg(target_os = "macos")]
    if start_hidden {
        crate::window::show_account(&app, &accounts::window_label(&acct.id));
    }

    let is_default = accounts::startup_account(&f).is_some_and(|startup| startup.id == acct.id);
    Ok(AccountView {
        id: acct.id,
        name: acct.name,
        order: acct.order,
        unread: 0,
        open: true,
        is_default,
        detached: false,
    })
}

#[tauri::command]
pub async fn remove_account(
    window: tauri::Webview,
    app: tauri::AppHandle,
    id: String,
) -> Result<(), String> {
    if is_remote(&window) {
        return Err("forbidden".into());
    }
    lock::require_unlocked(&app)?;

    let _guard = accounts::lock_mutations();
    let mut f = accounts::load(&app);
    let removed = accounts::remove(&mut f, &id)?;
    accounts::save(&app, &f).map_err(|e| e.to_string())?;

    // Close the window if open.
    if let Some(_w) = app.get_webview(&accounts::window_label(&removed.id)) {
        let _ = _w.clear_all_browsing_data();
        #[cfg(windows)]
        crate::sessions::remove_view(&app, &removed.id).map_err(|e| e.to_string())?;
        #[cfg(not(windows))]
        {
            if crate::sessions::enabled() {
                crate::sessions::remove_view(&app, &removed.id).map_err(|e| e.to_string())?;
            } else {
                let _ = _w.close();
            }
        }
    }
    // Drop the per-account unread count.
    {
        let state = app.state::<UnreadMap>();
        let mut map = crate::lock::guard(&state);
        map.remove(&removed.id);
    }
    accounts::delete_profile(&app, &removed.id);

    // If the removed account was the active one, point at a surviving account
    // so toggle/show don't target a window that no longer exists. (On Windows
    // the active view is tracked by sessions.rs instead.)
    #[cfg(not(windows))]
    if let (false, Some(active)) = (crate::sessions::enabled(), app.try_state::<ActiveAccount>()) {
        let mut label = active.lock().unwrap_or_else(|e| e.into_inner());
        if *label == accounts::window_label(&removed.id) {
            if let Some(next) = accounts::startup_account(&f) {
                *label = accounts::window_label(&next.id);
            }
        }
    }

    // Recompute the aggregate badge and the menu.
    let total = {
        let state = app.state::<UnreadMap>();
        let map = crate::lock::guard(&state);
        accounts::aggregate_unread(&map)
    };
    crate::tray::update_badge(&app, total);
    crate::tray::rebuild_menu(&app);
    crate::integration::broadcast(&app);
    Ok(())
}

#[tauri::command]
pub async fn rename_account(
    window: tauri::Webview,
    app: tauri::AppHandle,
    id: String,
    name: String,
) -> Result<(), String> {
    if is_remote(&window) {
        return Err("forbidden".into());
    }
    lock::require_unlocked(&app)?;
    let name = name.trim();
    if name.is_empty() {
        return Err("Informe um nome para a conta.".into());
    }

    let _guard = accounts::lock_mutations();
    let mut f = accounts::load(&app);
    accounts::rename(&mut f, &id, name)?;
    accounts::save(&app, &f).map_err(|e| e.to_string())?;

    if let Some(w) = app.get_webview(&accounts::window_label(&id)) {
        #[cfg(windows)]
        let visible_account =
            crate::sessions::selected(&app, w.window().label()).as_deref() == Some(w.label());
        #[cfg(not(windows))]
        let visible_account = !crate::sessions::enabled()
            || crate::sessions::selected(&app, w.window().label()).as_deref() == Some(w.label());
        if visible_account {
            let _ = w.window().set_title(&format!("Zalo — {name}"));
        }
    }
    crate::tray::rebuild_menu(&app);
    crate::integration::broadcast(&app);
    Ok(())
}

#[tauri::command]
pub async fn open_account(
    window: tauri::Webview,
    app: tauri::AppHandle,
    id: String,
) -> Result<(), String> {
    if is_remote(&window) {
        return Err("forbidden".into());
    }
    lock::require_unlocked(&app)?;
    let _guard = accounts::lock_mutations();
    let f = accounts::load(&app);
    let Some(acct) = f.accounts.iter().find(|a| a.id == id) else {
        return Err(trf("Conta não encontrada: {0}", &[&id]));
    };
    // Open the window if it was closed, then show + focus it.
    // Hidden first in menu-bar-only mode: show_account presents it as a
    // panel, and no full-size window flashes in between.
    let start_hidden = crate::menubar::enabled(&app);
    if app.get_webview(&accounts::window_label(&acct.id)).is_none() {
        crate::window::open_account_window(&app, acct, start_hidden).map_err(|e| e.to_string())?;
    }
    crate::window::show_account(&app, &accounts::window_label(&acct.id));
    // Track as the active account.
    #[cfg(not(windows))]
    if let Some(active) = app.try_state::<ActiveAccount>() {
        *crate::lock::guard(&active) = accounts::window_label(&acct.id);
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// App-lock commands.
// ---------------------------------------------------------------------------

/// Argon2 is deliberately slow; keep it off the thread that pumps UI events.
async fn hash_off_thread(password: String) -> Result<String, String> {
    tauri::async_runtime::spawn_blocking(move || applock::hash_password(&password))
        .await
        .map_err(|e| e.to_string())?
}

async fn verify_off_thread(password: String, phc: String) -> bool {
    tauri::async_runtime::spawn_blocking(move || applock::verify_password(&password, &phc))
        .await
        .unwrap_or(false)
}

#[derive(Debug, Clone, Serialize)]
pub struct LockStatus {
    pub enabled: bool,
    pub biometric_available: bool,
    pub biometric_enabled: bool,
    pub biometric_label: String,
    pub lock_on_launch: bool,
    pub lock_on_hide: bool,
    pub idle_secs: u32,
}

/// Read-only status for BOTH the settings window and the lock screen. Never returns
/// the password hash. Allowed from any non-remote window, even while locked.
#[tauri::command(async)]
pub fn get_lock_status(
    window: tauri::Webview,
    app: tauri::AppHandle,
) -> Result<LockStatus, String> {
    if is_remote(&window) {
        return Err("forbidden".into());
    }
    let c = applock::load(&app);
    let available = matches!(
        crate::biometric::availability(),
        crate::biometric::Availability::Available
    );
    Ok(LockStatus {
        enabled: c.is_active(),
        biometric_available: available,
        biometric_enabled: c.biometric_enabled && available,
        biometric_label: crate::biometric::label().to_string(),
        lock_on_launch: c.lock_on_launch,
        lock_on_hide: c.lock_on_hide,
        idle_secs: c.idle_secs,
    })
}

/// Enable the lock by setting the first password. Errors if already enabled (use
/// `change_app_lock_password`). Runs only from an unlocked, local window.
#[tauri::command]
pub async fn set_app_lock_password(
    window: tauri::Webview,
    app: tauri::AppHandle,
    new: String,
    confirm: String,
) -> Result<(), String> {
    if is_remote(&window) {
        return Err("forbidden".into());
    }
    lock::require_unlocked(&app)?;
    let mut c = applock::load(&app);
    if c.is_active() {
        return Err(tr("O bloqueio já está ativado.").into());
    }
    lock::validate_new_password(&new, &confirm)?;
    c.password_phc = Some(hash_off_thread(new).await?);
    c.enabled = true;
    applock::save(&app, &c).map_err(|e| e.to_string())?;
    crate::tray::rebuild_menu(&app);
    crate::integration::broadcast(&app);
    Ok(())
}

#[tauri::command]
pub async fn change_app_lock_password(
    window: tauri::Webview,
    app: tauri::AppHandle,
    current: String,
    new: String,
    confirm: String,
) -> Result<(), String> {
    if is_remote(&window) {
        return Err("forbidden".into());
    }
    lock::require_unlocked(&app)?;
    let mut c = applock::load(&app);
    let phc = c
        .password_phc
        .clone()
        .ok_or_else(|| tr("O bloqueio não está ativado.").into_owned())?;
    if !verify_off_thread(current, phc).await {
        return Err(tr("A senha atual está incorreta.").into());
    }
    lock::validate_new_password(&new, &confirm)?;
    c.password_phc = Some(hash_off_thread(new).await?);
    applock::save(&app, &c).map_err(|e| e.to_string())
}

#[tauri::command]
pub async fn disable_app_lock(
    window: tauri::Webview,
    app: tauri::AppHandle,
    current: String,
) -> Result<(), String> {
    if is_remote(&window) {
        return Err("forbidden".into());
    }
    lock::require_unlocked(&app)?;
    let mut c = applock::load(&app);
    let phc = c
        .password_phc
        .clone()
        .ok_or_else(|| tr("O bloqueio não está ativado.").into_owned())?;
    if !verify_off_thread(current, phc).await {
        return Err(tr("A senha atual está incorreta.").into());
    }
    c = AppLockConfig::default(); // fully reset: disabled, no hash, no biometric, default triggers
    applock::save(&app, &c).map_err(|e| e.to_string())?;
    crate::tray::rebuild_menu(&app);
    crate::integration::broadcast(&app);
    Ok(())
}

#[tauri::command]
pub fn set_app_lock_options(
    window: tauri::Webview,
    app: tauri::AppHandle,
    lock_on_launch: bool,
    lock_on_hide: bool,
    idle_secs: u32,
) -> Result<(), String> {
    if is_remote(&window) {
        return Err("forbidden".into());
    }
    lock::require_unlocked(&app)?;
    let mut c = applock::load(&app);
    c.lock_on_launch = lock_on_launch;
    c.lock_on_hide = lock_on_hide;
    c.idle_secs = idle_secs;
    applock::save(&app, &c).map_err(|e| e.to_string())
}

/// Enable/disable biometric. Enabling requires the lock to be set, the platform to
/// report Available, and one successful test authentication.
#[tauri::command(async)]
pub fn set_biometric_enabled(
    window: tauri::Webview,
    app: tauri::AppHandle,
    enabled: bool,
) -> Result<(), String> {
    if is_remote(&window) {
        return Err("forbidden".into());
    }
    lock::require_unlocked(&app)?;
    let mut c = applock::load(&app);
    if enabled {
        if !c.is_active() {
            return Err(tr("Defina uma senha de bloqueio primeiro.").into());
        }
        if !matches!(
            crate::biometric::availability(),
            crate::biometric::Availability::Available
        ) {
            return Err(
                tr("A autenticação biométrica não está disponível neste dispositivo.").into(),
            );
        }
        if !crate::biometric::authenticate(
            &app,
            tr("Ativar desbloqueio por biometria no Zalo").as_ref(),
        )? {
            return Err(tr("Não foi possível confirmar a biometria.").into());
        }
    }
    c.biometric_enabled = enabled;
    applock::save(&app, &c).map_err(|e| e.to_string())
}

/// Manual "Lock now" from the settings window. Async: it builds the lock window.
#[tauri::command]
pub async fn lock_app(window: tauri::Webview, app: tauri::AppHandle) -> Result<(), String> {
    if is_remote(&window) {
        return Err("forbidden".into());
    }
    if !applock::load(&app).is_active() {
        return Err(tr("O bloqueio não está ativado.").into());
    }
    lock::lock_now(&app);
    Ok(())
}

/// Unlock with the password. Lock-window only; works while locked (no require_unlocked).
/// Wrong guesses are rate-limited, and the Argon2 check runs off the UI thread.
#[tauri::command]
pub async fn unlock_password(
    window: tauri::Webview,
    app: tauri::AppHandle,
    password: String,
) -> Result<bool, String> {
    if !lock::is_lock_window(&window) {
        return Err("forbidden".into());
    }
    let c = applock::load(&app);
    let Some(phc) = c.password_phc else {
        // No lock configured: treat as already unlocked.
        lock::unlock(&app);
        return Ok(true);
    };
    {
        let t = lock::guard(&lock::THROTTLE);
        if let Some(Err(secs)) = t.as_ref().map(|t| t.check(std::time::Instant::now())) {
            return Err(format!("throttled:{secs}"));
        }
    }
    let ok = verify_off_thread(password, phc).await;
    {
        let mut t = lock::guard(&lock::THROTTLE);
        let t = t.get_or_insert_with(Default::default);
        if ok {
            t.record_success();
        } else {
            t.record_failure(std::time::Instant::now());
        }
    }
    if ok {
        lock::unlock(&app);
    }
    Ok(ok)
}

/// Unlock with biometric. Lock-window only; works while locked.
#[tauri::command(async)]
pub fn unlock_biometric(window: tauri::Webview, app: tauri::AppHandle) -> Result<bool, String> {
    if !lock::is_lock_window(&window) {
        return Err("forbidden".into());
    }
    if !applock::load(&app).biometric_enabled {
        return Err(tr("O desbloqueio por biometria não está ativado.").into());
    }
    if crate::biometric::authenticate(&app, tr("Desbloquear o Zalo").as_ref())? {
        lock::unlock(&app);
        Ok(true)
    } else {
        Ok(false)
    }
}

/// Forgot-password reset: wipe ALL account sessions + the app-lock config, then
/// relaunch fresh (logged out, lock disabled). Lock-window only.
#[tauri::command]
pub fn reset_app_lock(
    window: tauri::Webview,
    app: tauri::AppHandle,
    confirmed: bool,
) -> Result<(), String> {
    if !lock::is_lock_window(&window) {
        return Err("forbidden".into());
    }
    if !confirmed {
        return Err(tr("A redefinição precisa ser confirmada.").into());
    }
    crate::applock::request_reset(&app)?;
    app.restart();
}

#[cfg(test)]
mod tests {
    use super::{folder_title, is_remote_label};
    use crate::i18n::{tr_in, Lang};

    #[test]
    fn is_remote_wa_prefix_is_true() {
        assert!(is_remote_label("wa-default"));
    }

    #[test]
    fn is_remote_wa_acct_is_true() {
        assert!(is_remote_label("wa-acct-2"));
    }

    #[test]
    fn is_remote_settings_is_false() {
        assert!(!is_remote_label("settings"));
    }

    // --- batch 10 J5: the folder-picker titles --------------------------

    #[test]
    fn folder_titles_are_translated_per_key() {
        // Each known key routes to its OWN Portuguese source string
        // (whatever the current language is)…
        assert_eq!(folder_title(Some("media")), crate::i18n::tr("Pasta de armazenamento de mídia"));
        assert_eq!(folder_title(Some("backup")), crate::i18n::tr("Pasta de backup"));
        // …and each source string really maps in BOTH languages (the
        // vi.json side is additionally pinned by i18n.rs's
        // every_english_text_has_a_vietnamese_entry).
        assert_eq!(
            tr_in(Lang::En, "Pasta de armazenamento de mídia"),
            "Media storage folder"
        );
        assert_eq!(
            tr_in(Lang::Vi, "Pasta de armazenamento de mídia"),
            "Thư mục lưu trữ media"
        );
        assert_eq!(tr_in(Lang::En, "Pasta de backup"), "Backup folder");
        assert_eq!(tr_in(Lang::Vi, "Pasta de backup"), "Thư mục sao lưu");
        // …while absent/unknown keys keep the download default — a
        // hostile or stale caller cannot put arbitrary text in the
        // native dialog.
        for key in [None, Some("download"), Some("MEDIA"), Some("whatever <b>")] {
            assert_eq!(
                folder_title(key),
                crate::i18n::tr("Pasta de downloads"),
                "{key:?} falls back to the download title"
            );
        }
    }

    // --- batch 18: the shadow-password command surface -------------------
    //
    // The mock-runtime ACL tests in ipc_acl_tests.rs run on Linux only;
    // these parse the same capability JSON on every platform (the
    // archive-batch-11 pattern) so a capability regression fails on
    // this Windows machine too.

    fn capability(name: &str) -> serde_json::Value {
        let path = format!("{}/capabilities/{name}", env!("CARGO_MANIFEST_DIR"));
        let text = std::fs::read_to_string(&path)
            .unwrap_or_else(|e| panic!("read {path}: {e}"));
        serde_json::from_str(&text).unwrap_or_else(|e| panic!("parse {name}: {e}"))
    }

    fn permissions(cap: &serde_json::Value) -> Vec<String> {
        cap["permissions"]
            .as_array()
            .expect("permissions array")
            .iter()
            .map(|p| p.as_str().expect("permission string").to_string())
            .collect()
    }

    /// The five settings-window commands + the one unlock command.
    const SHADOW_SETTINGS_PASS_COMMANDS: &[&str] = &[
        "allow-shadow-password-status",
        "allow-shadow-set-password",
        "allow-shadow-change-password",
        "allow-shadow-remove-password",
        "allow-shadow-set-remember",
    ];

    #[test]
    fn the_unlock_capability_grants_exactly_the_unlock_window() {
        let cap = capability("shadow-unlock.json");
        assert_eq!(cap["identifier"], "shadow-unlock-local");
        let webviews: Vec<&str> = cap["webviews"]
            .as_array()
            .expect("webviews array")
            .iter()
            .map(|w| w.as_str().expect("webview string"))
            .collect();
        assert_eq!(webviews, vec!["shadow-unlock"], "the unlock webview only");
        let perms = permissions(&cap);
        assert!(perms.contains(&"core:default".to_string()));
        assert!(perms.contains(&"core:window:allow-close".to_string()));
        assert!(
            perms.contains(&"allow-shadow-unlock".to_string()),
            "its ONE command"
        );
        // NOTHING else: no remote, no account/lock/notification, none
        // of the settings-window password commands.
        for p in &perms {
            let allowed = p == "core:default"
                || p == "core:window:allow-close"
                || p == "allow-shadow-unlock";
            assert!(allowed, "shadow-unlock.json grants an unexpected permission: {p}");
        }
    }

    #[test]
    fn the_settings_capability_grants_exactly_the_five_password_commands() {
        let perms = permissions(&capability("settings.json"));
        let mut pass: Vec<String> = perms
            .iter()
            .filter(|p| p.starts_with("allow-shadow-"))
            .cloned()
            .collect();
        pass.sort();
        let mut want: Vec<String> =
            SHADOW_SETTINGS_PASS_COMMANDS.iter().map(|s| s.to_string()).collect();
        want.sort();
        assert_eq!(pass, want, "exactly the five, never allow-shadow-unlock");
    }

    #[test]
    fn no_other_capability_grants_a_shadow_password_command() {
        // The bridge's `allow-shadow-e2ee-message` / `allow-shadow-handshake`
        // (main-remote) are pre-existing page commands, NOT password
        // commands — check the exact six names instead of a prefix.
        let all: Vec<String> = SHADOW_SETTINGS_PASS_COMMANDS
            .iter()
            .chain(std::iter::once(&"allow-shadow-unlock"))
            .map(|s| s.to_string())
            .collect();
        for name in ["main-remote.json", "lock.json", "shell.json", "archive.json"] {
            for p in permissions(&capability(name)) {
                assert!(
                    !all.contains(&p),
                    "{name} must not carry a shadow password permission: {p}"
                );
            }
        }
    }

    #[test]
    fn the_shadow_password_commands_are_registered_in_the_app_manifest() {
        // C3's lesson: a capability granting an unregistered command
        // panics tauri-build on a clean clone. The six names must be in
        // build.rs's app manifest exactly once each.
        let path = format!("{}/build.rs", env!("CARGO_MANIFEST_DIR"));
        let src = std::fs::read_to_string(&path).unwrap();
        for cmd in [
            "shadow_password_status",
            "shadow_set_password",
            "shadow_change_password",
            "shadow_remove_password",
            "shadow_set_remember",
            "shadow_unlock",
        ] {
            let quoted = format!("\"{cmd}\"");
            let n = src.matches(&quoted).count();
            assert_eq!(n, 1, "build.rs must register {cmd} exactly once");
        }
    }

    #[test]
    fn the_shadow_guards_match_exactly_one_label_each() {
        // The unlock window guard is the exact-label rule of the lock
        // window (a `shadow-unlock-evil` prefix must NOT pass).
        for label in ["shadow-unlock", "Shadow-Unlock", "shadow-unlockx"] {
            let is = label == crate::window::SHADOW_UNLOCK_LABEL;
            assert_eq!(
                is,
                label == "shadow-unlock",
                "{label} must not count as the unlock window"
            );
        }
        assert_eq!(crate::window::SHADOW_UNLOCK_LABEL, "shadow-unlock");
    }
}
