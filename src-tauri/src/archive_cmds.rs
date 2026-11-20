//! IPC commands + isolation for the "Lưu trữ" (Archive) window —
//! audit §4 Phase 3 item 3.2, batch 11.
//!
//! Isolation model (three layers, each independently testable):
//! 1. **Capability** (`capabilities/archive.json`, identifier
//!    `archive-local`, webview `archive`): the ACL only lets the
//!    `archive` webview invoke the four `archive_*` commands (plus
//!    `core:default` and the window-close permission it needs);
//!    `main-remote` grants NONE of them, settings gains only
//!    `allow-archive-open`. `src/ipc_acl_tests.rs` runs the real
//!    capability files through the ACL on Linux; the capability-JSON
//!    unit test below is the platform-independent half.
//! 2. **Caller check in every command** (defence in depth): the data
//!    commands refuse any webview whose label is not exactly
//!    [`ARCHIVE_LABEL`] on a local URL; `archive_open` also accepts
//!    `settings` (its button lives in the shadow section).
//! 3. **App lock**: data commands go through `lock::require_unlocked`
//!    and the window itself is hidden by `lock::should_hide`; a
//!    locked `archive_open` raises the lock screen, exactly like the
//!    settings window.
//!
//! The DB connection is a SEPARATE read-only session (A5: never the
//!    flusher's), opened lazily on the first command and dropped when
//!    the window closes (`ArchiveState`). Shadow disabled / key
//!    missing → a clean translated error, nothing else.

use std::path::PathBuf;

use tauri::{AppHandle, Manager, Webview};

use crate::i18n::tr;
use crate::shadow::archive;

/// The archive window's label — the one caller the data commands
/// accept, and the webview the media scheme answers.
pub const ARCHIVE_LABEL: &str = "archive";

/// Managed per-session state: the read-only connection, opened
/// lazily by the first command and dropped when the window closes
/// (`close()` on `WindowEvent::CloseRequested`, see window.rs).
///
/// F2 (batch-18 review): the slot also remembers the key-cell EPOCH
/// the connection was opened under; when the epoch moves (the flusher
/// just set/changed/removed the store password, or the store was just
/// unlocked), the cached connection — which holds the OLD key — is
/// dropped and the next use reopens with the CURRENT key.
pub struct ArchiveState {
    slot: std::sync::Mutex<ArchiveSlot>,
}

#[derive(Default)]
struct ArchiveSlot {
    conn: Option<rusqlite::Connection>,
    /// The shared key cell's epoch when `conn` was opened.
    epoch: u64,
}

impl ArchiveSlot {
    /// F2: reopen unless the cache holds a connection opened under the
    /// CURRENT epoch.
    fn needs_reopen(&self, current_epoch: u64) -> bool {
        self.conn.is_none() || self.epoch != current_epoch
    }
}

impl ArchiveState {
    pub fn new() -> Self {
        Self {
            slot: std::sync::Mutex::new(ArchiveSlot::default()),
        }
    }
    /// End the session: the cached connection goes away with the
    /// window (a reopen reopens the DB).
    pub fn close(&self) {
        self.drop_cache();
    }
    /// F2: drop the cached connection (the epoch stamp resets with the
    /// next open). The command layer calls this — through
    /// [`drop_cached_conn`] — right before sending a
    /// Passphrase{Set,Change,Remove} job, so the conversion never has
    /// to fight this connection's lock; a reopen racing the conversion
    /// is caught by its `store-busy` refusal (F1).
    pub fn drop_cache(&self) {
        *crate::lock::guard(&self.slot) = ArchiveSlot::default();
    }
}

impl Default for ArchiveState {
    fn default() -> Self {
        Self::new()
    }
}

/// F2: drop the archive window's cached connection, if the window's
/// state is managed (the window may not be open at all). Called by the
/// password commands right before they send the conversion job to the
/// flusher.
pub fn drop_cached_conn(app: &AppHandle) {
    if let Some(state) = app.try_state::<ArchiveState>() {
        state.drop_cache();
    }
}

// --- pure decision fns (unit-tested) -----------------------------------------

/// Pure predicate behind the data commands' caller check.
pub(crate) fn caller_can_read(label: &str) -> bool {
    label == ARCHIVE_LABEL
}

/// Pure predicate behind `archive_open`'s caller check: the archive
/// window itself and the settings window's "open archive" button —
/// never a remote `wa-*` webview.
pub(crate) fn caller_can_open(label: &str) -> bool {
    matches!(label, ARCHIVE_LABEL | "settings")
}

/// Pure decision behind `archive_open`'s lock rule — the same one the
/// main windows follow: locked never opens data; it raises the lock
/// screen instead.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum OpenDecision {
    Open,
    Locked,
}

pub(crate) fn open_decision(unlocked: bool) -> OpenDecision {
    if unlocked {
        OpenDecision::Open
    } else {
        OpenDecision::Locked
    }
}

// --- guards ------------------------------------------------------------------

/// The data-command guard: exact archive label on a local URL (the
/// remote page cannot forge either), then the app-lock check.
fn read_guard(window: &Webview, app: &AppHandle) -> Result<(), String> {
    if !caller_can_read(window.label())
        || !window.url().is_ok_and(|u| crate::integration::local_url(&u))
    {
        return Err("forbidden".into());
    }
    crate::lock::require_unlocked(app)
}

/// The `archive_open` guard: archive or settings label on a local URL.
fn open_guard(window: &Webview) -> Result<(), String> {
    if !caller_can_open(window.label())
        || !window.url().is_ok_and(|u| crate::integration::local_url(&u))
    {
        return Err("forbidden".into());
    }
    Ok(())
}

// --- the read-only session ----------------------------------------------------

/// Open the archive session: a SEPARATE read-only connection, never
/// the flusher's (A5). `open_with_key_readonly` /
/// `open_with_passphrase_readonly` set `query_only` and the H3 busy
/// timeout (verified in sqlcipher.rs); the unencrypted path mirrors
/// both. Shadow disabled, key missing, or a passphrase-mode store
/// without its remember file → a clean translated error (batch 18: the
/// archive window never asks for the password — it opens only what the
/// "remember on this machine" file can).
fn open_readonly(app: &AppHandle) -> Result<rusqlite::Connection, String> {
    use std::time::Duration;
    let cfg = crate::settings::load(app).shadow;
    if !cfg.enabled {
        return Err(tr("O armazenamento shadow está desativado.").into_owned());
    }
    let dir = crate::shadow::runtime::shadow_dir(app);
    // One clean translated error for every open failure — the kind
    // never reaches the UI (and the log stays free of paths/keys).
    fn fail<T>(_: T) -> String {
        tr("Não foi possível abrir o armazenamento de mensagens.").into_owned()
    }
    if !cfg.encrypt {
        let conn = rusqlite::Connection::open_with_flags(
            &crate::shadow::db_file(&dir),
            rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY,
        )
        .map_err(fail)?;
        conn.busy_timeout(Duration::from_millis(
            crate::migrate::sqlcipher::BUSY_TIMEOUT_MS,
        ))
        .map_err(fail)?;
        conn.pragma_update(None, "query_only", true).map_err(fail)?;
        return Ok(conn);
    }
    // Batch 18 (R4) + F2 (review): open in whichever mode the store's
    // marker says — raw through the DPAPI key file, passphrase through
    // the in-process shared key cell when it holds the CURRENT
    // password (unlocking WITHOUT "remember" still opens the archive),
    // falling back to the remember file. Locked (neither source) is
    // its own message.
    match crate::shadow::passphrase::open_store_with_cell(&dir, true) {
        Ok((conn, _)) => Ok(conn),
        Err(crate::shadow::passphrase::StoreOpenError::Locked) => Err(tr(
            "O armazenamento está protegido por senha: ative “Lembrar neste computador” nas \
             configurações ou abra o banco com a senha em um programa externo.",
        )
        .into_owned()),
        Err(crate::shadow::passphrase::StoreOpenError::Other(_)) => Err(fail(())),
    }
}

/// Run `f` against the session connection, opening it lazily and
/// REOPENING it whenever the key cell's epoch moved since it was
/// cached (F2: the flusher published a new key — the cached connection
/// holds the old one). The guard is a short-lived lock; query fns are
/// bounded by the page clamp.
fn with_conn<T>(
    app: &AppHandle,
    f: impl FnOnce(&rusqlite::Connection) -> Result<T, String>,
) -> Result<T, String> {
    let state = app.state::<ArchiveState>();
    with_conn_slot(&state, || open_readonly(app), f)
}

/// The cache-staleness half of [`with_conn`], split out so the reopen
/// rule is unit-testable without an app: no connection, or one opened
/// under an older epoch → reopen through `open` and stamp the current
/// epoch.
fn with_conn_slot<T>(
    state: &ArchiveState,
    open: impl FnOnce() -> Result<rusqlite::Connection, String>,
    f: impl FnOnce(&rusqlite::Connection) -> Result<T, String>,
) -> Result<T, String> {
    let mut slot = crate::lock::guard(&state.slot);
    let current = crate::shadow::passphrase::cell_epoch();
    if slot.needs_reopen(current) {
        let conn = open()?;
        *slot = ArchiveSlot { conn: Some(conn), epoch: current };
    }
    f(slot.conn.as_ref().expect("opened above"))
}

/// A query failure: log the SQLite KIND only (the pure layer already
/// reports kinds — never content), then hand the UI a translated
/// message. Open failures pass through unchanged (already translated).
fn query_failure(stage: &str, kind: String) -> String {
    crate::dlog::log(&format!("archive: {stage} failed ({kind})"));
    tr("Não foi possível consultar o armazenamento.").into_owned()
}

// --- the commands -------------------------------------------------------------

/// Conversations of the archive, newest first, keyset-paginated on
/// `(last_ts, id)`. Archive webview only; read-only.
#[tauri::command]
pub async fn archive_list_conversations(
    window: Webview,
    app: AppHandle,
    before: Option<(i64, String)>,
    limit: Option<u32>,
) -> Result<Vec<archive::ConvRow>, String> {
    read_guard(&window, &app)?;
    with_conn(&app, |conn| {
        archive::list_conversations(conn, before.as_ref(), archive::clamp_page(limit))
            .map_err(|kind| query_failure("list_conversations", kind))
    })
}

/// Messages of one conversation, newest first, keyset-paginated on
/// `(ts, msg_id)`. Archive webview only; read-only.
#[tauri::command]
pub async fn archive_list_messages(
    window: Webview,
    app: AppHandle,
    conv_id: String,
    before: Option<(i64, String)>,
    limit: Option<u32>,
) -> Result<Vec<archive::MsgRow>, String> {
    read_guard(&window, &app)?;
    with_conn(&app, |conn| {
        archive::list_messages(conn, &conv_id, before.as_ref(), archive::clamp_page(limit))
            .map_err(|kind| query_failure("list_messages", kind))
    })
}

/// Full-text search (batch 9 FTS5, Vietnamese-friendly), joined back
/// to full rows + conversation names. Archive webview only; read-only.
#[tauri::command]
pub async fn archive_search(
    window: Webview,
    app: AppHandle,
    query: String,
    limit: Option<u32>,
) -> Result<Vec<archive::SearchRow>, String> {
    read_guard(&window, &app)?;
    let query: String = query.chars().take(200).collect();
    with_conn(&app, |conn| {
        archive::search_messages(conn, &query, archive::clamp_page(limit))
            .map_err(|kind| query_failure("search", kind))
    })
}

/// Open (or focus) the archive window. Callable from the archive
/// window itself and from the settings window's button. While locked
/// this raises the lock screen — the same rule the main windows
/// follow — and never shows archive data.
#[tauri::command]
pub async fn archive_open(window: Webview, app: AppHandle) -> Result<(), String> {
    open_guard(&window)?;
    match open_decision(crate::lock::is_unlocked(&app)) {
        OpenDecision::Open => {
            crate::window::open_archive_window(&app);
            Ok(())
        }
        OpenDecision::Locked => {
            crate::lock::show_lock_window(&app);
            Ok(())
        }
    }
}

// --- K3: the zrarchive media scheme (handler half; pure fns in shadow/archive) --

/// Serve one `zrarchive://…/media/<msg_id>/<idx>` request. Only the
/// archive webview is answered; the file is chosen by the DB row
/// (never a path from the URL); the content type comes from the magic
/// bytes; a media row whose bytes fail the sniff is refused. Range
/// requests (video seeking) are honored within a bounded window.
pub(crate) fn serve_media(
    app: &AppHandle,
    label: &str,
    request: &tauri::http::Request<Vec<u8>>,
) -> tauri::http::Response<Vec<u8>> {
    use std::io::{Read, Seek, SeekFrom};
    use tauri::http::{header, Response, StatusCode};
    let not_found = || {
        Response::builder()
            .status(StatusCode::NOT_FOUND)
            .header(header::CACHE_CONTROL, "private, no-store")
            .body(Vec::new())
            .unwrap()
    };
    // (a) caller: only the archive webview is ever answered.
    if label != ARCHIVE_LABEL {
        return not_found();
    }
    // (b) URL: one strict shape — ids only, no path.
    let Some((msg_id, idx)) = archive::parse_media_uri(request.uri().path()) else {
        return not_found();
    };
    // (c) DB row picks the file, resolved INSIDE the media root.
    let cfg = crate::settings::load(app).shadow;
    let Some((path, kind)) = media_row(app, &cfg, &msg_id, idx) else {
        return not_found();
    };
    let Ok(meta) = std::fs::metadata(&path) else {
        return not_found();
    };
    if !meta.is_file() {
        return not_found();
    }
    let len = meta.len();
    if len == 0 {
        return not_found();
    }
    let Ok(mut file) = std::fs::File::open(&path) else {
        return not_found();
    };
    // (d) content type from the magic bytes (media::magic_ok family);
    //     a media row that fails the sniff serves nothing.
    let mut head = [0u8; 16];
    let head_len = file.read(&mut head).unwrap_or(0);
    let Some(content_type) = archive::content_type_for(kind.as_deref(), &head[..head_len]) else {
        return not_found();
    };
    // (e) range: a single range within a bounded window; a rangeless
    //     request gets the head of the file (images are far below the
    //     cap; a media element asks with Range for the rest).
    let range_header = request
        .headers()
        .get(header::RANGE)
        .and_then(|v| v.to_str().ok());
    let (status, start, end, content_range) = match range_header {
        None => (
            StatusCode::OK,
            0u64,
            len.min(archive::SERVE_FULL) - 1,
            None,
        ),
        Some(h) => match archive::parse_range(h, len) {
            Some((s, e)) => (
                StatusCode::PARTIAL_CONTENT,
                s,
                e,
                Some(format!("bytes {s}-{e}/{len}")),
            ),
            // An explicit but unsatisfiable range: 416, per RFC 9110.
            None => {
                return Response::builder()
                    .status(StatusCode::RANGE_NOT_SATISFIABLE)
                    .header(header::CONTENT_RANGE, format!("bytes */{len}"))
                    .header(header::CACHE_CONTROL, "private, no-store")
                    .body(Vec::new())
                    .unwrap();
            }
        },
    };
    // (f) read the slice (bounded by the window computed above).
    let take = (end - start + 1) as usize;
    if file.seek(SeekFrom::Start(start)).is_err() {
        return not_found();
    }
    let mut body = vec![0u8; take];
    let mut filled = 0usize;
    while filled < take {
        match file.read(&mut body[filled..]) {
            Ok(0) => break,
            Ok(n) => filled += n,
            Err(_) => return not_found(),
        }
    }
    body.truncate(filled);
    let mut builder = Response::builder()
        .status(status)
        .header(header::CONTENT_TYPE, content_type)
        .header(header::CONTENT_LENGTH, body.len())
        // Tell the media element it may seek (video).
        .header(header::ACCEPT_RANGES, "bytes")
        .header(header::CACHE_CONTROL, "private, max-age=3600");
    if let Some(cr) = content_range {
        builder = builder.header(header::CONTENT_RANGE, cr);
    }
    builder.body(body).unwrap_or_else(|_| not_found())
}

/// Resolve one media row through the session connection — the same
/// epoch-aware cache as the query commands (`with_conn_slot`).
/// Opening or querying failures are a plain 404 — the window's own
/// list command surfaces the real open error to the user.
fn media_row(
    app: &AppHandle,
    cfg: &crate::settings::ShadowSettings,
    msg_id: &str,
    idx: i64,
) -> Option<(PathBuf, Option<String>)> {
    let state = app.try_state::<ArchiveState>()?;
    match with_conn_slot(&state, || open_readonly(app), |conn| {
        Ok(archive::attachment_media(conn, cfg, msg_id, idx))
    }) {
        Ok(found) => found,
        Err(_) => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_the_archive_webview_may_read_archive_data() {
        assert!(caller_can_read("archive"));
        for label in ["settings", "lock", "wa-default", "shell-main", "detached-x", "Archive", ""] {
            assert!(!caller_can_read(label), "{label} must not read");
        }
    }

    #[test]
    fn archive_open_is_callable_from_archive_and_settings_only() {
        assert!(caller_can_open("archive"));
        assert!(caller_can_open("settings"));
        for label in ["wa-default", "lock", "shell-main", "detached-x", ""] {
            assert!(!caller_can_open(label), "{label} must not open");
        }
    }

    #[test]
    fn a_locked_app_never_opens_the_archive_window() {
        // The lock rule the main windows follow: locked → lock screen,
        // not the data. Pure decision, tested without app state.
        assert_eq!(open_decision(true), OpenDecision::Open);
        assert_eq!(open_decision(false), OpenDecision::Locked);
    }

    #[test]
    fn the_archive_cache_reopens_after_an_epoch_bump() {
        // F2 (batch-18 review): a cached connection opened under an
        // older key-cell epoch holds a key the store no longer accepts
        // — it must be dropped and reopened. Exercised through the
        // same slot helper `with_conn` uses, with a counting opener
        // instead of the AppHandle (no app launch). Serialized with
        // the other cell-mutating tests through the cell test lock.
        let _g = crate::shadow::passphrase::CELL_TEST_LOCK
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let state = ArchiveState::new();
        let opens = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let mk_open = || {
            let opens = opens.clone();
            move || {
                opens.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                Ok::<rusqlite::Connection, String>(
                    rusqlite::Connection::open_in_memory().unwrap(),
                )
            }
        };
        let ping = |c: &rusqlite::Connection| -> Result<i64, String> {
            c.query_row("SELECT 1", [], |r| r.get(0))
                .map_err(|e| e.to_string())
        };
        // First use: the slot is empty → opens, stamps the epoch.
        with_conn_slot(&state, mk_open(), |c| ping(c)).unwrap();
        assert_eq!(opens.load(std::sync::atomic::Ordering::SeqCst), 1);
        // Same epoch: the cached connection is reused (no reopen).
        with_conn_slot(&state, mk_open(), |c| ping(c)).unwrap();
        assert_eq!(opens.load(std::sync::atomic::Ordering::SeqCst), 1);
        // Epoch bump — the flusher just converted the store: the cache
        // is dropped and the next use reopens under the new epoch.
        crate::shadow::passphrase::publish_key(None);
        with_conn_slot(&state, mk_open(), |c| ping(c)).unwrap();
        assert_eq!(opens.load(std::sync::atomic::Ordering::SeqCst), 2);
        // drop_cache (the command layer's pre-conversion step) forces
        // a reopen too.
        state.drop_cache();
        with_conn_slot(&state, mk_open(), |c| ping(c)).unwrap();
        assert_eq!(opens.load(std::sync::atomic::Ordering::SeqCst), 3);
        // Leave the cell neutral for whichever test runs next.
        crate::shadow::passphrase::publish_key(None);
    }

    // --- the capability files, platform-independently ------------------------
    //
    // The mock-runtime ACL tests in ipc_acl_tests.rs run on Linux
    // only; these parse the same JSON on every platform so a
    // capability regression fails on this Windows machine too.

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

    const ARCHIVE_DATA_COMMANDS: &[&str] = &[
        "allow-archive-list-conversations",
        "allow-archive-list-messages",
        "allow-archive-search",
    ];

    #[test]
    fn the_archive_capability_grants_exactly_the_archive_window_its_commands() {
        let cap = capability("archive.json");
        assert_eq!(cap["identifier"], "archive-local", "identifier per the brief");
        let webviews: Vec<&str> = cap["webviews"]
            .as_array()
            .expect("webviews array")
            .iter()
            .map(|w| w.as_str().expect("webview string"))
            .collect();
        assert_eq!(webviews, vec!["archive"], "the archive webview only");
        let perms = permissions(&cap);
        for needed in ARCHIVE_DATA_COMMANDS
            .iter()
            .chain(std::iter::once(&"allow-archive-open"))
        {
            assert!(perms.contains(&needed.to_string()), "archive.json needs {needed}");
        }
        assert!(
            perms.contains(&"core:default".to_string()),
            "core:default (invoke + the local window set)"
        );
        assert!(
            perms.contains(&"core:window:allow-close".to_string()),
            "the window needs close itself (core:window:default has no allow-close)"
        );
        // NOTHING else: every other permission is an archive command or
        // one of the two entries above — no remote, no account, lock,
        // notification or settings command sneaks in.
        for p in &perms {
            let allowed = p == "core:default"
                || p == "core:window:allow-close"
                || p.starts_with("allow-archive-");
            assert!(allowed, "archive.json grants an unexpected permission: {p}");
        }
    }

    #[test]
    fn the_remote_capability_gains_no_archive_permission() {
        for name in ["main-remote.json"] {
            for p in permissions(&capability(name)) {
                assert!(
                    !p.contains("archive"),
                    "{name} must not carry an archive permission: {p}"
                );
            }
        }
    }

    #[test]
    fn settings_gains_only_allow_archive_open() {
        let perms = permissions(&capability("settings.json"));
        let archive_perms: Vec<&String> =
            perms.iter().filter(|p| p.starts_with("allow-archive-")).collect();
        assert_eq!(
            archive_perms,
            vec![&"allow-archive-open".to_string()],
            "settings may gain ONLY allow-archive-open"
        );
    }

    #[test]
    fn lock_and_shell_gain_no_archive_permission() {
        for name in ["lock.json", "shell.json"] {
            for p in permissions(&capability(name)) {
                assert!(
                    !p.starts_with("allow-archive-"),
                    "{name} must not carry an archive permission: {p}"
                );
            }
        }
    }

    #[test]
    fn the_archive_commands_are_registered_in_the_app_manifest() {
        // C3's lesson: a capability granting an unregistered command
        // panics tauri-build on a clean clone. The four names must be
        // in build.rs's app manifest exactly once.
        let path = format!("{}/build.rs", env!("CARGO_MANIFEST_DIR"));
        let src = std::fs::read_to_string(&path).unwrap();
        for cmd in [
            "archive_list_conversations",
            "archive_list_messages",
            "archive_search",
            "archive_open",
        ] {
            let quoted = format!("\"{cmd}\"");
            let n = src.matches(&quoted).count();
            assert_eq!(n, 1, "build.rs must register {cmd} exactly once");
        }
    }
}
