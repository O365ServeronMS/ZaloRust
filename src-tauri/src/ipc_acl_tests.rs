//! Which window, from which origin, may call which Zalo command.
//!
//! Tauri refuses a custom command from a remote origin unless a capability with
//! a matching `remote` URL grants it. Zalo had no app permission manifest,
//! so nothing could grant `notify`/`set_unread`/`dlog` to chat.zalo.me: every
//! call from the injected bridge was rejected, and bridge.js swallows the
//! rejection — no message notifications and no unread badge (issues #3, #32).
//! These tests run the real capability files through Tauri's ACL with the mock
//! runtime, so a capability or build.rs change that breaks either direction
//! (the page losing its bridge, or gaining account/lock commands) fails here.

use tauri::ipc::{CallbackFn, InvokeBody};
use tauri::test::{get_ipc_response, mock_builder, INVOKE_KEY};
use tauri::webview::InvokeRequest;
use tauri::{WebviewUrl, WebviewWindowBuilder};

const PAGE: &str = "https://chat.zalo.me/";

/// The commands the Zalo page's bridge.js needs.
const PAGE_COMMANDS: &[&str] = &[
    "notify",
    "set_unread",
    "dlog",
    "open_download",
    "reveal_download",
    "switcher_accounts",
    "switch_account",
    "zoom_step",
];
/// Commands only the local settings window may use.
const SETTINGS_COMMANDS: &[&str] = &[
    "get_settings",
    "set_settings",
    "pick_download_dir",
    "choose_app_icon",
    "reset_app_icon",
    "restart_app",
    "list_accounts",
    "add_account",
    "remove_account",
    "rename_account",
    "open_account",
    "set_default_account",
    "get_lock_status",
    "set_app_lock_password",
    "change_app_lock_password",
    "disable_app_lock",
    "set_app_lock_options",
    "set_biometric_enabled",
    "lock_app",
    "get_update_status",
    "check_for_updates",
    "install_update",
    "restart_to_update",
    "open_release_page",
];
/// Commands only the lock screen may use.
const LOCK_COMMANDS: &[&str] = &[
    "get_lock_status",
    "unlock_password",
    "unlock_biometric",
    "reset_app_lock",
];
/// Commands only the Lưu trữ (archive) window may use (batch 11,
/// audit §4 3.2). `archive_open` is additionally granted to settings.
const ARCHIVE_COMMANDS: &[&str] = &[
    "archive_list_conversations",
    "archive_list_messages",
    "archive_search",
    // Batch 29a.
    "archive_conv_media",
    "archive_conv_media_counts",
    "archive_conv_info",
    "archive_open_link",
    "archive_save_attachment",
];
/// Shadow DB password commands (batch 18): the five settings-window
/// ones plus the unlock prompt's own — the Zalo page must reach NONE
/// of them (they carry passwords, and the page never sees the store).
const SHADOW_PASS_COMMANDS: &[&str] = &[
    "shadow_password_status",
    "shadow_set_password",
    "shadow_change_password",
    "shadow_remove_password",
    "shadow_set_remember",
    "shadow_unlock",
];

fn allowed(app: &tauri::App<tauri::test::MockRuntime>, label: &str, url: &str, cmd: &str) -> bool {
    use tauri::Manager;
    let window = match app.get_webview_window(label) {
        Some(w) => w,
        None => WebviewWindowBuilder::new(app, label, WebviewUrl::External(url.parse().unwrap()))
            .build()
            .unwrap(),
    };
    let request = InvokeRequest {
        cmd: cmd.into(),
        callback: CallbackFn(0),
        error: CallbackFn(1),
        url: url.parse().unwrap(),
        body: InvokeBody::default(),
        headers: Default::default(),
        invoke_key: INVOKE_KEY.to_string(),
    };
    match get_ipc_response(&window, request) {
        Ok(_) => true,
        Err(e) => {
            let msg = e.to_string();
            assert!(
                msg.contains("not allowed"),
                "{cmd} failed for another reason: {msg}"
            );
            false
        }
    }
}

fn app() -> tauri::App<tauri::test::MockRuntime> {
    mock_builder()
        // Answers every command: the ACL decides by command name before any
        // handler runs, so a catch-all proves the decision without app state.
        .invoke_handler(|invoke| {
            invoke.resolver.resolve(());
            true
        })
        .build(tauri::generate_context!())
        .expect("mock app")
}

#[test]
fn the_zalo_page_reaches_its_bridge_commands_in_every_account() {
    let app = app();
    for label in ["wa-default", "wa-acct-2"] {
        for cmd in PAGE_COMMANDS {
            assert!(
                allowed(&app, label, PAGE, cmd),
                "{label} must be allowed {cmd}"
            );
        }
    }
}

/// The Zalo page loads in whatever `wa-<id>` window presents it, including the
/// macOS menu-bar panel. A `main-remote` change that swaps the `wa-*` glob for concrete
/// labels would silently kill notifications for every account not spelled out.
#[test]
fn the_remote_capability_matches_every_wa_label_the_page_may_load_in() {
    // (a) straight from the manifest: `webviews` must stay a `wa-*` glob, not a
    // list of concrete labels, so any account the app opens is covered.
    let manifest = concat!(env!("CARGO_MANIFEST_DIR"), "/capabilities/main-remote.json");
    let capability: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(manifest).unwrap()).unwrap();
    let webviews = capability["webviews"]
        .as_array()
        .expect("main-remote.json must list `webviews`");
    assert!(
        webviews
            .iter()
            .filter_map(|w| w.as_str())
            .any(|w| w.starts_with("wa-") && w.ends_with('*')),
        "the `webviews` field must keep a `wa-*` glob: {webviews:?}"
    );

    // (b) through the ACL, with labels beyond the ones the other tests use.
    let app = app();
    for label in ["wa-default", "wa-acct-42", "wa-2e6f9a1b7c4d"] {
        for cmd in PAGE_COMMANDS {
            assert!(
                allowed(&app, label, PAGE, cmd),
                "{label} must be allowed {cmd}"
            );
        }
    }
}

#[test]
fn the_zalo_page_cannot_reach_settings_or_lock_commands() {
    let app = app();
    for cmd in SETTINGS_COMMANDS
        .iter()
        .chain(LOCK_COMMANDS)
        .chain(ARCHIVE_COMMANDS)
        .chain(SHADOW_PASS_COMMANDS)
        .chain(&["open_settings", "archive_open"])
    {
        assert!(
            !allowed(&app, "wa-default", PAGE, cmd),
            "the page must not reach {cmd}"
        );
    }
    // Nor plugin commands that would bypass Zalo's lock-aware `notify`.
    assert!(!allowed(
        &app,
        "wa-default",
        PAGE,
        "plugin:notification|notify"
    ));
}

#[test]
fn the_notification_plugins_permission_query_is_answered() {
    // The plugin's init script asks this on every page load; refusing it left an
    // unhandled promise rejection in Zalo's page (found testing v0.6.5). The
    // mock app doesn't register the plugin, so getting past the ACL shows up as
    // "plugin notification not found" rather than "not allowed".
    let app = app();
    let window = WebviewWindowBuilder::new(
        &app,
        "wa-default",
        WebviewUrl::External(PAGE.parse().unwrap()),
    )
    .build()
    .unwrap();
    let request = InvokeRequest {
        cmd: "plugin:notification|is_permission_granted".into(),
        callback: CallbackFn(0),
        error: CallbackFn(1),
        url: PAGE.parse().unwrap(),
        body: InvokeBody::default(),
        headers: Default::default(),
        invoke_key: INVOKE_KEY.to_string(),
    };
    let err = get_ipc_response(&window, request).unwrap_err().to_string();
    assert!(
        !err.contains("not allowed"),
        "the ACL must let it through: {err}"
    );
}

#[test]
fn bridge_commands_are_refused_from_any_other_site() {
    let app = app();
    assert!(!allowed(
        &app,
        "wa-default",
        "https://evil.example/",
        "notify"
    ));
}

#[test]
fn local_windows_keep_exactly_their_own_commands() {
    let app = app();
    let local = "tauri://localhost/";
    for cmd in SETTINGS_COMMANDS {
        assert!(
            allowed(&app, "settings", local, cmd),
            "settings must be allowed {cmd}"
        );
    }
    for cmd in LOCK_COMMANDS {
        assert!(
            allowed(&app, "lock", local, cmd),
            "lock must be allowed {cmd}"
        );
    }
    for cmd in ["unlock_password", "reset_app_lock", "notify"] {
        assert!(
            !allowed(&app, "settings", local, cmd),
            "settings must not reach {cmd}"
        );
    }
    for cmd in ["get_settings", "add_account", "disable_app_lock", "notify"] {
        assert!(
            !allowed(&app, "lock", local, cmd),
            "lock must not reach {cmd}"
        );
    }
}

// --- Lưu trữ (archive) isolation (batch 11, audit §4 3.2) -------------------
//
// The archive window reads the shadow DB through its own capability
// (`archive-local`): the four archive commands are granted to the
// `archive` webview only, settings gains only `archive_open`, and the
// remote Zalo page gets none of them.

#[test]
fn the_archive_window_reaches_exactly_the_archive_commands() {
    let app = app();
    let local = "tauri://localhost/";
    for cmd in ARCHIVE_COMMANDS.iter().chain(std::iter::once(&"archive_open")) {
        assert!(
            allowed(&app, "archive", local, cmd),
            "archive must be allowed {cmd}"
        );
    }
    // And nothing else of the other windows' commands.
    for cmd in [
        "get_settings",
        "set_settings",
        "add_account",
        "unlock_password",
        "notify",
        "open_settings",
    ] {
        assert!(
            !allowed(&app, "archive", local, cmd),
            "archive must not reach {cmd}"
        );
    }
}

#[test]
fn the_settings_window_can_only_open_not_read_the_archive() {
    let app = app();
    let local = "tauri://localhost/";
    assert!(
        allowed(&app, "settings", local, "archive_open"),
        "settings must be allowed archive_open (the shadow-section button)"
    );
    for cmd in ARCHIVE_COMMANDS {
        assert!(
            !allowed(&app, "settings", local, cmd),
            "settings must not read the archive: {cmd}"
        );
    }
}
