use crate::i18n::trf;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(default)]
pub struct Settings {
    pub close_to_tray: bool,
    pub start_minimized: bool,
    pub autostart: bool,
    pub hotkey_enabled: bool,
    pub hotkey: String,
    /// Global shortcut that toggles the privacy blur in every account window.
    /// Off by default: a new global shortcut must not grab a key combination
    /// (Ctrl+Shift+B is the browsers' bookmarks bar) from users who never asked.
    pub blur_hotkey_enabled: bool,
    pub blur_hotkey: String,
    pub notifications: bool,
    pub notify_when_focused: bool,
    pub notify_active_chat: bool,
    pub respect_muted: bool,
    /// macOS only: the app lives in the menu bar, no Dock icon and no
    /// standard window. Every account stays connected in the background and
    /// opens as a panel from the tray. Off by default. Ignored on other platforms.
    pub menubar_only: bool,
    /// Linux/macOS: host every account in one window with a switcher instead
    /// of one window per account. Off by default; applies after a restart.
    /// Windows always uses a single window. Menu-bar-only mode wins if both
    /// are on.
    pub single_window: bool,
    /// macOS only: hide the Dock icon but keep the normal main window. The
    /// menu bar icon is forced on, since it becomes the way back to the app.
    pub hide_dock_icon: bool,
    /// Display zoom for the Zalo webview, 1.0 = the site's own sizing.
    pub zoom: f64,
    /// macOS only (issue #44): show the icon in the menu bar. With it off, the
    /// Dock icon brings a hidden window back. Windows and Linux always show the
    /// tray icon, since there it is the only way back to a hidden window.
    pub menu_bar_icon: bool,
    /// Interface language: `vi` (default) or `en`.
    pub language: String,
    /// Folder downloads are saved to (issue #40). `None` keeps the OS Downloads
    /// folder. Checked when saved and again before each download; a folder that
    /// has gone away or is no longer writable falls back to Downloads.
    pub download_dir: Option<String>,
    /// Use the PNG copied into the config dir as the app icon (issue #54).
    pub custom_icon: bool,
    /// Network proxy for the Zalo webviews: `off`, `socks5` or `http`
    /// (issue #52). Applied when a webview is created, so changes need a restart.
    pub proxy_mode: String,
    pub proxy_host: String,
    pub proxy_port: u32,
    /// Look for a newer release on GitHub shortly after start and every six
    /// hours (api.github.com). On by default.
    pub auto_update_check: bool,
    /// Download and install a newer release without asking, where that needs no
    /// password (AppImage, macOS app: replaced in place; Windows: downloaded and
    /// verified, installed on a click). On by default; never for .deb or Flatpak.
    pub auto_update_install: bool,
    /// Shadow DB (feat/shadow-db-rebuild): mirrors the user's own Zalo Web
    /// traffic on this machine into an encrypted local store. D17 priority
    /// order: shadow → import → Lưu trữ → backup.
    pub shadow: ShadowSettings,
}

/// Shadow capture/store options (D2-D5, D8, D11 defaults from the design).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(default)]
pub struct ShadowSettings {
    /// Master switch for the capture pipeline.
    pub enabled: bool,
    /// Keep the SQLCipher encryption on the shadow DB (D2). Only disable
    /// for debugging; the key file is always DPAPI-wrapped.
    pub encrypt: bool,
    /// Capture transport: `cdp` (WebView2 DevTools protocol network
    /// events). Reserved: `bridge` (in-page hooks only).
    pub capture: String,
    /// `raw_events` retention in days (D4 ring buffer).
    pub raw_events_days: u32,
    /// Batch window and cap for the pipeline (D5).
    pub batch_ms: u64,
    pub batch_max: usize,
    /// P1b media store root (D11). `None` = `<app data>\ZaloRust Data`.
    /// Set to `D:\ZaloRust Data` for this install.
    pub media_store: Option<String>,
    /// Own uid (KQ2 / audit 1.4): the Zalo userId of THIS install's
    /// account, as a configuration decision — the bridge no longer
    /// probes page DI tokens for it (0 hits in practice, A2 risk).
    /// Shape: 5..=32 ASCII digits. Seeds the flusher's self-sent
    /// sender substitution and the `accounts` row; never logged.
    pub own_uid: Option<String>,
    /// sha256(UIN) truncated to 12 lowercase hex chars — the account
    /// fingerprint stored in `accounts.uin_hash` (the UIN itself is
    /// never stored). `None` = the accounts row is skipped; a hash is
    /// never invented.
    pub own_uin_hash: Option<String>,
    /// Phase 4 backup (audit §4 4.1/4.2, batch 8 H4): scheduled
    /// encrypted DB + media backups. **OFF by default** — nothing runs
    /// unless this is on AND `backup_dir` is set.
    pub backup_enabled: bool,
    /// Where `shadow-<stamp>.db/.json` backups and the `media/` copy
    /// are written. `None` (or off) = no backup thread. Validated like
    /// the media store (exists, writable; NO same-volume rule).
    pub backup_dir: Option<String>,
    /// Hours between backup runs (the first runs ~2 min after start).
    pub backup_interval_hours: u32,
    /// D13 (audit 4.3): free-space percentage at/below which the media
    /// worker logs a warning transition (downloads continue).
    pub disk_warn_pct: u8,
    /// D13 (audit 4.3): free-space percentage at/below which the media
    /// worker pauses downloading (rows stay `ref`; text capture is
    /// never affected).
    pub disk_stop_pct: u8,
    /// Batch 26 M3: opt-in backfill of IMPORT-sourced media history.
    /// **OFF by default** — the live media thread only ever picks
    /// `status='ref'` rows (the module doc's "never a backfill scan of
    /// history"), and the Desktop import's `ref-import` rows are not
    /// live traffic. When ON, the thread may pick `ref-import` rows too,
    /// but only after the `ref` queue is empty in that cycle, at most 2
    /// per cycle, and a circuit breaker pauses the picks for the rest
    /// of the session after 20 consecutive gone/http_other outcomes.
    pub media_backfill_import: bool,
}

impl Default for ShadowSettings {
    fn default() -> Self {
        Self {
            enabled: true,
            encrypt: true,
            capture: "cdp".to_string(),
            raw_events_days: 7,
            batch_ms: 200,
            batch_max: 500,
            media_store: None,
            // KQ2: no configured uid by default — unconfigured installs
            // keep the old behaviour (the handshake's learned uid).
            own_uid: None,
            own_uin_hash: None,
            // H4: the whole Phase 4 feature is opt-in.
            backup_enabled: false,
            backup_dir: None,
            backup_interval_hours: 6,
            disk_warn_pct: 10,
            disk_stop_pct: 3,
            // Batch 26 M3: import-history media backfill is opt-in.
            media_backfill_import: false,
        }
    }
}

impl Default for Settings {
    fn default() -> Self {
        Self {
            close_to_tray: true,
            start_minimized: false,
            autostart: false,
            hotkey_enabled: true,
            hotkey: "CmdOrCtrl+Shift+W".to_string(),
            blur_hotkey_enabled: false,
            blur_hotkey: "CmdOrCtrl+Shift+B".to_string(),
            notifications: true,
            notify_when_focused: true,
            notify_active_chat: true,
            respect_muted: true,
            menubar_only: false,
            single_window: false,
            hide_dock_icon: false,
            zoom: 1.0,
            menu_bar_icon: true,
            language: crate::i18n::system_default().to_string(),
            download_dir: None,
            custom_icon: false,
            proxy_mode: crate::proxy::MODE_OFF.to_string(),
            proxy_host: String::new(),
            proxy_port: 0,
            auto_update_check: true,
            auto_update_install: true,
            shadow: ShadowSettings::default(),
        }
    }
}

/// Do two accelerator strings name the same key combination? Compared after
/// parsing, so "CmdOrCtrl+Shift+B" and "Shift+CmdOrCtrl+B" match. Unparseable
/// strings never match (registration reports those separately).
#[cfg(desktop)]
pub fn same_shortcut(a: &str, b: &str) -> bool {
    use tauri_plugin_global_shortcut::Shortcut;
    match (a.trim().parse::<Shortcut>(), b.trim().parse::<Shortcut>()) {
        (Ok(x), Ok(y)) => x == y,
        _ => false,
    }
}

/// Is `pressed` the privacy-blur shortcut (enabled, valid, and distinct from
/// the show/hide shortcut, which always wins a tie)?
#[cfg(desktop)]
pub fn is_blur_shortcut(s: &Settings, pressed: &tauri_plugin_global_shortcut::Shortcut) -> bool {
    s.blur_hotkey_enabled
        && !same_shortcut(&s.blur_hotkey, &s.hotkey)
        && s.blur_hotkey
            .trim()
            .parse::<tauri_plugin_global_shortcut::Shortcut>()
            .is_ok_and(|b| &b == pressed)
}

pub fn start_hidden(preference: bool, args: &[String]) -> bool {
    if args.iter().any(|a| a == "--show") {
        return false;
    }
    if cfg!(windows) {
        // A manual launch from Start or a desktop shortcut has no startup flag
        // and should always show the window. Apply the preference only to OS
        // startup. Accept --minimized for older Run entries, but still respect
        // the saved preference; new entries use the explicit flag below.
        preference
            && args
                .iter()
                .any(|a| a == "--autostart" || a == "--minimized")
    } else {
        preference || args.iter().any(|a| a == "--minimized")
    }
}

/// Zoom bounds. The settings UI only offers four presets inside this range; the
/// clamp exists so a hand-edited settings.json cannot leave the app at a zoom
/// level from which the settings window is unreadable.
pub const ZOOM_MIN: f64 = 0.5;
pub const ZOOM_MAX: f64 = 2.0;

/// Levels the zoom shortcuts step through (Ctrl +/-, Ctrl+wheel), all inside
/// `ZOOM_MIN..=ZOOM_MAX`. They include the four presets of the Display size
/// control, so shortcut and dropdown agree where they overlap.
pub const ZOOM_STEPS: [f64; 10] = [0.5, 0.67, 0.75, 0.85, 1.0, 1.15, 1.25, 1.5, 1.75, 2.0];

/// What a zoom shortcut asks for.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ZoomAction {
    In,
    Out,
    Reset,
}

impl ZoomAction {
    pub fn parse(s: &str) -> Option<Self> {
        match s {
            "in" => Some(Self::In),
            "out" => Some(Self::Out),
            "reset" => Some(Self::Reset),
            _ => None,
        }
    }
}

/// The zoom after one shortcut step. Steps to the next level strictly beyond
/// the current value, so an off-grid value (hand-edited, or from an older
/// build) lands on a level instead of skipping one; at the ends it stays put.
pub fn step_zoom(current: f64, action: ZoomAction) -> f64 {
    let cur = sanitize_zoom(current);
    const EPS: f64 = 1e-6;
    match action {
        ZoomAction::Reset => 1.0,
        ZoomAction::In => ZOOM_STEPS
            .iter()
            .copied()
            .find(|z| *z > cur + EPS)
            .unwrap_or(ZOOM_MAX),
        ZoomAction::Out => ZOOM_STEPS
            .iter()
            .rev()
            .copied()
            .find(|z| *z < cur - EPS)
            .unwrap_or(ZOOM_MIN),
    }
}

/// Bring a zoom factor into range. A non-finite value (a `null` or a string in
/// the JSON deserialises to the default, but arithmetic in an older build could
/// still have written a NaN) falls back to 1.0 rather than to a bound.
pub fn sanitize_zoom(zoom: f64) -> f64 {
    if zoom.is_finite() {
        zoom.clamp(ZOOM_MIN, ZOOM_MAX)
    } else {
        1.0
    }
}

impl Settings {
    /// Repair values an older or hand-edited settings.json can carry.
    pub fn sanitized(mut self) -> Self {
        self.zoom = sanitize_zoom(self.zoom);
        self.language = crate::i18n::sanitize_code(&self.language);
        self.download_dir = self.download_dir.filter(|d| !d.trim().is_empty());
        // Batch 8 H4: hand-edited backup numbers are clamped into the
        // ranges the runtime can actually use — a 0-hour interval would
        // spin the backup thread, a >100 % threshold is meaningless.
        // `disk_warn_pct < disk_stop_pct` is left alone on purpose: the
        // verdict checks Stop first, so a warn line below stop is
        // simply unreachable (benign). `backup_dir` trimming follows
        // the media_store pattern: normalized in `set_settings`, not
        // on load.
        self.shadow.backup_interval_hours = self.shadow.backup_interval_hours.clamp(1, 168);
        self.shadow.disk_warn_pct = self.shadow.disk_warn_pct.min(100);
        self.shadow.disk_stop_pct = self.shadow.disk_stop_pct.min(100);
        // Menu-bar-only mode needs WKWebView's inactive-scheduling policy
        // (macOS 14+). Dropping the flag here means a settings file or an
        // older build can never leave the app in a mode it cannot sustain.
        #[cfg(target_os = "macos")]
        if !crate::menubar::supported() {
            self.menubar_only = false;
        }
        self
    }
}

use std::path::PathBuf;
use tauri::{AppHandle, Manager};

#[cfg(target_os = "linux")]
fn is_valid_flatpak_id(id: &str) -> bool {
    id.len() <= 255
        && id.split('.').count() >= 3
        && id.split('.').all(|part| {
            let mut chars = part.chars();
            chars
                .next()
                .is_some_and(|first| first.is_ascii_alphabetic() || first == '_')
                && chars.all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-')
        })
}

#[cfg(target_os = "linux")]
pub(crate) fn flatpak_id() -> Option<String> {
    std::env::var("FLATPAK_ID")
        .ok()
        .filter(|id| is_valid_flatpak_id(id))
}

#[cfg(target_os = "linux")]
fn flatpak_autostart_entry(flatpak_id: &str) -> String {
    format!(
        "[Desktop Entry]\n\
         Type=Application\n\
         Version=1.0\n\
         Name=Zalo\n\
         Comment=Start Zalo minimized\n\
         Exec=flatpak run --command=zalors {flatpak_id} --minimized\n\
         Icon={flatpak_id}\n\
         Terminal=false\n\
         X-GNOME-Autostart-enabled=true\n\
         X-Flatpak={flatpak_id}\n"
    )
}

#[cfg(target_os = "linux")]
fn apply_flatpak_autostart(flatpak_id: &str, enabled: bool) -> std::io::Result<()> {
    let home = std::env::var_os("HOME")
        .map(PathBuf::from)
        .ok_or_else(|| std::io::Error::new(std::io::ErrorKind::NotFound, "HOME is not set"))?;
    let dir = home.join(".config/autostart");
    let path = dir.join(format!("{flatpak_id}.desktop"));
    if enabled {
        std::fs::create_dir_all(&dir)?;
        std::fs::write(path, flatpak_autostart_entry(flatpak_id))
    } else if path.exists() {
        std::fs::remove_file(path)
    } else {
        Ok(())
    }
}

fn settings_path(app: &AppHandle) -> tauri::Result<PathBuf> {
    let dir = app.path().app_config_dir()?;
    std::fs::create_dir_all(&dir)?;
    Ok(dir.join("settings.json"))
}

pub fn load(app: &AppHandle) -> Settings {
    let Ok(path) = settings_path(app) else {
        return Settings::default();
    };
    load_file(&path, true)
}

/// Read + sanitize a settings.json at an explicit path (the shared
/// loader core). `preserve` writes the `.corrupt-<ts>` copy the app
/// loader makes when the file turns out to be corrupt; strictly
/// read-only callers pass false.
fn load_file(path: &std::path::Path, preserve: bool) -> Settings {
    use crate::jsonfile::Loaded;
    match crate::jsonfile::read::<Settings>(path) {
        Loaded::Ok(s) | Loaded::Recovered(s) => s.sanitized(),
        Loaded::Missing => Settings::default(),
        Loaded::Corrupt => {
            if preserve {
                crate::jsonfile::preserve_corrupt(path);
            }
            Settings::default()
        }
    }
}

/// The settings loader WITHOUT an AppHandle (batch 15 O4): the import
/// CLI dispatches before Tauri exists, so `--own-uid-from-settings`
/// reads the same file through the same `jsonfile::read` +
/// `sanitized()` semantics — but strictly read-only: a corrupt file
/// is NOT preserved (the import CLI performs zero writes by
/// construction) and a missing/corrupt file yields the defaults.
pub fn load_at(path: &std::path::Path) -> Settings {
    load_file(path, false)
}

/// The app identifier `settings_path` resolves through Tauri's
/// app_config_dir — re-derived here because the import CLI runs
/// before Tauri exists (same string the shadow store helpers use).
const APP_CONFIG_DIR_ID: &str = "com.o365serveronms.zalors";

/// `<APPDATA>\<identifier>\settings.json` — the file [`load`] reads,
/// resolved without an AppHandle (batch 15 O4:
/// `--own-uid-from-settings` on the import CLI). `None` when
/// APPDATA is not set.
pub fn path_without_app() -> Option<PathBuf> {
    let base = std::env::var_os("APPDATA")?;
    Some(
        PathBuf::from(base)
            .join(APP_CONFIG_DIR_ID)
            .join("settings.json"),
    )
}

pub fn save(app: &AppHandle, s: &Settings) -> tauri::Result<()> {
    let path = settings_path(app)?;
    crate::jsonfile::save(&path, s)?;
    Ok(())
}

/// Apply side effects of settings (autostart + global shortcut + the macOS menu bar).
/// Returns any non-fatal side-effect failures as one warning string;
/// persisted settings and zoom changes are still applied.
pub fn apply(app: &AppHandle, s: &Settings) -> Option<String> {
    // Zoom is a webview property, so it applies on every platform and takes
    // effect on the open account windows without a reload.
    let lang = crate::i18n::Lang::from_code(&s.language);
    if lang != crate::i18n::current() {
        crate::i18n::set(lang);
        crate::i18n::refresh(app);
    }
    crate::window::apply_zoom_all(app, s.zoom);
    crate::appicon::apply(app, s.custom_icon, false);

    // Menu-bar mode is only available where a hidden WKWebView keeps running
    // (macOS 14+); elsewhere the setting is ignored rather than dropping every
    // account's session the moment it is enabled.
    #[cfg(target_os = "macos")]
    // Single-window mode keeps its window set for the whole run, so a live
    // menu-bar toggle only takes effect after a restart (menu-bar wins then).
    let menubar_only = s.menubar_only && crate::menubar::supported() && !crate::sessions::enabled();
    #[cfg(target_os = "macos")]
    let hide_dock = menubar_only || s.hide_dock_icon;

    // In menu-bar-only mode the tray icon is the app's only entry point, so
    // it can never be hidden.
    #[cfg(target_os = "macos")]
    crate::tray::apply_visibility(app, s.menu_bar_icon || hide_dock);
    #[cfg(not(target_os = "macos"))]
    crate::tray::apply_visibility(app, s.menu_bar_icon);

    // macOS menu-bar mode: reconcile the live window set with the settings.
    #[cfg(target_os = "macos")]
    {
        if menubar_only {
            crate::menubar::enter_only(app);
        } else if crate::menubar::leave_only(app) {
            // Leaving menu-bar-only mode: reopen missing windows and show the
            // active one, so the app is never left with no visible window.
            for a in crate::accounts::load(app).accounts {
                let label = crate::accounts::window_label(&a.id);
                if app.get_webview_window(&label).is_none() {
                    let _ = crate::window::open_account_window(app, &a, true);
                }
            }
            crate::window::show_active(app);
        }

        // Menu-bar-only apps have no Dock presence.
        let policy = if hide_dock {
            tauri::ActivationPolicy::Accessory
        } else {
            tauri::ActivationPolicy::Regular
        };
        let h = app.clone();
        let _ = app.run_on_main_thread(move || {
            let _ = h.set_activation_policy(policy);
        });

        // Hold the App Nap shield only while menu-bar-only mode is on.
        crate::menubar::set_keep_alive(menubar_only);
    }

    #[cfg(desktop)]
    {
        let mut warnings = Vec::new();

        #[cfg(target_os = "linux")]
        let flatpak_autostart_handled = flatpak_id()
            .map(|id| {
                if let Err(e) = apply_flatpak_autostart(&id, s.autostart) {
                    warnings.push(trf(
                        "Não foi possível atualizar a inicialização automática: {0}",
                        &[&e],
                    ));
                }
                true
            })
            .unwrap_or(false);
        #[cfg(not(target_os = "linux"))]
        let flatpak_autostart_handled = false;

        if !flatpak_autostart_handled {
            use tauri_plugin_autostart::ManagerExt;
            let autostart = app.autolaunch();
            let result = if s.autostart {
                autostart.enable()
            } else {
                // Windows reports NotFound when removing a Run entry that isn't
                // there, so turning off what is already off would warn.
                autostart
                    .is_enabled()
                    .and_then(|on| if on { autostart.disable() } else { Ok(()) })
            };
            if let Err(e) = result {
                warnings.push(trf(
                    "Não foi possível atualizar a inicialização automática: {0}",
                    &[&e],
                ));
            }
        }

        use tauri_plugin_global_shortcut::GlobalShortcutExt;
        let gs = app.global_shortcut();
        let _ = gs.unregister_all();
        if s.hotkey_enabled && !s.hotkey.trim().is_empty() {
            if let Err(e) = gs.register(s.hotkey.as_str()) {
                warnings.push(trf(
                    "Não foi possível registrar o atalho (ele pode estar em uso): {0}",
                    &[&e],
                ));
            }
        }
        if s.blur_hotkey_enabled && !s.blur_hotkey.trim().is_empty() {
            if same_shortcut(&s.blur_hotkey, &s.hotkey) {
                warnings.push(trf(
                    "O atalho para desfocar não pode ser igual ao atalho de mostrar/ocultar: {0}",
                    &[&s.blur_hotkey],
                ));
            } else if let Err(e) = gs.register(s.blur_hotkey.as_str()) {
                warnings.push(trf(
                    "Não foi possível registrar o atalho (ele pode estar em uso): {0}",
                    &[&e],
                ));
            }
        }
        if warnings.is_empty() {
            None
        } else {
            Some(warnings.join("; "))
        }
    }
    #[cfg(not(desktop))]
    {
        let _ = (app, s);
        None
    }
}

#[cfg(test)]
mod tests {
    use super::{sanitize_zoom, step_zoom, Settings, ZoomAction, ZOOM_MAX, ZOOM_MIN, ZOOM_STEPS};

    #[cfg(target_os = "linux")]
    use super::{flatpak_autostart_entry, is_valid_flatpak_id};

    #[test]
    fn old_settings_keep_default_download_folder_and_icon() {
        let s: Settings = serde_json::from_str(r#"{"notifications":false}"#).unwrap();
        assert_eq!(s.download_dir, None);
        assert!(!s.custom_icon);
        let blank = Settings {
            download_dir: Some("  ".into()),
            ..Settings::default()
        };
        assert_eq!(blank.sanitized().download_dir, None);
    }

    #[test]
    fn old_settings_enable_new_notification_preferences() {
        let s: Settings = serde_json::from_str(r#"{"notifications":false}"#).unwrap();
        assert!(!s.notifications);
        assert!(s.notify_when_focused && s.notify_active_chat && s.respect_muted);
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn flatpak_id_validation_blocks_path_and_desktop_entry_injection() {
        assert!(is_valid_flatpak_id("io.github.o365serveronms.zalors"));
        assert!(!is_valid_flatpak_id("../../autostart"));
        assert!(!is_valid_flatpak_id(
            "io.github.o365serveronms.zalors\nExec=sh"
        ));
        assert!(!is_valid_flatpak_id("io..Zalo"));
        assert!(!is_valid_flatpak_id("io.github.505Zalo"));
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn flatpak_autostart_entry_reenters_the_sandbox() {
        let entry = flatpak_autostart_entry("io.github.o365serveronms.zalors");
        assert!(entry.contains(
            "Exec=flatpak run --command=zalors io.github.o365serveronms.zalors --minimized"
        ));
        assert!(entry.contains("Icon=io.github.o365serveronms.zalors"));
        assert!(entry.contains("X-Flatpak=io.github.o365serveronms.zalors"));
        assert!(!entry.contains("Exec=/app/bin/zalors"));
    }

    #[test]
    fn defaults_are_sane() {
        let s = Settings::default();
        assert!(s.close_to_tray);
        assert!(s.notifications);
        // The menu-bar mode is opt-in.
        assert!(!s.menubar_only);
        assert_eq!(s.hotkey, "CmdOrCtrl+Shift+W");
        assert!(!s.autostart);
        assert_eq!(s.zoom, 1.0);
        assert!(s.menu_bar_icon);
    }

    #[test]
    fn zoom_steps_are_in_range_and_ascending() {
        assert!(ZOOM_STEPS.windows(2).all(|w| w[0] < w[1]));
        assert_eq!(ZOOM_STEPS[0], ZOOM_MIN);
        assert_eq!(ZOOM_STEPS[ZOOM_STEPS.len() - 1], ZOOM_MAX);
        assert!(ZOOM_STEPS.contains(&1.0));
    }

    #[test]
    fn zoom_in_and_out_walk_the_levels() {
        assert_eq!(step_zoom(1.0, ZoomAction::In), 1.15);
        assert_eq!(step_zoom(1.0, ZoomAction::Out), 0.85);
        assert_eq!(step_zoom(1.15, ZoomAction::Out), 1.0);
        assert_eq!(step_zoom(0.75, ZoomAction::In), 0.85);
        assert_eq!(step_zoom(1.5, ZoomAction::Reset), 1.0);
    }

    #[test]
    fn zoom_stops_at_the_ends() {
        assert_eq!(step_zoom(ZOOM_MAX, ZoomAction::In), ZOOM_MAX);
        assert_eq!(step_zoom(ZOOM_MIN, ZoomAction::Out), ZOOM_MIN);
    }

    #[test]
    fn off_grid_zoom_lands_on_the_next_level() {
        assert_eq!(step_zoom(1.05, ZoomAction::In), 1.15);
        assert_eq!(step_zoom(1.05, ZoomAction::Out), 1.0);
        assert_eq!(step_zoom(f64::NAN, ZoomAction::In), 1.15);
        assert_eq!(step_zoom(9.0, ZoomAction::Out), 1.75);
    }

    #[test]
    fn zoom_action_parses_only_known_names() {
        assert_eq!(ZoomAction::parse("in"), Some(ZoomAction::In));
        assert_eq!(ZoomAction::parse("sideways"), None);
    }

    #[test]
    fn zoom_presets_survive_sanitizing() {
        for z in [0.75, 0.85, 1.0, 1.15] {
            assert_eq!(sanitize_zoom(z), z);
        }
    }

    #[test]
    fn out_of_range_zoom_is_clamped() {
        assert_eq!(sanitize_zoom(0.01), ZOOM_MIN);
        assert_eq!(sanitize_zoom(9.0), ZOOM_MAX);
        assert_eq!(sanitize_zoom(-1.0), ZOOM_MIN);
    }

    #[test]
    fn non_finite_zoom_falls_back_to_unscaled() {
        assert_eq!(sanitize_zoom(f64::NAN), 1.0);
        assert_eq!(sanitize_zoom(f64::INFINITY), 1.0);
    }

    #[test]
    fn zoom_from_json_is_sanitized() {
        let s: Settings = serde_json::from_str(r#"{"zoom": 12}"#).unwrap();
        assert_eq!(s.sanitized().zoom, ZOOM_MAX);
        // Absent in a settings.json written by an older build.
        let s: Settings = serde_json::from_str(r#"{"autostart": true}"#).unwrap();
        assert_eq!(s.sanitized().zoom, 1.0);
    }

    #[test]
    fn partial_json_fills_defaults() {
        let s: Settings = serde_json::from_str(r#"{"autostart": true}"#).unwrap();
        assert!(s.autostart);
        assert!(s.close_to_tray);
        assert_eq!(s.hotkey, "CmdOrCtrl+Shift+W");
        // Absent in a settings.json written before issue #44: keep the icon.
        assert!(s.menu_bar_icon);
    }

    #[test]
    fn empty_json_is_all_defaults() {
        let s: Settings = serde_json::from_str("{}").unwrap();
        assert_eq!(s, Settings::default());
    }

    #[test]
    fn old_shadow_settings_load_without_own_uid_fields() {
        // A settings.json written before batch 4 carries neither
        // own_uid nor own_uin_hash; both must deserialize to None
        // (`#[serde(default)]` on the struct) and every other shadow
        // field keeps its stored value.
        let s: Settings = serde_json::from_str(
            r#"{"shadow":{"enabled":true,"raw_events_days":7,"batch_ms":200,"batch_max":500}}"#,
        )
        .unwrap();
        assert!(s.shadow.enabled);
        assert_eq!(s.shadow.raw_events_days, 7);
        assert_eq!(s.shadow.own_uid, None);
        assert_eq!(s.shadow.own_uin_hash, None);
        // The bare shadow object with no fields at all is the same.
        let s: Settings = serde_json::from_str(r#"{"shadow":{}}"#).unwrap();
        assert_eq!(s.shadow.own_uid, None);
        assert_eq!(s.shadow.own_uin_hash, None);
    }

    #[test]
    fn shadow_own_identity_roundtrips() {
        // Written-back settings keep the configured identity (the
        // flusher reads exactly these fields at start).
        let mut s = Settings::default();
        s.shadow.own_uid = Some("1234567890123456789".into()); // FAKE uid
        s.shadow.own_uin_hash = Some("abc123def456".into()); // FAKE hash
        let json = serde_json::to_string(&s).unwrap();
        let back: Settings = serde_json::from_str(&json).unwrap();
        assert_eq!(back.shadow.own_uid.as_deref(), Some("1234567890123456789"));
        assert_eq!(back.shadow.own_uin_hash.as_deref(), Some("abc123def456"));
    }

    #[test]
    fn shadow_settings_roundtrip_keeps_every_field_untouched() {
        // Batch 7 G1: a settings save that does not touch the shadow
        // section must keep the stored media_store / own_uid /
        // own_uin_hash verbatim — `set_settings` persists exactly this
        // struct, so its serialization is the round-trip contract.
        let mut s = Settings::default();
        s.shadow.media_store = Some("D:\\ZaloRust Data".into()); // documented install default
        s.shadow.own_uid = Some("1234567890123456789".into()); // FAKE uid
        s.shadow.own_uin_hash = Some("abc123def456".into()); // FAKE hash
        let json = serde_json::to_string(&s).unwrap();
        let back: Settings = serde_json::from_str(&json).unwrap();
        assert_eq!(back, s, "the whole struct survives a save cycle");
        assert_eq!(back.shadow.media_store.as_deref(), Some("D:\\ZaloRust Data"));
        assert_eq!(back.shadow.own_uid.as_deref(), Some("1234567890123456789"));
        assert_eq!(back.shadow.own_uin_hash.as_deref(), Some("abc123def456"));
    }

    #[test]
    fn old_shadow_settings_load_without_backup_fields() {
        // Batch 8 H4: a settings.json written before this batch carries
        // none of the five backup fields — `#[serde(default)]` on the
        // struct fills them with the OFF-by-default values, and every
        // stored field keeps its value.
        let s: Settings = serde_json::from_str(
            r#"{"shadow":{"enabled":true,"media_store":"D:\\ZaloRust Data","own_uid":"1234567890123456789"}}"#,
        )
        .unwrap();
        assert!(s.shadow.enabled);
        assert!(!s.shadow.backup_enabled, "backups are opt-in");
        assert_eq!(s.shadow.backup_dir, None);
        assert_eq!(s.shadow.backup_interval_hours, 6);
        assert_eq!(s.shadow.disk_warn_pct, 10);
        assert_eq!(s.shadow.disk_stop_pct, 3);
        assert_eq!(s.shadow.media_store.as_deref(), Some("D:\\ZaloRust Data"));
        // The bare shadow object is the same.
        let s: Settings = serde_json::from_str(r#"{"shadow":{}}"#).unwrap();
        assert!(!s.shadow.backup_enabled);
        assert_eq!(s.shadow.backup_interval_hours, 6);
    }

    #[test]
    fn backup_settings_roundtrip_and_off_by_default() {
        // The whole struct survives a save cycle (the flusher and the
        // backup thread read exactly these fields at start).
        let mut s = Settings::default();
        assert!(!s.shadow.backup_enabled, "OFF by default (H4)");
        assert_eq!(s.shadow.backup_dir, None);
        s.shadow.backup_enabled = true;
        s.shadow.backup_dir = Some(r"D:\ZaloRust Backups".into());
        s.shadow.backup_interval_hours = 12;
        s.shadow.disk_warn_pct = 15;
        s.shadow.disk_stop_pct = 5;
        let json = serde_json::to_string(&s).unwrap();
        let back: Settings = serde_json::from_str(&json).unwrap();
        assert_eq!(back, s);
        assert_eq!(back.shadow.backup_dir.as_deref(), Some(r"D:\ZaloRust Backups"));
        assert_eq!(back.shadow.backup_interval_hours, 12);
        assert_eq!(back.shadow.disk_warn_pct, 15);
        assert_eq!(back.shadow.disk_stop_pct, 5);
    }

    #[test]
    fn hand_edited_backup_numbers_are_clamped() {
        // A hand-edited settings.json must not leave the backup thread
        // spinning (0-hour interval) or the thresholds meaningless.
        let mut s = Settings::default();
        s.shadow.backup_interval_hours = 0;
        s.shadow.disk_warn_pct = 200; // > u8 range of a percent
        s.shadow.disk_stop_pct = 255;
        let s = s.sanitized();
        assert_eq!(s.shadow.backup_interval_hours, 1);
        assert_eq!(s.shadow.disk_warn_pct, 100);
        assert_eq!(s.shadow.disk_stop_pct, 100);
        // Sane values pass through untouched.
        let mut s = Settings::default();
        s.shadow.backup_interval_hours = 6;
        s.shadow.disk_warn_pct = 10;
        s.shadow.disk_stop_pct = 3;
        let c = s.clone();
        assert_eq!(s.sanitized().shadow, c.shadow);
    }

    // --- batch 15 O4: the AppHandle-free settings loader -------------

    /// A fresh unique temp dir (synthetic settings files only).
    fn tmp(tag: &str) -> std::path::PathBuf {
        let ms = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_millis())
            .unwrap_or(0);
        let dir = std::env::temp_dir().join(format!("zr-settings-{tag}-{}-{ms}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[test]
    fn load_at_reads_a_synthetic_file_through_the_same_loader() {
        // A FAKE uid of the documented shape (never a real one).
        let dir = tmp("loadat");
        let file = dir.join("settings.json");
        std::fs::write(
            &file,
            r#"{"shadow":{"enabled":true,"own_uid":"1234567890123456789","raw_events_days":9}}"#,
        )
        .unwrap();
        let s = super::load_at(&file);
        assert!(s.shadow.enabled);
        assert_eq!(s.shadow.raw_events_days, 9);
        assert_eq!(s.shadow.own_uid.as_deref(), Some("1234567890123456789"));
        // The sanitizer runs on this path too (hand-edited clamps).
        std::fs::write(
            &file,
            r#"{"zoom": 99, "shadow":{"backup_interval_hours":0,"disk_warn_pct":200}}"#,
        )
        .unwrap();
        let s = super::load_at(&file);
        assert_eq!(s.zoom, ZOOM_MAX);
        assert_eq!(s.shadow.backup_interval_hours, 1);
        assert_eq!(s.shadow.disk_warn_pct, 100);
        // Missing file → defaults, no error surface.
        let s = super::load_at(&dir.join("nope.json"));
        assert_eq!(s, Settings::default());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn load_at_never_writes_not_even_for_a_corrupt_file() {
        // The import CLI's contract is ZERO writes: a corrupt file
        // yields defaults and leaves the directory untouched (no
        // `.corrupt-*` copy — that is the app loader's job).
        let dir = tmp("loadcor");
        let file = dir.join("settings.json");
        std::fs::write(&file, "definitely not json").unwrap();
        let s = super::load_at(&file);
        assert_eq!(s, Settings::default());
        let names: Vec<String> = std::fs::read_dir(&dir)
            .unwrap()
            .flatten()
            .map(|e| e.file_name().to_string_lossy().into_owned())
            .collect();
        assert_eq!(names, vec!["settings.json".to_string()], "nothing was written");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn path_without_app_mirrors_the_app_config_dir_shape() {
        if let Some(p) = super::path_without_app() {
            assert!(p.is_absolute());
            let s = p.to_string_lossy();
            assert!(
                s.replace('/', "\\")
                    .ends_with("com.o365serveronms.zalors\\settings.json"),
                "{s}"
            );
        } else {
            // APPDATA unset (unusual, but the function must not panic).
            assert!(std::env::var_os("APPDATA").is_none());
        }
    }

    #[test]
    fn roundtrip() {
        let s = Settings {
            autostart: true,
            hotkey: "Ctrl+Alt+W".into(),
            ..Default::default()
        };
        let json = serde_json::to_string(&s).unwrap();
        let back: Settings = serde_json::from_str(&json).unwrap();
        assert_eq!(s, back);
    }
    #[test]
    fn explicit_foreground_launch_overrides_background_preference() {
        let args = |items: &[&str]| items.iter().map(|s| s.to_string()).collect::<Vec<_>>();
        assert_eq!(super::start_hidden(true, &args(&[])), !cfg!(windows));
        assert_eq!(
            super::start_hidden(false, &args(&["--minimized"])),
            !cfg!(windows)
        );
        assert!(!super::start_hidden(true, &args(&["--show"])));
        assert!(!super::start_hidden(
            true,
            &args(&["--show", "--minimized"])
        ));
        assert!(!super::start_hidden(false, &args(&[])));
    }

    #[cfg(windows)]
    #[test]
    fn start_minimized_only_affects_system_autostart() {
        assert!(!super::start_hidden(true, &[]));
        assert!(super::start_hidden(true, &["--autostart".into()]));
        assert!(!super::start_hidden(false, &["--autostart".into()]));
        assert!(!super::start_hidden(false, &["--minimized".into()]));
        assert!(!super::start_hidden(
            true,
            &["--autostart".into(), "--show".into()]
        ));
    }
}

#[cfg(all(test, desktop))]
mod blur_shortcut_tests {
    use super::{is_blur_shortcut, same_shortcut, Settings};
    use tauri_plugin_global_shortcut::Shortcut;

    #[test]
    fn blur_shortcut_is_off_by_default() {
        let s = Settings::default();
        assert!(!s.blur_hotkey_enabled);
        let b: Shortcut = s.blur_hotkey.parse().unwrap();
        assert!(!is_blur_shortcut(&s, &b));
    }

    #[test]
    fn enabled_blur_shortcut_matches_only_itself() {
        let s = Settings {
            blur_hotkey_enabled: true,
            ..Settings::default()
        };
        let blur: Shortcut = "CmdOrCtrl+Shift+B".parse().unwrap();
        let toggle: Shortcut = s.hotkey.parse().unwrap();
        assert!(is_blur_shortcut(&s, &blur));
        assert!(!is_blur_shortcut(&s, &toggle));
    }

    #[test]
    fn show_hide_shortcut_wins_a_tie() {
        let s = Settings {
            blur_hotkey_enabled: true,
            blur_hotkey: "Shift+CmdOrCtrl+W".into(),
            ..Settings::default()
        };
        assert!(same_shortcut(&s.blur_hotkey, &s.hotkey));
        let pressed: Shortcut = s.hotkey.parse().unwrap();
        assert!(!is_blur_shortcut(&s, &pressed));
    }

    #[test]
    fn unparseable_shortcuts_never_match() {
        assert!(!same_shortcut("not a key", "not a key"));
    }
}
