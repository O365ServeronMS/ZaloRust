//! Links that Zalo opens itself instead of handing to a browser.
//!
//! - `https://chat.zalo.me/…` — Zalo Web's own pages. Clicked inside a chat they
//!   stay in the app instead of opening a browser tab.
//! - `zalors://…` — Zalo' private scheme. It only brings the window forward and
//!   loads the Zalo Web home page. Zalo deliberately does NOT register the
//!   `zalo:` scheme: that belongs to the official Zalo desktop app.
//!
//! Other `zalo.me` links (profile / group-invite short links) are left to the
//! default browser, because their in-app equivalents on Zalo Web are not
//! documented and have not been verified.

use tauri::{AppHandle, Manager, Url};

const WEB: &str = "https://chat.zalo.me/";

/// The Zalo Web page for a link, or `None` when `raw` isn't one we open in-app
/// (callers then fall back to just showing the window, or to the system browser).
pub fn zalo_web_url(raw: &str) -> Option<Url> {
    let url = Url::parse(raw.trim()).ok()?;
    let host = url.host_str().map(str::to_ascii_lowercase);
    match (url.scheme(), host.as_deref()) {
        ("zalors", _) => Url::parse(WEB).ok(),
        ("https", Some("chat.zalo.me")) if url.port().is_none() && url.username().is_empty() => {
            Some(url)
        }
        _ => None,
    }
}

/// The first command-line argument that is a Zalo link (`zalors:` or a
/// `chat.zalo.me` web link). Plain flags like `--minimized` are skipped.
pub fn link_from_args<S: AsRef<str>>(args: &[S]) -> Option<String> {
    args.iter()
        .map(AsRef::as_ref)
        .skip(1) // argv[0] is the program
        .find(|a| {
            a.get(..7)
                .is_some_and(|p| p.eq_ignore_ascii_case("zalors:"))
                || zalo_web_url(a).is_some()
        })
        .map(str::to_string)
}

/// Open a link from outside the app (command line, single-instance relaunch,
/// macOS open-URL event): load it in the active account's window and bring it
/// forward. The link itself is never logged.
pub fn open_from_outside(app: &AppHandle, raw: &str) {
    match zalo_web_url(raw) {
        Some(target) => {
            crate::dlog::log("links: opening a Zalo link in-app");
            if let Some(win) = active_account_window(app) {
                let _ = win.navigate(target);
            }
        }
        None => crate::dlog::log("links: unrecognized link, focusing only"),
    }
    // Defers to the lock screen when locked, like every other "reveal" path.
    crate::window::show_main(app);
}

fn active_account_window(app: &AppHandle) -> Option<tauri::Webview> {
    if let Some(active) = app.try_state::<crate::accounts::ActiveAccount>() {
        let label = crate::lock::guard(&active).clone();
        if let Some(w) = app.get_webview(&label) {
            return Some(w);
        }
    }
    app.webviews()
        .into_iter()
        .find(|(label, _)| label.starts_with("wa-"))
        .map(|(_, w)| w)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn map(raw: &str) -> Option<String> {
        zalo_web_url(raw).map(|u| u.to_string())
    }

    #[test]
    fn zalo_web_links_stay_in_the_app() {
        assert_eq!(
            map("https://chat.zalo.me/"),
            Some("https://chat.zalo.me/".into())
        );
        assert_eq!(
            map("https://CHAT.zalo.me/?x=1"),
            Some("https://chat.zalo.me/?x=1".into())
        );
    }

    #[test]
    fn private_scheme_loads_the_home_page() {
        assert_eq!(map("zalors://open"), Some("https://chat.zalo.me/".into()));
        assert_eq!(
            map("ZALORS://anything/else"),
            Some("https://chat.zalo.me/".into())
        );
    }

    #[test]
    fn other_links_are_not_zalors_links() {
        for raw in [
            "https://github.com/O365ServeronMS/ZaloRust",
            "https://zalo.me/0912345678",
            "https://zalo.me/g/abcdef",
            "http://chat.zalo.me/",
            "https://chat.zalo.me.evil.test/",
            "https://evil.test/https://chat.zalo.me/",
            "https://user@chat.zalo.me/",
            "https://chat.zalo.me:8443/",
            "zalo://conversation",
            "mailto:someone@example.com",
            "not a url",
        ] {
            assert_eq!(map(raw), None, "{raw}");
        }
    }

    #[test]
    fn the_link_is_found_among_launch_arguments() {
        assert_eq!(
            link_from_args(&["zalors", "--minimized", "zalors://open"]),
            Some("zalors://open".into())
        );
        assert_eq!(
            link_from_args(&["/usr/bin/zalors", "https://chat.zalo.me/"]),
            Some("https://chat.zalo.me/".into())
        );
        assert_eq!(link_from_args(&["zalors", "--toggle"]), None);
        // argv[0] is never taken for a link.
        assert_eq!(link_from_args(&["zalors://open"]), None);
    }
}
