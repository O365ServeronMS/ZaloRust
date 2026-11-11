# Zalo — Unofficial Zalo Web Desktop Client (Rust + Tauri)

> **Unofficial, independent project** — not affiliated with, endorsed by, or sponsored by VNG Corporation or Zalo. Zalo simply loads the official `chat.zalo.me` interface in a native system webview. "Zalo" is a trademark of its owner.

Zalo is a lightweight desktop wrapper for [Zalo Web](https://chat.zalo.me), derived from the MIT-licensed [whatRust](https://github.com/karem505/whatRust) by Karem. It reuses the operating system's webview (WebView2 on Windows, WebKitGTK on Linux, WKWebView on macOS) instead of bundling a browser engine, via [Tauri v2](https://tauri.app).

## Status — please read

**This is an early port. Windows 10/11 is the target platform.** The shell features inherited from whatRust (tray, close-to-tray, window state, proxy, downloads, app lock, auto-start, global shortcut, single instance, updater) do not depend on the page and are unit-tested. Everything that depends on **Zalo Web's own page** could not be verified against a live account when this port was written:

| Area | State |
|---|---|
| Loading `chat.zalo.me`, login by QR / phone | Expected to work (it is the normal web page); needs a real-device check |
| Unread badge | Reads the page title as `(n) …` or `[n] …`. Zalo's real title format is **unverified**. The log records the title's *shape* (digits masked) so it can be confirmed |
| Native notifications | Hooks the standard web `Notification` / service-worker APIs. Works only if Zalo Web uses them |
| Message-based notification fallback, per-chat mute detection, privacy blur | Inherited from whatRust and tied to WhatsApp's page structure. **Not adapted**; they do nothing on Zalo |
| Multiple accounts | Isolated profiles per window. Zalo may limit concurrent web sessions per account; this is Zalo's rule and is not worked around |
| Voice / video calls | Not offered by Zalo Web. Zalo does not disguise the browser or OS to obtain them |
| Drag & drop of files | Windows/macOS use the webview's native drop. The Linux injection path targets WhatsApp's page and is unverified for Zalo |

## Features (shell)

- Multiple accounts, each in its own window with an isolated session
- System tray, close-to-tray, unread badge (see Status)
- Native OS notifications (see Status)
- Optional app lock (Argon2id password; Windows Hello / Touch ID / polkit)
- SOCKS5 / HTTP proxy (no credentials), custom download folder, display zoom
- Launch at startup, global show/hide shortcut (`zalors --toggle` on Wayland)
- Optional update check against this repository's GitHub Releases, verified with SHA-256 (Settings → Updates; can be turned off)

## Build from source

```bash
# Linux build dependencies (Ubuntu/Debian)
sudo apt install -y libwebkit2gtk-4.1-dev build-essential curl wget file \
  libxdo-dev libssl-dev libayatana-appindicator3-dev librsvg2-dev libhunspell-dev patchelf
cargo install tauri-cli --version "^2.0" --locked
cargo tauri dev        # run in development
cargo tauri build      # installers for the current OS
cd src-tauri && cargo test
```

## Releases and versioning

- Versions are calendar versions `YYYY.M.D` (e.g. `2026.11.10`). **No leading zeros** (`2026.12.5`, not `2026.12.05`): the version must stay valid semver for Cargo, NSIS and the in-app updater. A follow-up release on the same day takes the next day's number (e.g. `2026.11.11`).
- Only the Windows NSIS installer is built. To release: bump `version` in `src-tauri/Cargo.toml` and `src-tauri/tauri.conf.json`, add `docs/release-notes/vYYYY.M.D.md`, push, then push the tag `vYYYY.M.D`; the `windows-build` workflow publishes the GitHub Release with the installer and `SHA256SUMS`.
- The installer defaults to `%LOCALAPPDATA%\zalo-web`.
- The repository is private, so the in-app update check cannot read its releases until it is made public; it then reports that the releases are not reachable.

## Diagnostics

The log (`%LOCALAPPDATA%\zalo-web\logs\zalors.log` on Windows) records routing and page-health events, never message content or contact names. When reporting a problem, attach it.

## Disclaimer & license

Zalo only displays the official `chat.zalo.me` page and does not modify or intercept Zalo's services. Use of Zalo remains subject to Zalo's terms. Released under the [MIT License](LICENSE); the original copyright notice of whatRust is retained.
