# Zalo — Unofficial Zalo Web Desktop Client

> Unofficial, independent project, not affiliated with VNG Corporation or Zalo. It only loads the official `chat.zalo.me` page in a native webview. "Zalo" is a trademark of its owner.

A lightweight desktop app for [Zalo Web](https://chat.zalo.me) built with Rust and [Tauri v2](https://tauri.app). It uses the system webview (WebView2 on Windows) instead of bundling a browser. Windows 10/11 is the target platform.

## Features

- Multiple accounts, each in its own window with an isolated session
- System tray, close-to-tray, unread badge
- Native notifications (when Zalo Web uses the standard web Notification API)
- Optional app lock (password or Windows Hello)
- SOCKS5 / HTTP proxy, custom download folder, zoom
- Launch at startup, global show/hide shortcut
- In-app updates from GitHub Releases, verified with SHA-256 (Settings → Updates)

Not supported: voice/video calls (Zalo Web does not offer them).

## Install

Download `Zalo_<version>_x64-setup.exe` from [Releases](https://github.com/O365ServeronMS/ZaloRust/releases/latest). It installs to `%LOCALAPPDATA%\zalo-web`.

## Build from source

```bash
cargo install tauri-cli --version "^2.0" --locked
cargo tauri dev        # run in development
cargo tauri build      # build the installer
cd src-tauri && cargo test
```

## Releasing

Versions are `YYYY.M.D` with **no leading zeros** (`2026.12.5`, not `2026.12.05`) so they stay valid semver. A second release on the same day takes the next day's number.

1. Bump `version` in `src-tauri/Cargo.toml` and `src-tauri/tauri.conf.json`.
2. Add `docs/release-notes/vYYYY.M.D.md`.
3. Push, then push the tag `vYYYY.M.D`. The `windows-build` workflow publishes the release with the installer and `SHA256SUMS`.

## Diagnostics

The log at `%LOCALAPPDATA%\zalo-web\logs\zalors.log` records app events, never message content or contact names. Attach it when reporting a problem.

## License

[MIT](LICENSE).
