#!/bin/sh
set -eu

APP_ID="io.github.o365serveronms.zalors"
BASE_URL="https://github.com/O365ServeronMS/ZaloRust/releases/latest/download"

if ! command -v flatpak >/dev/null 2>&1; then
  printf '%s\n' "Flatpak is required. Install it from https://flatpak.org/setup/ and run this installer again." >&2
  exit 1
fi
if ! command -v curl >/dev/null 2>&1; then
  printf '%s\n' "curl is required to download Zalo." >&2
  exit 1
fi

case "$(uname -m)" in
  x86_64|amd64) ARCH="x86_64" ;;
  aarch64|arm64) ARCH="aarch64" ;;
  *)
    printf 'Unsupported architecture: %s\n' "$(uname -m)" >&2
    exit 1
    ;;
esac

TMP_DIR="$(mktemp -d "${TMPDIR:-/tmp}/zalors-flatpak.XXXXXX")"
TMP="$TMP_DIR/Zalo_${ARCH}.flatpak"
cleanup() {
  rm -f "$TMP"
  rmdir "$TMP_DIR" 2>/dev/null || :
}
trap cleanup EXIT
trap 'exit 1' HUP INT TERM

flatpak remote-add --if-not-exists --user flathub \
  https://dl.flathub.org/repo/flathub.flatpakrepo
curl -fL --retry 3 --progress-bar \
  "$BASE_URL/Zalo_${ARCH}.flatpak" -o "$TMP"
if flatpak info --user "$APP_ID" >/dev/null 2>&1; then
  flatpak install --user --reinstall -y "$TMP"
else
  flatpak install --user -y "$TMP"
fi

printf '%s\n' "Zalo is installed. Launch it from your application menu or run:"
printf '  flatpak run %s\n' "$APP_ID"
