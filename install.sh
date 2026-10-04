#!/usr/bin/env bash
# Top-level installer for `pass`: detects the OS and installs whatever
# makes sense there — the CLI, the pass-syncd real-time sync service, and
# the native GUI app (pass-gnome on Linux; pass-apple needs Xcode on a
# real Mac, so this only points you at its README). Each piece also has
# its own narrower install script (pass-syncd/service/, chrome-extension/
# native-host/, pass-howdy/) if you only want one of them — this is just
# the "do everything sensible for this machine" entry point.
#
# Usage:
#   ./install.sh                          # CLI + sync service + GUI app
#   ./install.sh --extension-id ID        # ...and register the Chromium
#                                          # native messaging host for the
#                                          # already-loaded extension ID
#   ./install.sh --with-howdy             # ...and set up the pass-howdy
#                                          # PAM service (needs sudo — see
#                                          # pass-howdy/setup-pam-service.sh)
#   ./install.sh --skip-gui               # CLI + sync service only

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
OS="$(uname -s)"

EXTENSION_ID=""
WITH_HOWDY=0
SKIP_GUI=0

while [ $# -gt 0 ]; do
  case "$1" in
    --extension-id) EXTENSION_ID="${2:-}"; shift 2 ;;
    --with-howdy) WITH_HOWDY=1; shift ;;
    --skip-gui) SKIP_GUI=1; shift ;;
    -h|--help)
      sed -n '2,17p' "$0"
      exit 0
      ;;
    *) echo "Unknown option: $1" >&2; exit 1 ;;
  esac
done

echo "== Pass installer =="
echo "Detected OS: $OS"
echo "Repo: $REPO_ROOT"
echo

# --------------------------------------------------------------- libclang
#
# passcli/pass-gnome/pass-native-host all depend (transitively, via
# pass-howdy) on pam-client, whose build script uses bindgen to generate
# PAM's FFI bindings at compile time — which needs libclang. Ubuntu/Debian
# ship libclang's runtime .so (versioned, e.g. libclang-18.so.1) without
# the unversioned `libclang.so` symlink bindgen's clang-sys looks for
# unless the `libclang-dev` package is installed. Rather than requiring
# that package, look for any installed libclang and point clang-sys at it
# via a local symlink shim — no sudo, nothing installed system-wide.
ensure_libclang() {
  if [ -n "${LIBCLANG_PATH:-}" ]; then
    return
  fi
  # A libclang.so already resolvable (e.g. libclang-dev is installed)?
  if command -v ldconfig >/dev/null 2>&1 && ldconfig -p 2>/dev/null | grep -q "libclang\.so "; then
    return
  fi

  local found
  # Numeric versions only (libclang-21.so.21) — excludes libclang-cpp.so.*,
  # the separate C++ interface library, which is not what clang-sys wants.
  found="$(find /usr/lib /usr/lib64 /usr/local/lib -maxdepth 4 -iname "libclang-[0-9]*.so.*" 2>/dev/null | sort -V | tail -1)"
  if [ -z "$found" ]; then
    return # nothing found; let cargo's own error message guide the user
  fi

  local shim_dir="$HOME/.cache/pass-build/libclang-shim"
  mkdir -p "$shim_dir"
  ln -sf "$found" "$shim_dir/libclang.so"
  export LIBCLANG_PATH="$shim_dir"
  echo "(using $found for libclang, via a local shim at $shim_dir — no system changes made)"
}

ensure_libclang

# ------------------------------------------------------------------- CLI
#
# --locked matters here, not just as a style preference: `cargo install`
# ignores the workspace's own Cargo.lock by default and re-resolves
# dependencies from scratch, which (verified — it's what happened before
# this flag was added) can pick two incompatible major versions of a
# transitive dependency (crypto-common 0.1 vs 0.2, pulled in by different
# paths) and fail to build keepass entirely. --locked forces the exact,
# already-verified versions from Cargo.lock instead.
echo "--- Installing the CLI (pass) ---"
(cd "$REPO_ROOT" && cargo install --path passcli --force --locked)
echo

# ------------------------------------------------------------ sync service
echo "--- Installing pass-syncd (real-time sync service) ---"
case "$OS" in
  Linux) "$REPO_ROOT/pass-syncd/service/install-systemd.sh" ;;
  Darwin) "$REPO_ROOT/pass-syncd/service/install-launchd.sh" ;;
  *)
    echo "Unrecognized OS \"$OS\" for automatic install."
    echo "On Windows, run pass-syncd\\service\\install-windows.ps1 from PowerShell instead."
    ;;
esac
echo

# ------------------------------------------------------------------- GUI
if [ "$SKIP_GUI" -eq 0 ]; then
  case "$OS" in
    Linux)
      echo "--- Installing the GNOME app (pass-gnome) ---"
      (cd "$REPO_ROOT" && cargo build --release -p pass-gnome)
      BINARY_PATH="$REPO_ROOT/target/release/pass-gnome"

      ICON_DEST="$HOME/.local/share/icons/hicolor"
      mkdir -p "$ICON_DEST"
      cp -r "$REPO_ROOT/pass-gnome/icons/hicolor/." "$ICON_DEST/"

      APPS_DIR="$HOME/.local/share/applications"
      mkdir -p "$APPS_DIR"
      sed "s#__BINARY_PATH__#$BINARY_PATH#" \
        "$REPO_ROOT/pass-gnome/it.antoniopicone.Pass.desktop.template" \
        > "$APPS_DIR/it.antoniopicone.Pass.desktop"

      command -v gtk-update-icon-cache >/dev/null 2>&1 && gtk-update-icon-cache -q -t -f "$ICON_DEST" 2>/dev/null || true
      command -v update-desktop-database >/dev/null 2>&1 && update-desktop-database -q "$APPS_DIR" 2>/dev/null || true

      echo "Installed: $BINARY_PATH"
      echo "Desktop entry: $APPS_DIR/it.antoniopicone.Pass.desktop"
      echo "(a StatusNotifierItem top-bar icon is offered when the app runs — on"
      echo " stock/vanilla GNOME Shell this needs the \"AppIndicator and"
      echo " KStatusNotifierItem Support\" extension to actually be visible;"
      echo " Ubuntu ships it by default. The app works fully without it either way.)"
      ;;
    Darwin)
      echo "--- macOS/iOS app (pass-apple) ---"
      echo "This needs Xcode on a real Mac — see pass-apple/README.md for the"
      echo "build-xcframework.sh + Xcode steps. Not something this script can do."
      ;;
    *)
      echo "No native GUI app for \"$OS\"."
      ;;
  esac
  echo
fi

# ----------------------------------------------------- Chromium extension
echo "--- Chromium extension native host ---"
if [ -n "$EXTENSION_ID" ]; then
  case "$OS" in
    Linux|Darwin) "$REPO_ROOT/chrome-extension/native-host/install.sh" "$EXTENSION_ID" ;;
    *) echo "Run chrome-extension\\native-host\\install.ps1 -ExtensionId $EXTENSION_ID from PowerShell instead." ;;
  esac
else
  echo "Skipped (no --extension-id given). Load chrome-extension/ unpacked in your"
  echo "browser's developer mode, then run:"
  case "$OS" in
    Linux|Darwin) echo "  chrome-extension/native-host/install.sh <extension-id>" ;;
    *) echo "  chrome-extension\\native-host\\install.ps1 -ExtensionId <extension-id>" ;;
  esac
fi
echo

# --------------------------------------------------------------- howdy
if [ "$WITH_HOWDY" -eq 1 ]; then
  echo "--- Face unlock (howdy) ---"
  case "$OS" in
    Linux) "$REPO_ROOT/pass-howdy/setup-pam-service.sh" ;;
    *) echo "howdy is Linux-only; skipping on \"$OS\"." ;;
  esac
  echo
elif [ "$OS" = "Linux" ]; then
  echo "Tip: run with --with-howdy to set up \"unlock with your face\" (needs"
  echo "howdy already installed — https://github.com/boltgolt/howdy — and sudo"
  echo "for one isolated PAM service file; see pass-howdy/setup-pam-service.sh)."
  echo
fi

echo "== Done =="
