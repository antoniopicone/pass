#!/usr/bin/env bash
# Builds pass-native-host and registers it as a Chrome/Chromium native
# messaging host for the Pass extension.
#
# Usage: ./install.sh <extension-id>
#
# <extension-id> is shown on chrome://extensions once the unpacked
# extension in chrome-extension/ has been loaded (enable Developer mode
# first). Re-run this script if the extension ID changes (e.g. after
# reloading it from a different path).

set -euo pipefail

if [ $# -ne 1 ]; then
  echo "Usage: $0 <extension-id>" >&2
  exit 1
fi

EXTENSION_ID="$1"
HOST_NAME="com.antoniopicone.pass_native_host"

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"

echo "Building pass-native-host (release)…"
(cd "$REPO_ROOT" && cargo build --release -p pass-native-host)

BINARY_PATH="$REPO_ROOT/target/release/$HOST_NAME"
if [ ! -x "$BINARY_PATH" ]; then
  echo "Expected binary not found at $BINARY_PATH" >&2
  exit 1
fi

MANIFEST_PATH="$SCRIPT_DIR/$HOST_NAME.json"
cat > "$MANIFEST_PATH" <<JSON
{
  "name": "$HOST_NAME",
  "description": "Pass password manager native messaging host",
  "path": "$BINARY_PATH",
  "type": "stdio",
  "allowed_origins": [
    "chrome-extension://$EXTENSION_ID/"
  ]
}
JSON

install_for_dir() {
  local dir="$1"
  local label="$2"
  if [ -d "$(dirname "$dir")" ]; then
    mkdir -p "$dir"
    cp "$MANIFEST_PATH" "$dir/$HOST_NAME.json"
    echo "Installed for $label: $dir/$HOST_NAME.json"
  fi
}

case "$(uname -s)" in
  Darwin)
    install_for_dir "$HOME/Library/Application Support/Google/Chrome/NativeMessagingHosts" "Chrome (macOS)"
    install_for_dir "$HOME/Library/Application Support/Chromium/NativeMessagingHosts" "Chromium (macOS)"
    ;;
  Linux)
    install_for_dir "$HOME/.config/google-chrome/NativeMessagingHosts" "Chrome (Linux)"
    install_for_dir "$HOME/.config/chromium/NativeMessagingHosts" "Chromium (Linux)"
    ;;
  *)
    echo "Unsupported OS: $(uname -s). Copy $MANIFEST_PATH manually into your browser's" \
         "NativeMessagingHosts directory (see https://developer.chrome.com/docs/extensions/develop/concepts/native-messaging)." >&2
    ;;
esac

echo "Done. Reload the extension (or restart the browser) for the change to take effect."
