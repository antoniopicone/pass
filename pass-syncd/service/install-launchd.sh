#!/usr/bin/env bash
# Builds pass-syncd and installs it as a per-user LaunchAgent on macOS,
# started at login and kept alive (KeepAlive) — see install-systemd.sh for
# the Linux equivalent.
#
# Usage: ./install-launchd.sh

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
LABEL="com.antoniopicone.pass-syncd"

echo "Building pass-syncd (release)…"
(cd "$REPO_ROOT" && cargo build --release -p pass-syncd)

BINARY_PATH="$REPO_ROOT/target/release/pass-syncd"
if [ ! -x "$BINARY_PATH" ]; then
  echo "Expected binary not found at $BINARY_PATH" >&2
  exit 1
fi

LOG_DIR="$HOME/Library/Logs/pass-syncd"
mkdir -p "$LOG_DIR"

AGENTS_DIR="$HOME/Library/LaunchAgents"
mkdir -p "$AGENTS_DIR"
PLIST_PATH="$AGENTS_DIR/$LABEL.plist"

sed -e "s#__BINARY_PATH__#$BINARY_PATH#" -e "s#__LOG_DIR__#$LOG_DIR#" \
  "$SCRIPT_DIR/com.antoniopicone.pass-syncd.plist.template" > "$PLIST_PATH"

launchctl unload "$PLIST_PATH" >/dev/null 2>&1 || true
launchctl load -w "$PLIST_PATH"

echo "Installed and started: $PLIST_PATH"
echo "Logs: $LOG_DIR/pass-syncd.out.log / pass-syncd.err.log"
echo "Stop with: launchctl unload $PLIST_PATH"
