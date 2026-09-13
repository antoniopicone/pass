#!/usr/bin/env bash
# Builds pass-syncd and installs it as a per-user systemd service on Linux,
# started at login and kept running (Restart=on-failure) — the long-running
# daemon every pass client (CLI/native-host/GNOME) talks to on the loopback
# API while the vault is unlocked. Styled after
# chrome-extension/native-host/install.sh's structure.
#
# Usage: ./install-systemd.sh [-- extra pass-syncd serve args]
# Example: ./install-systemd.sh -- --device my-laptop --bootstrap 100.64.0.2:47210

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
EXTRA_ARGS=("$@")

echo "Building pass-syncd (release)…"
(cd "$REPO_ROOT" && cargo build --release -p pass-syncd)

BINARY_PATH="$REPO_ROOT/target/release/pass-syncd"
if [ ! -x "$BINARY_PATH" ]; then
  echo "Expected binary not found at $BINARY_PATH" >&2
  exit 1
fi

UNIT_DIR="$HOME/.config/systemd/user"
mkdir -p "$UNIT_DIR"
UNIT_PATH="$UNIT_DIR/pass-syncd.service"

EXEC_START="$BINARY_PATH serve"
if [ ${#EXTRA_ARGS[@]} -gt 0 ]; then
  EXEC_START="$EXEC_START ${EXTRA_ARGS[*]}"
fi

sed -e "s#__BINARY_PATH__#$BINARY_PATH#" "$SCRIPT_DIR/pass-syncd.service.template" > "$UNIT_PATH"
if [ ${#EXTRA_ARGS[@]} -gt 0 ]; then
  sed -i "s#^ExecStart=.*#ExecStart=$EXEC_START#" "$UNIT_PATH"
fi

systemctl --user daemon-reload
systemctl --user enable --now pass-syncd.service

echo "Installed and started: $UNIT_PATH"
echo "Check status with: systemctl --user status pass-syncd"
echo "Follow logs with:   journalctl --user -u pass-syncd -f"
