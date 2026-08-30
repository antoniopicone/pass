#!/usr/bin/env bash
# One-shot pre-build check: Rust unit tests + the full Chrome-extension
# end-to-end suite. Run this before packaging/shipping the extension:
#
#   chrome-extension/tests/run_tests.sh
#
# Requires: cargo, a Python 3 with `pip install -r requirements.txt` done
# once, and Brave or Chrome installed locally.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
VENV_DIR="$SCRIPT_DIR/.venv"

echo "==> Rust workspace tests (passlib, passlib_ffi, pass-native-host, passcli)"
(cd "$REPO_ROOT" && cargo test --workspace --exclude pass-gnome)

echo
echo "==> Preparing Python environment for the browser test suite"
if [ ! -d "$VENV_DIR" ]; then
  python3 -m venv "$VENV_DIR"
fi
"$VENV_DIR/bin/pip" install --quiet --upgrade pip
"$VENV_DIR/bin/pip" install --quiet -r "$SCRIPT_DIR/requirements.txt"

echo
echo "==> Registering the native messaging host for the extension's fixed ID"
EXTENSION_ID="$("$VENV_DIR/bin/python3" "$SCRIPT_DIR/run_tests.py" --print-extension-id)"
"$REPO_ROOT/chrome-extension/native-host/install.sh" "$EXTENSION_ID"

echo
echo "==> Chrome extension end-to-end suite"
"$VENV_DIR/bin/python3" "$SCRIPT_DIR/run_tests.py" "$@"
