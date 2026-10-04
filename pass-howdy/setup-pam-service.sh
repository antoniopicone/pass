#!/usr/bin/env bash
# Installs the isolated `pass-howdy` PAM service (see pass-howdy.pam.template
# and src/lib.rs's module doc comment) at /etc/pam.d/pass-howdy, so
# passcli/pass-gnome/the Chromium extension can offer "unlock with your
# face" via howdy (https://github.com/boltgolt/howdy).
#
# Needs sudo (PAM service files live under /etc/pam.d/) — this is the only
# step in the whole project that touches system configuration outside the
# user's own home directory, and it creates a brand-new, self-contained
# service file rather than editing any existing one (sudo, login, etc. are
# left untouched).
#
# Usage: ./setup-pam-service.sh

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SERVICE_FILE="/etc/pam.d/pass-howdy"

if ! command -v howdy >/dev/null 2>&1; then
  echo "howdy doesn't seem to be installed (no 'howdy' command found)." >&2
  echo "Install it first: https://github.com/boltgolt/howdy#installation" >&2
  exit 1
fi

MODULE_PATH=""
for candidate in \
  /usr/lib/x86_64-linux-gnu/security/pam_howdy.so \
  /usr/lib/aarch64-linux-gnu/security/pam_howdy.so \
  /usr/lib/i386-linux-gnu/security/pam_howdy.so \
  /usr/lib64/security/pam_howdy.so \
  /usr/lib/security/pam_howdy.so \
  /lib/security/pam_howdy.so
do
  if [ -f "$candidate" ]; then
    MODULE_PATH="$candidate"
    break
  fi
done

if [ -z "$MODULE_PATH" ]; then
  echo "howdy's PAM module (pam_howdy.so) was not found in any of the usual locations." >&2
  echo "Is howdy fully installed (not just the CLI)? Check its own setup instructions." >&2
  exit 1
fi

echo "Found pam_howdy.so at: $MODULE_PATH"

if [ -f "$SERVICE_FILE" ] && grep -q "$MODULE_PATH" "$SERVICE_FILE" 2>/dev/null; then
  echo "Already installed and up to date: $SERVICE_FILE"
  exit 0
fi

TMP_FILE="$(mktemp)"
sed "s#__PAM_HOWDY_MODULE_PATH__#$MODULE_PATH#" "$SCRIPT_DIR/pass-howdy.pam.template" > "$TMP_FILE"

echo "Installing $SERVICE_FILE (needs sudo)…"
sudo install -o root -g root -m 0644 "$TMP_FILE" "$SERVICE_FILE"
rm -f "$TMP_FILE"

echo "Done. \"Unlock with your face\" can now be enabled from pass/pass-gnome/the Chromium extension."
