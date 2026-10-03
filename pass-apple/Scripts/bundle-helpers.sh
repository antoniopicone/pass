#!/bin/bash
# Xcode "Run Script" build phase for the macOS Pass app target: builds the
# `pass` CLI and the Chromium native messaging host, puts them in
# Pass.app/Contents/Helpers/ and signs them with the app's own identity and
# App Group.
#
# Why: the vault lives in the App Group container
# (~/Library/Group Containers/<TEAM_ID>.it.antoniopicone.Pass), which since
# macOS 15 only processes signed by the same team can open without a
# consent prompt. Signed and bundled like this, Chrome's native host and the
# CLI open the very vault the app and its AutoFill extension use.
#
# Everything is derived from Xcode's own build settings — DEVELOPMENT_TEAM,
# ARCHS, EXPANDED_CODE_SIGN_IDENTITY — so no Team ID is stored in the repo.
# Needs ENABLE_USER_SCRIPT_SANDBOXING = NO (set in Config/App.xcconfig):
# the script reads the Rust workspace outside the Xcode project.

set -euo pipefail

if [ "${PLATFORM_NAME:-}" != "macosx" ]; then
  exit 0
fi

if [ -z "${DEVELOPMENT_TEAM:-}" ]; then
  echo "warning: DEVELOPMENT_TEAM is not set — the CLI and Chromium native host were not bundled. Select a team under Signing & Capabilities."
  exit 0
fi

APP_GROUP="${DEVELOPMENT_TEAM}.it.antoniopicone.Pass"
REPO_ROOT="$(cd "${SRCROOT}/.." && pwd)"
HELPERS_DIR="${TARGET_BUILD_DIR}/${CONTENTS_FOLDER_PATH}/Helpers"
WORK_DIR="${DERIVED_FILE_DIR}/pass-helpers"
export PATH="${HOME}/.cargo/bin:/opt/homebrew/bin:/usr/local/bin:${PATH}"

if ! command -v cargo >/dev/null 2>&1; then
  echo "error: cargo not found — install Rust (https://rustup.rs) to bundle the CLI and native host."
  exit 1
fi

mkdir -p "$HELPERS_DIR" "$WORK_DIR"

# Rust target for each architecture Xcode is building.
TARGETS=()
for arch in ${ARCHS}; do
  case "$arch" in
    arm64) TARGETS+=("aarch64-apple-darwin") ;;
    x86_64) TARGETS+=("x86_64-apple-darwin") ;;
    *) echo "warning: skipping unsupported architecture $arch" ;;
  esac
done

# Bakes the App Group into passlib (see passlib::app_group_id), so a vault
# created by the CLI lands in the shared container too.
export PASS_APP_GROUP="$APP_GROUP"

for target in "${TARGETS[@]}"; do
  rustup target add "$target" >/dev/null 2>&1 || true
  (cd "$REPO_ROOT" && cargo build --release --target "$target" -p passcli -p pass-native-host)
done

ENTITLEMENTS="$WORK_DIR/helpers.entitlements"
cat > "$ENTITLEMENTS" <<PLIST
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
	<key>com.apple.security.application-groups</key>
	<array>
		<string>${APP_GROUP}</string>
	</array>
</dict>
</plist>
PLIST

for binary in pass pass-native-host; do
  inputs=()
  for target in "${TARGETS[@]}"; do
    inputs+=("$REPO_ROOT/target/$target/release/$binary")
  done
  lipo -create "${inputs[@]}" -output "$HELPERS_DIR/$binary"
  codesign --force --options runtime --timestamp=none \
    --entitlements "$ENTITLEMENTS" \
    --identifier "it.antoniopicone.Pass.${binary}" \
    --sign "${EXPANDED_CODE_SIGN_IDENTITY:--}" \
    "$HELPERS_DIR/$binary"
  echo "Bundled $HELPERS_DIR/$binary"
done
