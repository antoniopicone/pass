#!/usr/bin/env bash
# The Xcode build of Pass, scripted: builds PassKitFFI.xcframework,
# generates Pass.xcodeproj from project.yml (XcodeGen) and, if asked,
# builds it with xcodebuild. This is the build with the AutoFill extension,
# Touch ID/Face ID unlock and (macOS) the bundled CLI and Chromium native
# host — and the only one for iOS. See build-macos-app.sh for the quicker
# macOS-only build that needs none of this.
#
# Usage:
#   ./build-xcode.sh            xcframework + Pass.xcodeproj, to open in Xcode
#   ./build-xcode.sh macos      ...and build Pass.app (Release, universal)
#   ./build-xcode.sh ios-sim    ...and build for the iOS Simulator (Debug)
#   ./build-xcode.sh ios        ...and build for an iOS device (Release)
# Anything after the action is passed on to xcodebuild.
#
# Signing needs your Apple Developer Team ID, which isn't in this repo: put
# `DEVELOPMENT_TEAM = ABCDE12345` in Config/Local.xcconfig (git-ignored), or
# export DEVELOPMENT_TEAM. Without one, `macos` and `ios` still compile,
# unsigned, as a check — but that app has no entitlements, so no AutoFill
# and no Touch ID. The simulator build needs no team.
#
# Needs Xcode, Rust (rustup) and XcodeGen (`brew install xcodegen`).
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
DERIVED_DATA="$SCRIPT_DIR/.build/xcode"
PRODUCTS="$DERIVED_DATA/Build/Products"

ACTION="${1:-generate}"
[ $# -gt 0 ] && shift

case "$ACTION" in
  generate | macos | ios-sim | ios) ;;
  -h | --help) sed -n '2,/^set -euo/p' "$0" | sed '$d'; exit 0 ;;
  *) echo "Unknown action: $ACTION (expected macos, ios-sim or ios)" >&2; exit 1 ;;
esac

if ! command -v xcodegen >/dev/null 2>&1; then
  echo "XcodeGen is needed to generate Pass.xcodeproj: brew install xcodegen" >&2
  exit 1
fi

has_team() {
  [ -n "${DEVELOPMENT_TEAM:-}" ] ||
    grep -qE '^DEVELOPMENT_TEAM *= *[A-Z0-9]{10}' "$SCRIPT_DIR/Config/Local.xcconfig" 2>/dev/null
}

"$SCRIPT_DIR/build-xcframework.sh"

echo "==> Generating Pass.xcodeproj"
xcodegen generate --quiet --spec "$SCRIPT_DIR/project.yml" --project "$SCRIPT_DIR"

if [ "$ACTION" = "generate" ]; then
  echo
  echo "Done: $SCRIPT_DIR/Pass.xcodeproj"
  echo "Open it with: open \"$SCRIPT_DIR/Pass.xcodeproj\"  (schemes Pass-macOS, Pass-iOS)"
  has_team || echo "No team set yet — see the top of this script, or pick one in Xcode."
  exit 0
fi

# -allowProvisioningUpdates lets xcodebuild create the App Group and the
# provisioning profiles the entitlements need, like Xcode does on its own.
if has_team; then
  SIGNING=(-allowProvisioningUpdates)
  if [ -n "${DEVELOPMENT_TEAM:-}" ]; then
    SIGNING+=("DEVELOPMENT_TEAM=$DEVELOPMENT_TEAM")
  fi
else
  SIGNING=(CODE_SIGNING_ALLOWED=NO)
fi

case "$ACTION" in
  macos)
    SCHEME="Pass-macOS"; CONFIGURATION="Release"
    DESTINATION="generic/platform=macOS"
    PRODUCT="$PRODUCTS/Release/Pass.app"
    ;;
  ios-sim)
    SCHEME="Pass-iOS"; CONFIGURATION="Debug"
    DESTINATION="generic/platform=iOS Simulator"
    PRODUCT="$PRODUCTS/Debug-iphonesimulator/Pass.app"
    SIGNING=(CODE_SIGN_IDENTITY=-)
    ;;
  ios)
    SCHEME="Pass-iOS"; CONFIGURATION="Release"
    DESTINATION="generic/platform=iOS"
    PRODUCT="$PRODUCTS/Release-iphoneos/Pass.app"
    ;;
esac

echo "==> Building $SCHEME ($CONFIGURATION)"
if [ "$ACTION" != "ios-sim" ] && ! has_team; then
  echo "    no DEVELOPMENT_TEAM set: building unsigned, without entitlements"
fi
xcodebuild -quiet \
  -project "$SCRIPT_DIR/Pass.xcodeproj" \
  -scheme "$SCHEME" \
  -configuration "$CONFIGURATION" \
  -destination "$DESTINATION" \
  -derivedDataPath "$DERIVED_DATA" \
  "${SIGNING[@]}" "$@" \
  build

echo
echo "Done: $PRODUCT"
case "$ACTION" in
  ios-sim) echo "Run it from Xcode on a simulator, or: xcrun simctl install booted \"$PRODUCT\"" ;;
  ios) echo "To put it on a device, run the Pass-iOS scheme from Xcode with the device selected." ;;
esac
