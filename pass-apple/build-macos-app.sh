#!/usr/bin/env bash
# Builds a runnable, ad-hoc signed Pass.app for macOS without an Xcode
# project: compiles passlib_ffi (Rust), the PassKit wrapper and the SwiftUI
# app sources directly with cargo/swiftc, then assembles the .app bundle.
#
# Output: pass-apple/.build/Pass.app  (open it with `open .build/Pass.app`)
#
# Env overrides:
#   CONFIGURATION=debug     build Rust + Swift without optimizations
#   ARCH=x86_64             build for Intel instead of the host architecture
#   EXTRA_SWIFT_FLAGS=...   extra flags passed to every swiftc invocation
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

CONFIGURATION="${CONFIGURATION:-release}"
ARCH="${ARCH:-$(uname -m)}"
MIN_MACOS="14.0"
BUNDLE_ID="it.antoniopicone.Pass"
EXTRA_SWIFT_FLAGS="${EXTRA_SWIFT_FLAGS:-}"

case "$ARCH" in
  arm64 | aarch64) RUST_TARGET="aarch64-apple-darwin"; SWIFT_ARCH="arm64" ;;
  x86_64)          RUST_TARGET="x86_64-apple-darwin";  SWIFT_ARCH="x86_64" ;;
  *) echo "Unsupported ARCH: $ARCH" >&2; exit 1 ;;
esac
SWIFT_TARGET="$SWIFT_ARCH-apple-macos$MIN_MACOS"

if [[ "$CONFIGURATION" == "release" ]]; then
  CARGO_PROFILE_FLAG="--release"
  SWIFT_OPT_FLAGS=(-O -wmo)
else
  CARGO_PROFILE_FLAG=""
  SWIFT_OPT_FLAGS=(-Onone -g)
fi

BUILD_DIR="$SCRIPT_DIR/.build/macos-app/$CONFIGURATION-$SWIFT_ARCH"
APP="$SCRIPT_DIR/.build/Pass.app"
FFI_DIR="$REPO_ROOT/passlib_ffi"  # passlib_ffi.h + module.modulemap (PassKitFFI)
FFI_LIB="$REPO_ROOT/target/$RUST_TARGET/$CONFIGURATION/libpasslib_ffi.a"

# Keeps the C code compiled by build scripts (e.g. `ring`) at the same
# deployment target as the app, instead of the host OS version.
export MACOSX_DEPLOYMENT_TARGET="$MIN_MACOS"

echo "==> Building passlib_ffi ($CONFIGURATION, $RUST_TARGET)"
rustup target add "$RUST_TARGET" >/dev/null 2>&1 || true
cargo build $CARGO_PROFILE_FLAG --manifest-path "$FFI_DIR/Cargo.toml" --target "$RUST_TARGET"

mkdir -p "$BUILD_DIR"

echo "==> Compiling PassKit"
# shellcheck disable=SC2086
xcrun swiftc $EXTRA_SWIFT_FLAGS "${SWIFT_OPT_FLAGS[@]}" \
  -target "$SWIFT_TARGET" \
  -parse-as-library \
  -module-name PassKit \
  -I "$FFI_DIR" \
  -emit-module -emit-module-path "$BUILD_DIR/PassKit.swiftmodule" \
  -c -o "$BUILD_DIR/PassKit.o" \
  "$SCRIPT_DIR"/Sources/PassKit/*.swift

echo "==> Compiling and linking Pass"
rm -rf "$APP"
mkdir -p "$APP/Contents/MacOS" "$APP/Contents/Resources"
# shellcheck disable=SC2086
xcrun swiftc $EXTRA_SWIFT_FLAGS "${SWIFT_OPT_FLAGS[@]}" \
  -target "$SWIFT_TARGET" \
  -parse-as-library \
  -module-name Pass \
  -I "$BUILD_DIR" -I "$FFI_DIR" \
  "$SCRIPT_DIR"/Pass/App/*.swift "$SCRIPT_DIR"/Pass/App/Views/*.swift \
  "$BUILD_DIR/PassKit.o" "$FFI_LIB" \
  -framework Security -framework SystemConfiguration -framework CoreFoundation -framework AppKit \
  -o "$APP/Contents/MacOS/Pass"

echo "==> Compiling asset catalog"
xcrun actool "$SCRIPT_DIR/Pass/Assets.xcassets" \
  --compile "$APP/Contents/Resources" \
  --platform macosx \
  --minimum-deployment-target "$MIN_MACOS" \
  --accent-color AccentColor \
  --output-partial-info-plist "$BUILD_DIR/assets-info.plist" \
  --output-format human-readable-text --notices --warnings >/dev/null

VERSION="$(sed -n 's/^version *= *"\(.*\)"/\1/p' "$FFI_DIR/Cargo.toml" | head -n1)"
VERSION="${VERSION:-0.1.0}"

cat > "$APP/Contents/Info.plist" <<PLIST
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
	<key>CFBundleDevelopmentRegion</key>
	<string>en</string>
	<key>CFBundleExecutable</key>
	<string>Pass</string>
	<key>CFBundleIdentifier</key>
	<string>$BUNDLE_ID</string>
	<key>CFBundleInfoDictionaryVersion</key>
	<string>6.0</string>
	<key>CFBundleName</key>
	<string>Pass</string>
	<key>CFBundleDisplayName</key>
	<string>Pass</string>
	<key>CFBundlePackageType</key>
	<string>APPL</string>
	<key>CFBundleShortVersionString</key>
	<string>$VERSION</string>
	<key>CFBundleVersion</key>
	<string>1</string>
	<key>LSMinimumSystemVersion</key>
	<string>$MIN_MACOS</string>
	<key>LSApplicationCategoryType</key>
	<string>public.app-category.utilities</string>
	<key>NSHighResolutionCapable</key>
	<true/>
	<key>NSPrincipalClass</key>
	<string>NSApplication</string>
	<key>NSFaceIDUsageDescription</key>
	<string>Unlock your Pass vault.</string>
</dict>
</plist>
PLIST
printf 'APPL????' > "$APP/Contents/PkgInfo"

echo "==> Signing (ad-hoc)"
codesign --force --sign - --timestamp=none "$APP"

echo
echo "Done: $APP"
echo "Run it with: open \"$APP\""
