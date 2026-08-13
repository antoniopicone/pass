#!/usr/bin/env bash
# Builds PassKitFFI.xcframework from the passlib_ffi Rust crate, for the
# PassKit Swift package (Package.swift) to depend on.
#
# Run this on macOS with Xcode (for `xcodebuild`/`lipo`) and Rust/rustup
# installed. It cannot run on Linux — Apple's SDKs and linker aren't
# available there, which is also why this repo doesn't ship a prebuilt
# PassKitFFI.xcframework: it was written and organized on Linux, but never
# built or run, since nothing in this toolchain can target Apple platforms.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
LIB_NAME="libpasslib_ffi.a"
HEADER_DIR="$REPO_ROOT/passlib_ffi"

if [[ "$(uname -s)" != "Darwin" ]]; then
  echo "This script must run on macOS (needs xcodebuild and Apple SDKs)." >&2
  exit 1
fi

TARGETS=(
  aarch64-apple-darwin     # macOS, Apple Silicon
  x86_64-apple-darwin      # macOS, Intel
  aarch64-apple-ios        # iOS device
  aarch64-apple-ios-sim    # iOS Simulator, Apple Silicon Macs
  x86_64-apple-ios         # iOS Simulator, Intel Macs
)

echo "==> Installing Rust targets (rustup target add)"
for target in "${TARGETS[@]}"; do
  rustup target add "$target"
done

echo "==> Building passlib_ffi (release) for each target"
for target in "${TARGETS[@]}"; do
  echo "  - $target"
  cargo build --release --manifest-path "$REPO_ROOT/passlib_ffi/Cargo.toml" --target "$target"
done

TARGET_DIR="$REPO_ROOT/target"
FAT_DIR="$TARGET_DIR/apple-fat"
rm -rf "$FAT_DIR"
mkdir -p "$FAT_DIR/macos" "$FAT_DIR/ios-sim"

echo "==> Combining macOS slices (arm64 + x86_64) with lipo"
lipo -create \
  "$TARGET_DIR/aarch64-apple-darwin/release/$LIB_NAME" \
  "$TARGET_DIR/x86_64-apple-darwin/release/$LIB_NAME" \
  -output "$FAT_DIR/macos/$LIB_NAME"

echo "==> Combining iOS Simulator slices (arm64 + x86_64) with lipo"
lipo -create \
  "$TARGET_DIR/aarch64-apple-ios-sim/release/$LIB_NAME" \
  "$TARGET_DIR/x86_64-apple-ios/release/$LIB_NAME" \
  -output "$FAT_DIR/ios-sim/$LIB_NAME"

OUT="$SCRIPT_DIR/PassKitFFI.xcframework"
echo "==> Assembling $OUT"
rm -rf "$OUT"
xcodebuild -create-xcframework \
  -library "$FAT_DIR/macos/$LIB_NAME" -headers "$HEADER_DIR" \
  -library "$FAT_DIR/ios-sim/$LIB_NAME" -headers "$HEADER_DIR" \
  -library "$TARGET_DIR/aarch64-apple-ios/release/$LIB_NAME" -headers "$HEADER_DIR" \
  -output "$OUT"

echo
echo "Done: $OUT"
echo "Package.swift's PassKitFFI binary target will now resolve — open"
echo "Package.swift in Xcode, or add pass-apple as a local package"
echo "dependency to an app project, to pick it up."
