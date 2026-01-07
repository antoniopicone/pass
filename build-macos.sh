#!/bin/bash

# Build script for creating a library for macOS (Apple Silicon)
# This builds the Rust library and prepares it for linking with Xcode

set -e

echo "🦀 Building Rust FFI library for macOS (Apple Silicon)..."

cd "$(dirname "$0")"

# Build for current platform (Apple Silicon)
echo "Building for aarch64-apple-darwin..."
cargo build --package passlib_ffi --release --target aarch64-apple-darwin

# Create directory for output
echo "Organizing build artifacts..."
mkdir -p target/macos/release

# Copy library
cp target/aarch64-apple-darwin/release/libpasslib_ffi.a target/macos/release/

# Copy header file
echo "Copying header file..."
cp passlib_ffi/passlib_ffi.h target/macos/release/

echo "✅ Library created at: target/macos/release/libpasslib_ffi.a"
echo "✅ Header file at: target/macos/release/passlib_ffi.h"
echo ""
echo "Library is ready for Xcode!"
