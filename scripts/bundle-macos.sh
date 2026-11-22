#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
APP_NAME="NetScope"
BUNDLE_DIR="$ROOT_DIR/dist/${APP_NAME}.app"
MACOS_DIR="$BUNDLE_DIR/Contents/MacOS"
RESOURCES_DIR="$BUNDLE_DIR/Contents/Resources"

CARGO_VERSION="$(grep -E '^version = "' "$ROOT_DIR/Cargo.toml" | head -n1 | cut -d'"' -f2 || true)"
VERSION="${1:-${CARGO_VERSION:-0.3.0}}"

echo "Building netscope v${VERSION} release binary..."
cd "$ROOT_DIR"
cargo build --release -p netscope-app

rm -rf "$BUNDLE_DIR"
mkdir -p "$MACOS_DIR" "$RESOURCES_DIR"
cp "$ROOT_DIR/target/release/netscope" "$MACOS_DIR/netscope"

cat > "$BUNDLE_DIR/Contents/Info.plist" << EOF
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>CFBundleDevelopmentRegion</key>
    <string>en</string>
    <key>CFBundleExecutable</key>
    <string>netscope</string>
    <key>CFBundleIdentifier</key>
    <string>io.github.burakberkkeskin.netscope</string>
    <key>CFBundleInfoDictionaryVersion</key>
    <string>6.0</string>
    <key>CFBundleName</key>
    <string>NetScope</string>
    <key>CFBundlePackageType</key>
    <string>APPL</string>
    <key>CFBundleShortVersionString</key>
    <string>${VERSION}</string>
    <key>CFBundleVersion</key>
    <string>${VERSION}</string>
    <key>LSMinimumSystemVersion</key>
    <string>13.0</string>
    <key>NSHighResolutionCapable</key>
    <true/>
    <key>NSLocalNetworkUsageDescription</key>
    <string>NetScope scans your local network to discover LAN devices, open ports, and router connectivity.</string>
</dict>
</plist>
EOF

echo "Packaged: $BUNDLE_DIR (v${VERSION})"
ls -lh "$MACOS_DIR/netscope"