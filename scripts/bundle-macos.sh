#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
APP_NAME="NetScope"
BUNDLE_DIR="$ROOT_DIR/dist/${APP_NAME}.app"
MACOS_DIR="$BUNDLE_DIR/Contents/MacOS"
RESOURCES_DIR="$BUNDLE_DIR/Contents/Resources"
ICON_PNG="$ROOT_DIR/crates/netscope-app/assets/icon.png"

CARGO_VERSION="$(grep -E '^version = "' "$ROOT_DIR/Cargo.toml" | head -n1 | cut -d'"' -f2 || true)"
VERSION="${1:-${CARGO_VERSION:-0.3.0}}"

echo "Building netscope v${VERSION} release binary..."
cd "$ROOT_DIR"
cargo build --release -p netscope-app

rm -rf "$BUNDLE_DIR"
mkdir -p "$MACOS_DIR" "$RESOURCES_DIR"
cp "$ROOT_DIR/target/release/netscope" "$MACOS_DIR/netscope"

if [[ -f "$ICON_PNG" ]] && command -v sips >/dev/null && command -v iconutil >/dev/null; then
    TMP_ICON_ROOT="$(mktemp -d)"
    trap 'rm -rf "$TMP_ICON_ROOT"' EXIT
    ICONSET_DIR="$TMP_ICON_ROOT/NetScope.iconset"
    mkdir -p "$ICONSET_DIR"

    sips -z 16 16     "$ICON_PNG" --out "$ICONSET_DIR/icon_16x16.png"      >/dev/null
    sips -z 32 32     "$ICON_PNG" --out "$ICONSET_DIR/icon_16x16@2x.png"   >/dev/null
    sips -z 32 32     "$ICON_PNG" --out "$ICONSET_DIR/icon_32x32.png"      >/dev/null
    sips -z 64 64     "$ICON_PNG" --out "$ICONSET_DIR/icon_32x32@2x.png"   >/dev/null
    sips -z 128 128   "$ICON_PNG" --out "$ICONSET_DIR/icon_128x128.png"    >/dev/null
    sips -z 256 256   "$ICON_PNG" --out "$ICONSET_DIR/icon_128x128@2x.png" >/dev/null
    sips -z 256 256   "$ICON_PNG" --out "$ICONSET_DIR/icon_256x256.png"    >/dev/null
    sips -z 512 512   "$ICON_PNG" --out "$ICONSET_DIR/icon_256x256@2x.png" >/dev/null
    sips -z 512 512   "$ICON_PNG" --out "$ICONSET_DIR/icon_512x512.png"    >/dev/null
    sips -z 1024 1024 "$ICON_PNG" --out "$ICONSET_DIR/icon_512x512@2x.png" >/dev/null

    iconutil -c icns "$ICONSET_DIR" -o "$RESOURCES_DIR/NetScope.icns"
fi

cat > "$BUNDLE_DIR/Contents/Info.plist" << EOF
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>CFBundleDevelopmentRegion</key>
    <string>en</string>
    <key>CFBundleExecutable</key>
    <string>netscope</string>
    <key>CFBundleIconFile</key>
    <string>NetScope</string>
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

# Seal Info.plist + NetScope.icns + executable into an ad-hoc bundle signature
codesign --force --deep --sign - "$BUNDLE_DIR"
codesign --verify --deep --strict "$BUNDLE_DIR"

echo "Packaged & ad-hoc signed: $BUNDLE_DIR (v${VERSION})"
ls -lh "$MACOS_DIR/netscope" "$RESOURCES_DIR/NetScope.icns"