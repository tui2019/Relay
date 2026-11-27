#!/usr/bin/env bash
set -euo pipefail
export PATH="$HOME/.cargo/bin:$PATH"

UNIVERSAL=0
if [ "${1:-}" = "--universal" ]; then
  UNIVERSAL=1
fi

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
ROOT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
APP_DIR="$SCRIPT_DIR/Relay.app"
APPEX_DIR="$APP_DIR/Contents/PlugIns/RelayFileProvider.appex"

ARCH_FLAGS=()
if [ "$UNIVERSAL" -eq 1 ]; then
  ARCH_FLAGS=(-arch arm64 -arch x86_64)
  echo "1/5 Building Universal (arm64 + x86_64) Rust relay-daemon..."
  (
    cd "$ROOT_DIR/core"
    cargo build --release --target aarch64-apple-darwin --bin relay-daemon
    cargo build --release --target x86_64-apple-darwin --bin relay-daemon
    mkdir -p target/universal
    lipo -create \
      target/aarch64-apple-darwin/release/relay-daemon \
      target/x86_64-apple-darwin/release/relay-daemon \
      -output target/universal/relay-daemon
  )
  DAEMON_BIN="$ROOT_DIR/core/target/universal/relay-daemon"
  echo "2/5 Building Universal RelayBridge BLE/CoreWLAN helper..."
  "$ROOT_DIR/bridge/build.sh" --universal
else
  echo "1/5 Building Rust relay-daemon..."
  (cd "$ROOT_DIR/core" && cargo build --release --bin relay-daemon)
  DAEMON_BIN="$ROOT_DIR/core/target/release/relay-daemon"
  echo "2/5 Building RelayBridge BLE/CoreWLAN helper..."
  "$ROOT_DIR/bridge/build.sh"
fi

echo "3/5 Compiling native macOS menu bar app Relay.app..."
rm -rf "$APP_DIR"
mkdir -p "$APP_DIR/Contents/MacOS" "$APP_DIR/Contents/Resources" "$APPEX_DIR/Contents/MacOS"

clang -O2 -fobjc-arc -Wall -Wextra \
  ${ARCH_FLAGS[@]+"${ARCH_FLAGS[@]}"} \
  -framework Cocoa \
  -framework FileProvider \
  -framework UserNotifications \
  -framework WebKit \
  "$SCRIPT_DIR/Relay.m" \
  -o "$APP_DIR/Contents/MacOS/Relay"

echo "4/5 Compiling native macOS FileProvider extension (Finder Locations sidebar)..."
clang -O2 -fobjc-arc -fapplication-extension -Wall -Wextra \
  ${ARCH_FLAGS[@]+"${ARCH_FLAGS[@]}"} \
  -e _NSExtensionMain \
  -framework Foundation \
  -framework FileProvider \
  -framework UniformTypeIdentifiers \
  "$SCRIPT_DIR/RelayFileProvider.m" \
  -o "$APPEX_DIR/Contents/MacOS/RelayFileProvider"

cp "$DAEMON_BIN" "$APP_DIR/Contents/Resources/relay-daemon"
cp "$ROOT_DIR/bridge/RelayBridge" "$APP_DIR/Contents/Resources/RelayBridge"

cat > "$APPEX_DIR/Contents/Info.plist" <<'PLIST'
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>CFBundleDevelopmentRegion</key>
    <string>en</string>
    <key>CFBundleDisplayName</key>
    <string>Relay</string>
    <key>CFBundleExecutable</key>
    <string>RelayFileProvider</string>
    <key>CFBundleIdentifier</key>
    <string>com.relay.mac.fileprovider</string>
    <key>CFBundleInfoDictionaryVersion</key>
    <string>6.0</string>
    <key>CFBundleName</key>
    <string>RelayFileProvider</string>
    <key>CFBundlePackageType</key>
    <string>XPC!</string>
    <key>CFBundleShortVersionString</key>
    <string>0.1.0</string>
    <key>CFBundleVersion</key>
    <string>1</string>
    <key>CFBundleIcons</key>
    <dict>
        <key>CFBundlePrimaryIcon</key>
        <dict>
            <key>CFBundleSymbolName</key>
            <string>iphone</string>
        </dict>
    </dict>
    <key>LSMinimumSystemVersion</key>
    <string>12.0</string>
    <key>NSExtension</key>
    <dict>
        <key>NSExtensionPointIdentifier</key>
        <string>com.apple.fileprovider-nonui</string>
        <key>NSExtensionPrincipalClass</key>
        <string>RelayFileProvider</string>
        <key>NSExtensionFileProviderSupportsEnumeration</key>
        <true/>
    </dict>
</dict>
</plist>
PLIST

cat > "$SCRIPT_DIR/RelayFileProvider.entitlements" <<'ENT'
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>com.apple.security.app-sandbox</key>
    <true/>
    <key>com.apple.security.network.client</key>
    <true/>
</dict>
</plist>
ENT

cat > "$APP_DIR/Contents/Info.plist" <<'PLIST'
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>CFBundleDevelopmentRegion</key>
    <string>en</string>
    <key>CFBundleExecutable</key>
    <string>Relay</string>
    <key>CFBundleIdentifier</key>
    <string>com.relay.mac</string>
    <key>CFBundleInfoDictionaryVersion</key>
    <string>6.0</string>
    <key>CFBundleName</key>
    <string>Relay</string>
    <key>CFBundlePackageType</key>
    <string>APPL</string>
    <key>CFBundleShortVersionString</key>
    <string>0.1.0</string>
    <key>CFBundleVersion</key>
    <string>1</string>
    <key>LSMinimumSystemVersion</key>
    <string>12.0</string>
    <key>LSUIElement</key>
    <true/>
    <key>NSBluetoothAlwaysUsageDescription</key>
    <string>Relay uses Bluetooth LE to discover and connect to your Android phone.</string>
    <key>NSLocalNetworkUsageDescription</key>
    <string>Relay uses your local Wi-Fi network for Notification Sync and Finder file access.</string>
</dict>
</plist>
PLIST

echo "5/5 Signing FileProvider extension and Relay.app..."
codesign --force --sign - --entitlements "$SCRIPT_DIR/RelayFileProvider.entitlements" "$APPEX_DIR"
codesign --force --sign - "$APP_DIR"

echo "Built $APP_DIR successfully!"
