# Relay

Native **Android Cross-Device Services** client for **macOS** — no Android companion app and no root required.

Relay speaks Google's stock Cross-Device Services protocols (`Nearby Presence`, `Nearby Connections` over BLE Weave + UKEY2 + Wi-Fi LAN, `DeviceLink`, `NotificationSyncRpcService`, `QuickAccessService`, and `nearby.sharedconnectivity`) directly from a lightweight Rust daemon and native macOS menu bar app.

## Features

- **Native Google Sign-In & Auto-Syncing Keys**: Built-in `WKWebView` sign-in (`Sign in with Google...`) syncs your account's Nearby Presence v3 credentials directly from `nearbypresence-pa.googleapis.com`, registers your Mac as a laptop in Android Cross-Device Services, and automatically refreshes keys in the background before their 5-day expiry.
- **Instant Hotspot & Instant Wi-Fi**: One-click **Start Instant Hotspot**, **Stop Instant Hotspot** (cleanly disables the phone's SoftAP over BLE), live battery `%` in the menu bar, and **Connect to Phone's Wi-Fi** when your phone is on a shareable Wi-Fi network.
- **Native macOS Notification Center Sync**: Real-time Android notifications delivered straight into macOS Notification Center with inline **Reply** and **Dismiss on Phone** synced back to your Android device.
- **Native Finder Integration (Read/Write)**: Exposes your Android phone's internal storage (`/sdcard`) in Finder's **Locations** sidebar via a native macOS `NSFileProviderReplicatedExtension` (`RelayFileProvider.appex`) with full read, write, create, rename, move, and delete support.

## Requirements

- **macOS 12+** (tested on macOS 14 Sonoma) with Bluetooth LE and Wi-Fi
- **Android phone** with Google Play Services & **Cross-device services** enabled (*Settings → Google → Devices & sharing → Cross-device services*) — works on stock, unrooted Android devices
- **Build tools**: Rust (`cargo`), Xcode Command Line Tools (`clang`, `codesign`)

> **Network note (Wi-Fi LAN vs Wi-Fi Direct):**
> - **Instant Hotspot, Instant Wi-Fi, and Battery Status** work over **Bluetooth LE** anywhere (no shared Wi-Fi required).
> - **Notification Sync and Finder File Access (`DeviceLink`)** require your Mac and Android phone to be reachable on the **same local Wi-Fi network** (macOS does not expose public Wi-Fi Direct / P2P Group Client APIs for Android's Wi-Fi Direct fallback).

## Download or Build

### Prebuilt Universal `.app` (Apple Silicon + Intel)
Every commit builds a Universal (`arm64` + `x86_64`) `Relay.app` via GitHub Actions — grab `Relay-macos-universal.zip` from the latest workflow run under the **Actions** tab (or **Releases** for tagged versions).

### Build from Source

```bash
git clone https://github.com/tui2019/Relay.git
cd Relay
./app/build_app.sh
open app/Relay.app
```

*(Pass `./app/build_app.sh --universal` to build a Universal `arm64` + `x86_64` bundle locally.)*

On first launch:
1. Grant **Bluetooth**, **Local Network**, and **Notifications** permissions when macOS prompts.
2. Click the Relay icon in the menu bar → **Sign in with Google...**
3. Relay automatically syncs your Nearby Presence keys and connects when your Android phone is nearby.

## Architecture

| Component | Path | Role |
|---|---|---|
| Rust Protocol Core & Daemon | [`core/`](core/) | Nearby Presence LDT-XTS-AES-256 decryption, UKEY2 ECDH-P256 handshake, BLE Weave framing, Nearby Connections Wi-Fi LAN upgrade, `DeviceLink` RPC multiplexer (`NotificationSync`, `QuickAccess`), Instant Hotspot tether client, loopback FileProvider/WebDAV API, and pure-Rust Google OAuth + `NearbyPresenceService` HTTP/2 gRPC sync |
| macOS BLE / Wi-Fi Bridge | [`bridge/`](bridge/) | Lightweight CoreBluetooth (`0xFCF1` scan + `0xFEF3` Weave GATT) and CoreWLAN helper |
| Native macOS App & Finder Extension | [`app/`](app/) | Menu bar UI (`Relay.m`), embedded `WKWebView` sign-in, `UNUserNotificationCenter` integration, and native `NSFileProviderReplicatedExtension` (`RelayFileProvider.m`) |

## Running Tests

```bash
cd core
cargo test --all-targets
```

## Security & Privacy

- Account tokens and synced Nearby Presence credentials are stored locally under `~/Library/Application Support/Relay/` with owner-only `0600` permissions and are never logged.
- All local device-to-device traffic is end-to-end encrypted with UKEY2 (`D2DConnectionContext`, AES-256-CBC + HMAC-SHA256) and authenticated with `PresenceConnectionAuthenticator`.

## License

[MIT](LICENSE)
