# VLESS VPN — Android App

A VLESS-over-WebSocket VPN client for Android, built on top of your `tun2socks` library.

## Architecture

```
┌─────────────────────────────────────────────────────────┐
│  Android App                                            │
│                                                         │
│  ┌──────────────┐   VPN permission   ┌───────────────┐ │
│  │ MainActivity │ ─────────────────► │ VlessVpnSvc   │ │
│  │  (UI / list) │                    │               │ │
│  └──────────────┘                    │  TUN iface    │ │
│        │                             │  (VpnService) │ │
│        │ import vless://             └──────┬────────┘ │
│        ▼                                    │           │
│  ┌──────────────┐                           │ tun2socks │
│  │ ConfigStore  │              ┌────────────▼────────┐  │
│  │ (SharedPrefs)│              │ libtun2socks.so      │  │
│  └──────────────┘              │ (badvpn native)      │  │
│                                └────────────┬────────┘  │
│                                             │ SOCKS5     │
│                                ┌────────────▼────────┐  │
│                                │ VlessProxyService    │  │
│                                │                      │  │
│                                │  SOCKS5 server       │  │
│                                │  :10800              │  │
│                                └────────────┬────────┘  │
│                                             │ WS/WSS     │
└─────────────────────────────────────────────┼───────────┘
                                              │
                                    ┌─────────▼──────────┐
                                    │  VLESS Server       │
                                    │  (your server.js /  │
                                    │   Xray / V2Ray)     │
                                    └────────────────────┘
```

### Flow
1. User imports a `vless://` URL → parsed into `VlessConfig`
2. User taps **Connect** → `VlessVpnService` creates a TUN interface
3. `tun2socks` routes all device TCP traffic → SOCKS5 `127.0.0.1:10800`
4. `VlessProxyService` accepts SOCKS5 connections → opens a WebSocket to the VLESS server
5. VLESS binary header is prepended (matching your `client.js` `buildVlessHeader()`)
6. Bidirectional relay runs — `relay()` logic mirrors `client.js` exactly

## URL Format

```
vless://<UUID>@<server>:<port>?encryption=none&security=tls&sni=<sni>&type=ws&host=<wsHost>&path=<path>#<name>
```

Example:
```
vless://55a95ae1-4ae8-4461-8484-457279821b40@broad.aicms.dpdns.org:443?encryption=none&security=tls&sni=broad.aicms.dpdns.org&type=ws&host=broad.aicms.dpdns.org&path=/?ed=2560#broad.aicms.dpdns.org
```

## Project Structure

```
VlessVPN/
├── settings.gradle
├── build.gradle
├── gradle.properties
│
├── tun2socks/                          ← Your tun2socks library module
│   ├── build.gradle
│   └── src/main/
│       ├── AndroidManifest.xml
│       ├── java/com/musicses/vlessvpn/
│       │   └── Tun2Socks.java          ← JNI wrapper (from your zip)
│       └── cpp/
│           ├── CMakeLists.txt
│           ├── tun2socks.cpp           ← JNI implementation (from your zip)
│           └── prebuilt/
│               ├── include/tun2socks/tun2socks.h
│               └── lib/arm64-v8a/libtun2socks.a
│
└── app/                                ← Main app module
    ├── build.gradle
    └── src/main/
        ├── AndroidManifest.xml
        ├── java/com/musicses/vlessvpn/app/
        │   ├── VlessConfig.java        ← Parses vless:// URLs
        │   ├── VlessHeader.java        ← Builds VLESS binary header
        │   ├── VlessProxyService.java  ← SOCKS5 + VLESS WS tunnel
        │   ├── VlessVpnService.java    ← Android VpnService + tun2socks
        │   ├── VpnStateHolder.java     ← State observable
        │   ├── ConfigStore.java        ← SharedPreferences persistence
        │   ├── MainActivity.java       ← UI
        │   └── ConfigAdapter.java      ← RecyclerView adapter
        └── res/
            ├── layout/
            │   ├── activity_main.xml
            │   └── item_config.xml
            ├── drawable/ic_vpn.xml
            └── values/
                ├── strings.xml
                └── themes.xml
```

## Build Requirements

- **Android Studio** Hedgehog (2023.1.1) or newer
- **NDK** r25c or newer (for arm64-v8a native build)
- **CMake** 3.22.1+
- **Min SDK**: 26 (Android 8.0)
- **Target SDK**: 36

## Build Steps

### 1. Open in Android Studio
```
File → Open → select the VlessVPN/ folder
```

### 2. Install NDK
```
Tools → SDK Manager → SDK Tools → NDK (Side by side) ✓
```

### 3. Sync & Build
```
Build → Make Project   (or Ctrl+F9)
Build → Generate Signed APK  (for release)
```

### 4. Run
- Connect Android device (USB debugging enabled)
- Run → Run 'app'

## Key Implementation Notes

### VLESS Header (`VlessHeader.java`)
Mirrors `buildVlessHeader()` in `client.js`:
- Version byte `0x00`
- 16-byte UUID
- Addon length `0x00`
- Command `0x01` (TCP)
- Port (big-endian uint16)
- Address type + address bytes

### Response Skip (`VlessProxyService.java`)
Mirrors `relay()` in `client.js`:
```java
// byte[0]=version, byte[1]=addon_len => total header = 2 + addon_len
respHdrSize = 2 + (respBuf[1] & 0xFF);
```

### TLS / Self-signed Certs
When `rejectUnauthorized = false`, the OkHttp client uses a trust-all `X509TrustManager` and disables hostname verification — same behavior as `client.js`.

### SNI
Set via `Request.Builder` URL host. For servers where the WS host differs from SNI, the actual TCP connection goes to `cfg.server` while the `Host` header is set to `cfg.wsHost`.

## Adding x86 / armeabi-v7a Support

The prebuilt `libtun2socks.a` currently only targets `arm64-v8a`. To add more ABIs:
1. Build `libtun2socks.a` for each ABI from [mokhtarabadi/badvpn](https://github.com/mokhtarabadi/badvpn)
2. Place under `tun2socks/src/main/cpp/prebuilt/lib/<abi>/`
3. Add to `build.gradle` ndk `abiFilters`

## Permissions Used

| Permission | Reason |
|---|---|
| `INTERNET` | WebSocket connections |
| `FOREGROUND_SERVICE` | Keep VPN running in background |
| `FOREGROUND_SERVICE_SPECIAL_USE` | Required for Android 14+ VPN services |
| `BIND_VPN_SERVICE` | Required for VpnService |
