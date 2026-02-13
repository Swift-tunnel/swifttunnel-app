<p align="center">
  <img src="https://swifttunnel.net/logo.png" alt="SwiftTunnel" width="120" />
</p>

<h1 align="center">SwiftTunnel</h1>

<p align="center">
  <strong>Game faster. Lag less.</strong>
</p>

<p align="center">
  A lightweight game connection optimizer with split tunneling — route only your game through our low-latency servers while everything else stays on your normal connection.
</p>

<p align="center">
  <a href="https://github.com/Swift-tunnel/swifttunnel-app/releases/latest">
    <img src="https://img.shields.io/github/v/release/Swift-tunnel/swifttunnel-app?style=flat-square&color=blue" alt="Latest Release" />
  </a>
  <a href="https://github.com/Swift-tunnel/swifttunnel-app/releases">
    <img src="https://img.shields.io/github/downloads/Swift-tunnel/swifttunnel-app/total?style=flat-square&color=green" alt="Downloads" />
  </a>
  <a href="https://github.com/Swift-tunnel/swifttunnel-app/blob/main/LICENSE">
    <img src="https://img.shields.io/github/license/Swift-tunnel/swifttunnel-app?style=flat-square" alt="License" />
  </a>
</p>

<p align="center">
  <a href="#features">Features</a> •
  <a href="#download">Download</a> •
  <a href="#how-it-works">How It Works</a> •
  <a href="https://status.swifttunnel.net">Servers</a> •
  <a href="#building">Building</a>
</p>

---

## Features

### 🎯 Smart Split Tunneling
Only game traffic is optimized through SwiftTunnel. Discord, Spotify, Chrome — everything else uses your normal internet. No bandwidth wasted.

### ⚡ Low Latency Gaming Servers
28 gaming-optimized servers across 8 regions. Each server runs:
- **BBR** congestion control for faster throughput
- **fq_codel** queue management to eliminate bufferbloat
- **WireGuard** protocol for minimal overhead

### 🚀 PC Boosts
Built-in performance optimizations:
- **FPS Unlocker** — Remove the 60 FPS cap
- **Network Tweaks** — Optimize TCP/UDP settings, DNS, and adapter config
- **System Boosts** — Process priority, timer resolution, memory management

### 🔒 Lightweight & Safe
- No kernel drivers required for basic operation
- Anti-cheat friendly — uses standard Windows APIs
- Minimal resource usage (~20MB RAM)
- All optimizations are reversible

### 🌍 Auto Region Detection
Automatically detects which game server you're connecting to and routes through the optimal SwiftTunnel server (ExitLag-style).

---

## Download

<p align="center">
  <a href="https://github.com/Swift-tunnel/swifttunnel-app/releases/latest">
    <img src="https://img.shields.io/badge/Download-Windows%20x64-blue?style=for-the-badge&logo=windows" alt="Download for Windows" />
  </a>
</p>

**Requirements:**
- Windows 10/11 (64-bit)
- Administrator privileges (for network optimization)

**Installation:**
1. Download the Windows installer (`*.exe`) from [Releases](https://github.com/Swift-tunnel/swifttunnel-app/releases/latest)
2. Run the installer
3. SwiftTunnel launches automatically after installation
4. Sign in with your SwiftTunnel account

---

## How It Works

```
┌─────────────────────────────────────────────────────────────────┐
│                        Your PC                                  │
│  ┌─────────────┐    ┌─────────────────────────────────────────┐ │
│  │   Roblox    │───▶│  SwiftTunnel Route Optimizer            │ │
│  └─────────────┘    │  ┌─────────────────────────────────────┐│ │
│                     │  │ Optimized Route → Gaming Server     ││ │
│  ┌─────────────┐    │  └─────────────────────────────────────┘│ │
│  │   Discord   │───▶│           (bypassed)                    │ │
│  └─────────────┘    └──────────────────────────────────────── ┘ │
│                              │                                  │
│  ┌─────────────┐             │                                  │
│  │   Chrome    │─────────────┘ (normal internet)                │
│  └─────────────┘                                                │
└─────────────────────────────────────────────────────────────────┘
```

SwiftTunnel intercepts game traffic at the network layer. Only packets from your game are optimized and routed through our servers — everything else goes directly to the internet.


## Building

### Prerequisites
- [Rust](https://rustup.rs/) 1.70 or later
- [Node.js](https://nodejs.org/) 20 or later
- Windows 10/11 SDK (for native builds)
- Visual Studio Build Tools (MSVC)

### Build Desktop App (Tauri + React)

```bash
# Clone the repo
git clone https://github.com/Swift-tunnel/swifttunnel-app.git
cd swifttunnel-app/swifttunnel-desktop

# Install frontend + Tauri CLI dependencies
npm ci

# Frontend production build
npm run build

# Desktop dev mode
npm run tauri:dev
```

### Build NSIS Installer

```bash
cd swifttunnel-desktop
npm run tauri:build
```

Installer output:
- `swifttunnel-desktop/src-tauri/target/release/bundle/nsis/*.exe`
- Updater artifacts and signatures are generated when signing keys are configured.

### Release Pipeline (GitHub Actions)

The release workflow uses `tauri-apps/tauri-action` and requires these repository secrets:
- `TAURI_SIGNING_PRIVATE_KEY`
- `TAURI_SIGNING_PRIVATE_KEY_PASSWORD`
- `TAURI_UPDATER_PUBLIC_KEY`
- `SWIFTTUNNEL_UPDATE_MANIFEST_PRIVATE_KEY`
- `SWIFTTUNNEL_UPDATE_MANIFEST_PUBLIC_KEY_B64`

Notes:
- Releases are tag-driven from `main` only (`v*` tags).
- `vX.Y.Z-*` publishes as prerelease (`Live` channel).
- `vX.Y.Z` publishes as stable release (`Stable` channel).
- `TAURI_UPDATER_PUBLIC_KEY` is injected into `swifttunnel-desktop/src-tauri/tauri.conf.json` during CI.
- `WinpkFilter-x64.msi` is fetched in CI and bundled into NSIS resources.
- `wintun.dll` and driver assets are bundled from `swifttunnel-desktop/src-tauri/resources/drivers`.
- `swifttunnel-update-manifest.json` and `swifttunnel-update-manifest.sig` are generated and uploaded per release for updater pre-verification.
- `SWIFTTUNNEL_UPDATE_MANIFEST_PRIVATE_KEY` should be an Ed25519 private key (PEM), and `SWIFTTUNNEL_UPDATE_MANIFEST_PUBLIC_KEY_B64` should be the matching raw 32-byte public key encoded in base64.

### Installer Validation Checklist (Clean Windows 10/11)

1. Install using the generated NSIS installer on a clean VM.
2. Launch app and confirm login flow works.
3. Confirm `%APPDATA%\SwiftTunnel\settings.json` is read/written correctly.
4. Connect/disconnect VPN at least once (ensures `wintun.dll` staging and driver checks are healthy).
5. Run in-app updater check from Settings.

Settings migration status: no schema migration required. The Tauri app continues using `%APPDATA%\SwiftTunnel\settings.json`.

### Automated Validation

On Windows test environments, run:

```powershell
.\scripts\validate-revamp.ps1
```

This runs formatter checks, region resolver tests, updater channel/security tests, and frontend build validation.

### Legacy Archive

The legacy egui app code is kept as `swifttunnel-old/` for reference only.

- It is not part of the Cargo workspace.
- It is not built by CI.
- It is not used in release publishing.

---

## Tech Stack

| Component | Technology |
|-----------|------------|
| GUI | [Tauri v2](https://tauri.app/) + [React 19](https://react.dev/) + TypeScript |
| Tunnel | [BoringTun](https://github.com/cloudflare/boringtun) (WireGuard) |
| Network Adapter | [Wintun](https://www.wintun.net/) |
| Split Tunnel | ndisapi (Windows Packet Filter) |
| Installer | NSIS (Tauri bundler) |

---

## License

MIT License — see [LICENSE](LICENSE) for details.

---

<p align="center">
  <sub>Built for gamers who hate lag.</sub>
</p>
