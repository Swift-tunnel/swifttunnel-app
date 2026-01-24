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
1. Download the `.msi` installer from [Releases](https://github.com/Swift-tunnel/swifttunnel-app/releases/latest)
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
- Windows 10/11 SDK
- Visual Studio Build Tools (MSVC)

### Build from Source

```bash
# Clone the repo
git clone https://github.com/Swift-tunnel/swifttunnel-app.git
cd swifttunnel-app/swifttunnel-windows

# Build release binary
cargo build --release

# Output: target/release/swifttunnel-fps-booster.exe
```

### Create Installer (MSI)

Requires [WiX Toolset v3.14](https://github.com/wixtoolset/wix3/releases).

```powershell
cd installer
& 'C:\Program Files (x86)\WiX Toolset v3.14\bin\candle.exe' -arch x64 -dSourceDir='../dist' -out './output/SwiftTunnel.wixobj' 'SwiftTunnel.wxs'
& 'C:\Program Files (x86)\WiX Toolset v3.14\bin\light.exe' -ext WixUIExtension -ext WixUtilExtension -out './output/SwiftTunnel.msi' './output/SwiftTunnel.wixobj'
```

---

## Tech Stack

| Component | Technology |
|-----------|------------|
| GUI | [egui](https://github.com/emilk/egui) / eframe |
| Tunnel | [BoringTun](https://github.com/cloudflare/boringtun) (WireGuard) |
| Network Adapter | [Wintun](https://www.wintun.net/) |
| Split Tunnel | ndisapi (Windows Packet Filter) |
| Installer | WiX Toolset |

---

## License

MIT License — see [LICENSE](LICENSE) for details.

---

<p align="center">
  <sub>Built for gamers who hate lag.</sub>
</p>
