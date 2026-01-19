<p align="center">
  <img src="https://swifttunnel.net/logo.png" alt="SwiftTunnel" width="120" />
</p>

<h1 align="center">SwiftTunnel</h1>

<p align="center">
  <strong>Game faster. Lag less.</strong>
</p>

<p align="center">
  A lightweight game traffic optimizer with split tunneling — route only your game through our low-latency servers while everything else stays on your normal connection.
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

### 🎯 Split Tunneling
Only game traffic is routed through SwiftTunnel. Discord, Spotify, Chrome — everything else uses your normal internet. No bandwidth wasted.

### ⚡ Low Latency Servers
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

---

## Download

<p align="center">
  <a href="https://github.com/Swift-tunnel/swifttunnel-app/releases/latest/download/SwiftTunnel-0.3.0-x64.msi">
    <img src="https://img.shields.io/badge/Download-Windows%20x64-blue?style=for-the-badge&logo=windows" alt="Download for Windows" />
  </a>
</p>

**Requirements:**
- Windows 10/11 (64-bit)
- Administrator privileges (for network optimization)

**Installation:**
1. Download the `.msi` installer
2. Run as Administrator
3. Follow the setup wizard
4. Launch SwiftTunnel from Start Menu

---

## How It Works

```
┌─────────────────────────────────────────────────────────────────┐
│                        Your PC                                  │
│  ┌─────────────┐    ┌─────────────────────────────────────────┐ │
│  │   Roblox    │───▶│  SwiftTunnel Split Tunnel               │ │
│  └─────────────┘    │  ┌─────────────────────────────────────┐│ │
│                     │  │ WireGuard Tunnel → Gaming Server    ││ │
│  ┌─────────────┐    │  └─────────────────────────────────────┘│ │
│  │   Discord   │───▶│           (bypassed)                    │ │
│  └─────────────┘    └──────────────────────────────────────── ┘ │
│                              │                                  │
│  ┌─────────────┐             │                                  │
│  │   Chrome    │─────────────┘ (normal internet)                │
│  └─────────────┘                                                │
└─────────────────────────────────────────────────────────────────┘
```

SwiftTunnel uses Windows Filtering Platform (WFP) to intercept game traffic at the network layer. Only packets from your game are encrypted and routed through our servers — everything else goes directly to the internet.


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

```bash
# Install WiX toolset first
cargo install cargo-wix

# Build MSI
cargo wix --nocapture
```

---

## Tech Stack

| Component | Technology |
|-----------|------------|
| GUI | [egui](https://github.com/emilk/egui) / eframe |
| Tunnel | [BoringTun](https://github.com/cloudflare/boringtun) (WireGuard) |
| Network Adapter | [Wintun](https://www.wintun.net/) |
| Split Tunnel | Windows Filtering Platform (WFP) |
| Installer | WiX Toolset |

---

## License

MIT License — see [LICENSE](LICENSE) for details.

---

<p align="center">
  <sub>Built for gamers who hate lag.</sub>
</p>
