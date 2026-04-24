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
    <img src="https://img.shields.io/github/v/release/Swift-tunnel/swifttunnel-app?display_name=tag&style=flat-square&color=blue" alt="Latest Release" />
  </a>
  <a href="https://github.com/Swift-tunnel/swifttunnel-app/releases">
    <img src="https://img.shields.io/badge/downloads-GitHub-green?style=flat-square" alt="Downloads" />
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
28 gaming-optimized servers across 10 regions. Each server runs:
- **BBR** congestion control for faster throughput
- **fq_codel** queue management to eliminate bufferbloat
- **V3 UDP relay** protocol for minimal overhead (~0.5-1ms)

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
Starts on the lowest-latency region from the in-app ping test, then detects which game server you're connecting to and routes through the optimal SwiftTunnel server (ExitLag-style). Manual server pins stay respected, and live ping-test refreshes keep Auto Route's server choices current while connected.

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
# Or: git clone git@github.com:Swift-tunnel/swifttunnel-app.git
cd swifttunnel-app/swifttunnel-desktop

# Install frontend + Tauri CLI dependencies
npm ci

# Frontend production build
npm run build

# Desktop dev mode
npm run tauri:dev
```

### Build MSI Installer

```bash
cd swifttunnel-desktop
npm run tauri:build
```

Installer output:
- `swifttunnel-desktop/src-tauri/target/release/bundle/msi/*.msi`
- Updater artifacts and signatures are generated when signing keys are configured.

### Release Pipeline

The release workflow requires these CI/CD variables:
- `TAURI_SIGNING_PRIVATE_KEY`
- `TAURI_SIGNING_PRIVATE_KEY_PASSWORD`
- `TAURI_UPDATER_PUBLIC_KEY`
- `TAURI_SIGNING_LEGACY_PRIVATE_KEY` (required only for a legacy bridge tag)
- `TAURI_SIGNING_LEGACY_PRIVATE_KEY_PASSWORD` (required only for a legacy bridge tag)
- `TAURI_UPDATER_LEGACY_PUBLIC_KEY` (required only for a legacy bridge tag)
- `SWIFTTUNNEL_UPDATE_MANIFEST_PRIVATE_KEY`
- `SWIFTTUNNEL_UPDATE_MANIFEST_PUBLIC_KEY_B64`

Notes:
- Releases are tag-driven from `main` only (`v*` tags).
- `vX.Y.Z-*` publishes as prerelease (`Live` channel).
- `vX.Y.Z` publishes as stable release (`Stable` channel).
- Any tag listed in `release-signing.toml` under `legacy_bridge.tags` is signed with the legacy Tauri private key instead of the current key, and the workflow verifies that the configured updater public keys match the expected key ids recorded in that file.
- `TAURI_UPDATER_PUBLIC_KEY` is the base64-encoded contents of the minisign updater public key file, and it is injected into `swifttunnel-desktop/src-tauri/tauri.conf.json` during CI.
- If `TAURI_UPDATER_LEGACY_PUBLIC_KEY` is configured, shipped apps can retry updater verification with the legacy Tauri key during a staged migration.
- `node scripts/check-desktop-version-sync.mjs` verifies `swifttunnel-desktop/src-tauri/Cargo.toml` and `swifttunnel-desktop/src-tauri/tauri.conf.json` stay on the same version, and CI now enforces it on pushes and PRs.
- x64 and ARM64 WinpkFilter MSIs are fetched in CI, SHA-256 checked, and extracted into signed INF/SYS/CAT driver packages under `swifttunnel-desktop/src-tauri/resources/drivers/winpkfilter/<arch>/win10`.
- MSI install runs `SwiftTunnel.exe --install-driver` after files land; the helper installs the extracted native driver package with `pnputil`, repairs/starts `NDISRD`, and writes `%ProgramData%\SwiftTunnel\logs\driver-install.log`.
- Runtime driver repair remains available in-app and uses structured health status to install, reset, reinstall, or request reboot without repeatedly offering the same install action.
- `wintun.dll` and driver assets are bundled from `swifttunnel-desktop/src-tauri/resources/drivers`.
- `swifttunnel-update-manifest.json` and `swifttunnel-update-manifest.sig` are generated and uploaded per release for updater pre-verification.
- `SWIFTTUNNEL_UPDATE_MANIFEST_PRIVATE_KEY` should be an Ed25519 private key (PEM), and `SWIFTTUNNEL_UPDATE_MANIFEST_PUBLIC_KEY_B64` should be the matching raw 32-byte public key encoded in base64.
- Windows CI and release packaging run on the self-hosted `testbench` GitHub runner so GitHub uses the same Windows environment we already trust for real builds.
- A scheduled GitHub reconciliation workflow dispatches the normal GitHub `Release` workflow if the newest GitHub semver tag is missing its release entry.

### GitHub Cutover Notes

- GitHub is the canonical source for releases and updater assets.
- GitHub is the only supported release publishing path.
- The existing GitHub updater secret currently matches the legacy GitHub trust root used by `v1.20.18` (`A943D352BDA748D5`), while GitLab `1.21.16` uses key id `436B4C95C608A09A`.
- Before enabling GitHub releases, move the current GitHub Tauri secrets into the `*_LEGACY_*` slots and replace the primary slots with the GitLab-era current keypair.
- If older installed builds still trust a legacy GitHub-era Tauri key, add the bridge tag to `release-signing.toml` before cutting it so the GitHub release workflow signs that one tag with the legacy private key while still embedding the current updater public key in the app.
- Do not publish a higher stable GitHub version signed only with the current key until that bridge window is complete, or legacy clients will select the newer tag and fail signature verification.

### Installer Validation Checklist (Clean Windows 10/11)

1. Install using the generated MSI installer on a clean VM.
2. Launch app and confirm login flow works.
3. Confirm `%APPDATA%\SwiftTunnel\settings.json` is read/written correctly.
4. Click Connect once on a clean machine and confirm SwiftTunnel auto-installs the Windows Packet Filter driver (UAC prompt expected) before connecting.
5. Connect/disconnect VPN at least once (ensures `wintun.dll` staging and split tunnel checks are healthy).
6. Run in-app updater check from Settings.

Settings migration status: no schema migration required. The Tauri app continues using `%APPDATA%\SwiftTunnel\settings.json`.

### Automated Validation

On Windows test environments, run:

```powershell
.\scripts\validate-revamp.ps1
```

This runs formatter checks, region resolver tests, updater channel/security tests, and frontend build validation.

---

## Tech Stack

| Component | Technology |
|-----------|------------|
| GUI | [Tauri v2](https://tauri.app/) + [React 19](https://react.dev/) + TypeScript |
| Tunnel | V3 UDP Relay (custom, ~0.5-1ms overhead) |
| Split Tunnel | ndisapi (Windows Packet Filter) |
| Installer | MSI (Tauri/WiX bundler) |

---

## License

MIT License — see [LICENSE](LICENSE) for details.

---

<p align="center">
  <sub>Built for gamers who hate lag.</sub>
</p>
