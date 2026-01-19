# SwiftTunnel

A gaming-focused VPN client with split tunneling, optimized for low-latency gameplay.

## Features

- **Split Tunneling** - Only game traffic goes through VPN, everything else uses your normal connection
- **Gaming Optimized** - Servers tuned with BBR congestion control and fq_codel for minimal latency
- **PC Boosts** - Built-in FPS unlocker, network optimizations, and system tweaks
- **Regional Servers** - 28 servers across 8 gaming regions worldwide

## Download

Download the latest installer from [Releases](https://github.com/Swift-tunnel/swifttunnel-app/releases).

**Requirements:**
- Windows 10/11 (64-bit)
- Administrator privileges

## Building from Source

### Prerequisites
- Rust 1.70+
- Windows SDK

### Build
```bash
cd swifttunnel-windows
cargo build --release
```

The executable will be at `target/release/swifttunnel-fps-booster.exe`

## License

MIT License - See [LICENSE](LICENSE) for details.
