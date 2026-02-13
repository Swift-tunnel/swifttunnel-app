# Windows Split Tunnel Test Tools

Pre-compiled CLI binaries for testing the split tunnel functionality on Windows.

## Contents

| File | Description |
|------|-------------|
| `split_tunnel_integration_test.exe` | Full integration test with WFP + driver + routing verification |
| `split_tunnel_test.exe` | Basic driver-only test (no VPN connection) |
| `ip_checker.exe` | Simple IP checker for split tunnel verification |
| `wintun.dll` | Wintun virtual network adapter (required) |

## Requirements

- Windows 10/11 (64-bit)
- Administrator privileges
- Mullvad split tunnel driver installed (`MullvadSplitTunnel` service)

## Usage

### Full Integration Test

Tests complete split tunnel flow: WFP setup, driver configuration, and traffic routing.

```powershell
# With API token (fetches config from swifttunnel.net)
.\split_tunnel_integration_test.exe --token ACCESS_TOKEN --region singapore

# With config file
.\split_tunnel_integration_test.exe --config vpn_config.json
```

**Options:**
- `--token, -t TOKEN` - Supabase access token for API auth
- `--region, -r REGION` - VPN region (default: singapore)
- `--config, -c FILE` - VPN config JSON file (alternative to --token)
- `--test-exe, -e PATH` - Test executable (default: ip_checker.exe)

**Exit codes:**
- `0` - Success (split tunnel routing verified)
- `1` - Test failed
- `2` - Usage error

### Basic Driver Test

Tests driver IOCTL communication without full VPN setup.

```powershell
.\split_tunnel_test.exe
```

### IP Checker

Simple utility to check your public IP.

```powershell
.\ip_checker.exe
```

## Config File Format

```json
{
  "region": "singapore",
  "serverEndpoint": "server.ip:51820",
  "serverPublicKey": "base64_encoded_key",
  "privateKey": "base64_encoded_key",
  "assignedIp": "10.0.0.77/16",
  "dns": ["1.1.1.1"]
}
```

## Troubleshooting

### Driver not available
```
sc start MullvadSplitTunnel
```

### Driver fails with error 183 ("file already exists")
This means WFP callouts are stuck. Reboot the machine:
```powershell
shutdown /r /t 0
```

### WFP setup fails
Make sure you're running as Administrator.

## Building from Source

```bash
cd swifttunnel-old
cargo build --release --bin split_tunnel_integration_test --bin split_tunnel_test --bin ip_checker
```

Copy binaries and wintun.dll to the same directory.
