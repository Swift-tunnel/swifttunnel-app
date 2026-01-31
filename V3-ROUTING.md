# V3 Routing Mode - UDP Relay (Unencrypted)

## Overview

V3 is SwiftTunnel's **lowest latency** routing mode, inspired by ExitLag and WTFast. It trades encryption for raw performance by forwarding game traffic through optimized UDP relay servers without WireGuard encryption.

## Routing Modes Comparison

| Feature | V1 (Process) | V2 (Hybrid) | V3 (Relay) |
|---------|--------------|-------------|------------|
| **Encryption** | WireGuard | WireGuard | None |
| **Latency Overhead** | ~3-5ms | ~2-4ms | ~0.5-1ms |
| **CPU Usage** | Medium | Medium | Low |
| **Privacy** | High | High | Low |
| **Wintun Adapter** | Required | Required | Not Used |
| **Connection Speed** | ~1.5-2s | ~1.5-2s | ~0.5-1s |
| **Best For** | Privacy-focused | Default | Competitive gaming |

## Architecture

### V1/V2 (Encrypted WireGuard)
```
Game → ndisapi → Workers → BoringTun Encrypt → VPN Server → Game Server
                                                    ↓
Game ← MSTCP ← NAT Rewrite ← Decrypt ← VPN Server ←
```

### V3 (Unencrypted UDP Relay)
```
Game → ndisapi → Workers → UDP Relay Server → Game Server
                                    ↓
Game ← MSTCP ← NAT Rewrite ← UDP Relay Server ←
```

## Protocol

V3 uses a simple session-based UDP protocol:

### Packet Format
```
Outbound (Client → Relay):
┌────────────────────┬─────────────────────────────┐
│ Session ID (8 bytes)│ Original UDP Payload        │
└────────────────────┴─────────────────────────────┘

Inbound (Relay → Client):
┌────────────────────┬─────────────────────────────┐
│ Session ID (8 bytes)│ Game Server Response        │
└────────────────────┴─────────────────────────────┘
```

### Session Management
- **Session ID**: 8-byte random identifier generated at connection time
- **Keepalive**: Empty packet with just session ID sent every 25 seconds
- **Port**: 51821/UDP (separate from WireGuard's 51820)

## Connection Flow

### V1/V2 Connection (~1.5-2 seconds)
1. Fetch VPN config from API
2. Create Wintun virtual adapter
3. Initialize WireGuard tunnel
4. Perform WireGuard handshake
5. Configure split tunnel (ndisapi)
6. Setup routes
7. Connected

### V3 Connection (~0.5-1 second)
1. Fetch config from API (for server IP)
2. Configure split tunnel (ndisapi)
3. Create UDP relay connection
4. Connected

**V3 skips:**
- Wintun adapter creation (~500ms)
- WireGuard tunnel initialization
- WireGuard handshake
- Route configuration

## Implementation

### Key Files
| File | Purpose |
|------|---------|
| `src/vpn/udp_relay.rs` | UDP relay client (session, keepalive, forward/receive) |
| `src/vpn/connection.rs` | `connect_v3()` and `setup_v3_split_tunnel()` |
| `src/vpn/parallel_interceptor.rs` | `run_v3_inbound_receiver()` for receiving relay responses |
| `src/settings.rs` | `RoutingMode::V3` enum variant |

### UdpRelay Struct
```rust
pub struct UdpRelay {
    socket: UdpSocket,           // Local UDP socket
    relay_addr: SocketAddr,      // Relay server address
    session_id: [u8; 8],         // Random session identifier
    stop_flag: Arc<AtomicBool>,  // Shutdown signal
    packets_sent: AtomicU64,     // Stats
    packets_received: AtomicU64, // Stats
}
```

### Key Methods
- `forward_outbound(payload)` - Add session ID and send to relay
- `receive_inbound(buffer)` - Receive from relay and strip session ID
- `send_keepalive()` - Maintain NAT binding

## Server Side

The relay server (port 51821) needs to:
1. Receive packets with session ID prefix
2. Track session → client address mapping
3. Forward payload to game server (from relay's IP)
4. Receive game server responses
5. Forward responses back to client with session ID

### Relay Server Requirements
- Runs on same IP as VPN server
- Port: 51821/UDP
- Tracks: `session_id → (client_addr, game_server_addr)`
- No encryption/decryption

## Security Considerations

**V3 provides:**
- Route optimization (lower latency path to game servers)
- IP masking (game server sees relay IP, not client IP)
- Session isolation (unique session ID per connection)

**V3 does NOT provide:**
- Encryption (traffic is readable)
- Protection from ISP inspection
- Privacy from relay server operator

**Use V3 when:**
- Competitive gaming where every millisecond matters
- Trusted network (home, not public WiFi)
- Priority is latency over privacy

**Use V1/V2 when:**
- Privacy is important
- On untrusted networks
- ISP throttles gaming traffic

## Configuration

### User Settings
```rust
pub enum RoutingMode {
    V1,              // Process-based WireGuard
    #[default]
    V2,              // Hybrid WireGuard (default)
    V3,              // UDP Relay (no encryption)
}
```

### UI Selection
Settings tab shows:
- **V1**: "Encrypted (Process)"
- **V2**: "Encrypted (Hybrid)" - Default, recommended
- **V3**: "Unencrypted (Fastest)" - For competitive gaming

## Troubleshooting

### V3 Not Working
1. Check relay server is running on port 51821
2. Verify UDP 51821 isn't blocked by firewall
3. Check logs for "V3 INBOUND RECEIVER" messages

### Zero Inbound Traffic in V3
- Relay server may not be forwarding responses
- Check session ID matches in logs
- Verify relay server tracks sessions correctly

### High Latency in V3
- This shouldn't happen - V3 should be fastest
- Check if relay server is overloaded
- Verify game server isn't far from relay server

## Metrics

V3 logs include:
```
V3 inbound health: 60s uptime, 1234 recv, 1230 injected, 15000 B/s avg, 4 errors
```

- `recv`: Packets received from relay
- `injected`: Packets delivered to game
- `B/s avg`: Average throughput
- `errors`: Injection failures
