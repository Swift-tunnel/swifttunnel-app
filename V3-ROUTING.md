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
   - When Auto Route is enabled, the initial region is chosen from the in-app ping-test latency cache when available.
2. Configure split tunnel (ndisapi)
3. Create UDP relay connection
   - On Windows, SwiftTunnel marks the relay UDP socket with DSCP EF (46) best-effort so latency-sensitive game packets can stay in low-latency queues on networks that honor DSCP.
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
| `src/process_names.rs` | Roblox process-name rules for Win32 player/studio detection |
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

### Relay Traffic QoS
- The removed Gaming QoS boost must stay removed: do not restore broad Windows QoS policies for Roblox executables or `Windows10Universal.exe`.
- The client may mark only SwiftTunnel relay UDP traffic with DSCP EF (46). It does this socket-scoped in `udp_relay.rs`; when latency network throttling boost is enabled, `network_booster.rs` also installs a process+UDP-scoped SwiftTunnel QoS policy and restores the global QoS registry values from snapshots on cleanup.
- Relay ports are still taken from the server-list API. QoS policy matching intentionally avoids hardcoding a relay port; the actual relay socket is marked directly.

### Auto Route Selection
- Initial Auto Route connects to the region with the best measured in-app ping-test latency when latency data exists; otherwise it falls back to the requested/last selected region.
- If the requested region has a manual server pin, Auto Route starts there and uses the pinned server. Pinned regions are scored by the pinned server's latency, not by another sibling server.
- The periodic server ping test updates the live auto-router candidate snapshot, so relay switches use the same fresh latency data shown in the UI. Latency probes use the native `IcmpSendEcho` API (locale-independent), never `ping.exe` text parsing, and always run on blocking threads.
- After Roblox game-server region detection, the auto-router still targets the matching SwiftTunnel region and picks the lowest-latency relay inside that region (cached latency), honoring any forced server override.
- Every auto-route relay switch authenticates the target relay first: relay ticket fetch + auth hello + ack `Ok` while the candidate game server's packets are still held. Any ticket/auth failure (one bounded retry for transport failures) leaves the session on its current authenticated relay — never an unauthenticated switch.
- Relay switches only happen at connection boundaries (first join or gone-quiet handoff) while packets are held. Once a game-server connection is flowing through a relay, it is never switched mid-session: the game server would see the client's source IP change, which Roblox's RakNet drops.
- Gone-quiet handoff: a new game-server IP becomes a routing signal only when all other tracked game-server traffic has been quiet for ≥3s (player left/teleported — Roblox loading screens provide the gap). A new IP observed while another connection is actively sending is recorded but never re-routed for the rest of the session.
- Auto Route, whitelisted regions, and forced-server changes apply to the live session on settings save; custom-relay sessions never run the auto-routing lookup task. Disabling Auto Route permanently invalidates in-flight lookups/switches — the session epoch is bumped, so a quick off→on toggle cannot resurrect them and `commit_switch` revalidates before mutating relay state (held packets release on the current relay) — and revokes an active whitelist bypass, as does un-whitelisting the current game region; a bypass is never newly engaged outside a lookup boundary.
- The relay RTT shown in the UI resets on every relay switch and is freshness-gated (~5s): a relay that stops answering pongs reports "no data" (falling back to ICMP) instead of freezing on the previous relay's reading.

### Roblox Process Identity
- Win32 Roblox player/studio executables are matched by exact process stem or known Roblox alias only; broad substring matches are not tunnel signals.
- Microsoft Store/UWP Roblox is intentionally not tunnel-eligible because it runs under the generic `Windows10Universal.exe` host used by unrelated Store apps.

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
