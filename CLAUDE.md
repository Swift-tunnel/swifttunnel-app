# SwiftTunnel App

Windows VPN client and PC optimizer built with Tauri v2 (Rust backend + React frontend).

## Agent Rules

- Always add or update tests to validate the bug/finding you fixed and the behavior you changed.
- If end-to-end testing is not feasible, add the closest deterministic unit tests and document the manual validation you performed.
- **Git remotes:** `origin` points to the legacy fork (`evelynwantscookies-ship-it`). Always push branches and create PRs against `upstream` (`Swift-tunnel/swifttunnel-app`).

## Stack

| Layer | Technology |
|-------|------------|
| Language | Rust (Edition 2024) |
| Desktop Framework | Tauri v2 (NSIS installer) |
| Frontend | React 19, TypeScript, Tailwind CSS 4, Vite 6 |
| State Management | Zustand 5 |
| Animations | Framer Motion 12 |
| Testing | Vitest 3 (frontend), cargo test (Rust) |
| VPN | V3 UDP relay (unencrypted, ~0.5-1ms latency) |
| Crypto | x25519-dalek (Curve25519 key exchange), ring 0.17 (Ed25519 signature verification) |
| Network | ndisapi 0.6 (packet filter for split tunneling) |
| Async | Tokio (full features) |
| HTTP | reqwest 0.12 (rustls-tls) |
| Storage | Dual: file-based (primary) + Windows Credential Manager via keyring 3 (secondary) |
| Updater | Tauri plugin updater + custom channel system (Stable/Live) via GitHub Releases |
| Notifications | winrt-notification 0.5 (Windows toast) |
| Discord | discord-rich-presence 0.2 |
| Process detection | ETW (Event Tracing for Windows) for instant game process detection |

## Versions

| Package | Version |
|---------|---------|
| swifttunnel-core | 1.0.40 |
| swifttunnel-desktop (Cargo) | 1.20.0 |
| swifttunnel-desktop (package.json) | 1.20.0 |
| tauri.conf.json | 1.20.0 |

## Filemap

```
swifttunnel-app/                    # Cargo workspace (resolver v2)
├── Cargo.toml                      # Workspace: [swifttunnel-core, swifttunnel-desktop/src-tauri]
│                                   # Release: opt-level=3, lto=true, codegen-units=1, strip=debuginfo
├── swifttunnel-core/               # Shared Rust library (v1.0.40)
│   ├── Cargo.toml                  # Edition 2024, windows 0.62, ndisapi 0.6
│   └── src/
│       ├── lib.rs                  # Module exports + re-exports from utils
│       ├── structs.rs              # Config, PerformanceMetrics, AppState, BoostInfo, ProfileInfo
│       ├── settings.rs             # AppSettings persistence (%APPDATA%\SwiftTunnel\settings.json)
│       ├── utils.rs                # hidden_command, is_administrator, relaunch_elevated, with_retry, log rotation
│       ├── auth/
│       │   ├── mod.rs              # Re-exports AuthManager, OAuthServer, types
│       │   ├── manager.rs          # AuthManager: sign-in, refresh, OAuth flow, profile refresh
│       │   ├── types.rs            # AuthState, AuthSession, UserInfo, VpnConfig, RelayTicketResponse
│       │   ├── storage.rs          # Dual storage: file (XOR-obfuscated) + Windows Credential Manager
│       │   ├── http_client.rs      # AuthClient: Supabase auth, VPN config, relay tickets, profile
│       │   └── oauth_server.rs     # Localhost HTTP server (port 17435) for OAuth callback
│       ├── vpn/
│       │   ├── mod.rs              # VpnError enum, re-exports
│       │   ├── connection.rs       # VpnConnection state machine (2134 lines)
│       │   ├── config.rs           # VPN config fetching, keypair generation, endpoint parsing
│       │   ├── udp_relay.rs        # UdpRelay: V3 unencrypted relay, auth handshake, sender thread + ping RTT/jitter telemetry
│       │   ├── split_tunnel.rs     # SplitTunnelDriver, GamePreset (Roblox/Valorant/Fortnite)
│       │   ├── parallel_interceptor.rs # Per-CPU packet workers, NetworkAdapterInfo, ThroughputStats
│       │   ├── process_cache.rs    # LockFreeProcessCache (RCU pattern), game server IP detection
│       │   ├── process_tracker.rs  # ProcessTracker: PID lookup via IP Helper APIs
│       │   ├── process_watcher.rs  # ProcessWatcher: ETW-based instant game detection
│       │   ├── auto_routing.rs     # AutoRouter: switch relay server based on game server region
│       │   ├── routes.rs           # get_internet_interface_ip()
│       │   ├── servers.rs          # DynamicServerList, latency measurement (TCP + ICMP), caching
│       │   ├── tso_recovery.rs     # TSO (TCP Segmentation Offload) crash recovery
│       │   ├── wfp_block.rs        # WFP (Windows Filtering Platform) per-process traffic blocking
│       │   └── error_messages.rs   # User-friendly VPN error messages
│       ├── network_analyzer/
│       │   ├── mod.rs              # Module exports
│       │   ├── types.rs            # NetworkAnalyzerState, StabilityTestResults, SpeedTestResults, BufferbloatGrade
│       │   ├── speed_test.rs       # Bandwidth measurement
│       │   ├── stability_test.rs   # Ping/jitter/packet loss testing
│       │   └── bufferbloat_test.rs # Bufferbloat detection
│       ├── discord_rpc/
│       │   ├── mod.rs              # Module exports
│       │   ├── manager.rs          # DiscordManager: Rich Presence lifecycle
│       │   └── state.rs            # DiscordState, DiscordActivity, region/game display helpers
│       ├── updater/
│       │   ├── mod.rs              # cleanup_updates()
│       │   └── types.rs            # UpdateState, UpdateInfo, UpdateChannel (Stable/Live), UpdateSettings
│       ├── network_booster.rs      # NetworkBooster: DNS, MTU, QoS, Nagle optimization
│       ├── system_optimizer.rs     # SystemOptimizer: timer resolution, power plan, MMCSS, priority
│       ├── roblox_optimizer.rs     # RobloxOptimizer: FPS unlocker, graphics tuning, ultraboost FFlags
│       ├── roblox_proxy/
│       │   ├── mod.rs              # Module exports, RobloxProxyError enum
│       │   ├── relay.rs            # RobloxProxy: TCP relay engine, ProxyState, per-connection handlers
│       │   ├── sni_parser.rs       # TLS ClientHello SNI extraction, HTTP Host parsing
│       │   ├── doh.rs              # DohResolver: DNS-over-HTTPS (Cloudflare/Google) with TTL cache
│       │   └── hosts.rs            # Windows hosts file management (apply/remove/recover overrides)
│       ├── roblox_watcher.rs       # RobloxWatcher: Roblox process monitoring (RobloxEvent enum)
│       ├── performance_monitor.rs  # PerformanceMonitor: CPU/RAM stats, SystemInfo
│       ├── notification.rs         # Windows toast: show_notification, show_relay_switch, show_server_location
│       └── geolocation.rs          # IP geolocation, RobloxRegion enum, Roblox IP-to-region mapping
├── swifttunnel-desktop/            # Tauri v2 desktop app (v1.20.0)
│   ├── package.json                # React 19, Zustand 5, Framer Motion 12, Tauri API v2
│   ├── vite.config.ts              # Port 1420, Tauri browser mocks for dev
│   ├── vitest.config.ts            # Vitest 3, node environment
│   ├── vitest.setup.ts             # Test setup
│   ├── tsconfig.json               # ES2020, strict, react-jsx
│   ├── index.html                  # Entry HTML
│   ├── src/
│   │   ├── main.tsx                # React entry point
│   │   ├── App.tsx                 # Root: auth gate, tab routing, window state, keyboard shortcuts
│   │   ├── components/
│   │   │   ├── auth/LoginScreen.tsx    # Google OAuth login UI
│   │   │   ├── connect/ConnectTab.tsx  # VPN connection UI, driver remediation status, region picker, connect button
│   │   │   ├── connect/connect.css     # Connect tab styles
│   │   │   ├── boost/BoostTab.tsx      # PC optimization toggles, boost info panels
│   │   │   ├── network/NetworkTab.tsx  # Network analyzer: stability, speed, bufferbloat tests
│   │   │   ├── settings/SettingsTab.tsx # Settings: theme, updater, startup, close-to-tray
│   │   │   └── common/
│   │   │       ├── Sidebar.tsx         # Navigation sidebar with tab icons
│   │   │       └── Toggle.tsx          # Reusable toggle component
│   │   ├── stores/                 # Zustand state stores
│   │   │   ├── authStore.ts        # Auth state, OAuth polling
│   │   │   ├── vpnStore.ts         # VPN connection, auto driver install gate, throughput, diagnostics
│   │   │   ├── boostStore.ts       # Optimization toggles, metrics polling
│   │   │   ├── networkStore.ts     # Network test state and results
│   │   │   ├── serverStore.ts      # Server list, latencies, region selection
│   │   │   ├── settingsStore.ts    # Settings load/save, tab switching
│   │   │   └── updaterStore.ts     # Update check, channel switching, install
│   │   ├── lib/
│   │   │   ├── commands.ts         # All 38 Tauri invoke wrappers (typed)
│   │   │   ├── types.ts            # TypeScript types mirroring Rust backend structs
│   │   │   ├── events.ts           # Tauri event listeners (VPN/auth/throughput/performance)
│   │   │   ├── closeToTray.ts      # Close-to-tray handler
│   │   │   ├── startup.ts          # Auto-reconnect on launch logic
│   │   │   ├── windowState.ts      # Window position/size persistence and visibility
│   │   │   ├── connectedServer.ts  # Connected server display helpers
│   │   │   ├── regionMatch.ts      # Region matching utilities
│   │   │   ├── adminErrors.ts      # Admin privilege error handling
│   │   │   ├── notifications.ts    # Frontend notification helpers
│   │   │   └── utils.ts            # General utilities
│   │   ├── mocks/                  # Browser-only Tauri API mocks (for vite dev without Tauri)
│   │   │   ├── tauri-core.ts
│   │   │   ├── tauri-event.ts
│   │   │   ├── tauri-window.ts
│   │   │   ├── tauri-dpi.ts
│   │   │   ├── tauri-plugin-shell.ts
│   │   │   ├── tauri-plugin-updater.ts
│   │   │   └── tauri-plugin-notification.ts
│   │   └── styles/globals.css      # Tailwind CSS 4 + custom CSS variables
│   └── src-tauri/                  # Tauri Rust backend (v1.20.0)
│       ├── Cargo.toml              # Edition 2024, tauri 2, ring 0.17, semver
│       ├── tauri.conf.json         # NSIS bundle, updater plugin, 1200x800 default window
│       ├── build.rs                # Tauri build script
│       ├── capabilities/default.json # Tauri v2 security capabilities
│       └── src/
│           ├── main.rs             # Entry: windows_subsystem = "windows"
│           ├── lib.rs              # run(): plugin setup, command registration, background tasks
│           ├── state.rs            # AppState: all managers (auth, vpn, servers, boost, discord, etc.)
│           ├── events.rs           # Event constants + payload structs (5 event types)
│           ├── tray.rs             # System tray: Show/Quit menu, left-click restore
│           ├── autostart.rs        # Windows registry Run key for startup launch
│           ├── window_restore.rs   # Restore window: unminimize + show + focus
│           └── commands/           # Tauri IPC commands (39 total)
│               ├── mod.rs          # Module re-exports
│               ├── auth.rs         # 7 commands: get_state, start_oauth, poll_oauth, cancel_oauth, complete_oauth, logout, refresh_profile
│               ├── vpn.rs          # 10 commands: get_state, connect, disconnect, throughput, ping, diagnostics, adapters, server_list/latencies/refresh/smart_select
│               ├── network.rs      # 3 commands: stability_test, speed_test, bufferbloat_test
│               ├── optimizer.rs    # 4 commands: get_metrics, update_config, system_info, restart_roblox
│               ├── proxy.rs        # 2 commands: get_state, toggle
│               ├── settings.rs     # 3 commands: load, save, generate_network_diagnostics_bundle
│               ├── system.rs       # 5 commands: is_admin, check_driver, install_driver (bundled+download fallback), open_url, restart_as_admin
│               └── updater.rs      # 2 commands: check_channel, install_channel
├── .github/workflows/
│   ├── ci.yml                      # CI pipeline
│   ├── release.yml                 # Release pipeline
│   └── claude.yml                  # Claude Code integration
├── scripts/
│   └── validate-revamp.ps1         # PowerShell validation script
├── Windows-testbench/              # Remote testbench documentation
└── V3-ROUTING.md                   # V3 routing protocol documentation
```

## Tauri Commands (39 total)

### Auth (7)
| Command | Signature |
|---------|-----------|
| `auth_get_state` | `() -> AuthStateResponse` |
| `auth_start_oauth` | `() -> String` |
| `auth_poll_oauth` | `() -> OAuthPollResult` |
| `auth_cancel_oauth` | `() -> ()` |
| `auth_complete_oauth` | `(token, callbackState) -> ()` |
| `auth_logout` | `() -> ()` |
| `auth_refresh_profile` | `() -> ()` |

### VPN (7)
| Command | Signature |
|---------|-----------|
| `vpn_get_state` | `() -> VpnStateResponse` |
| `vpn_connect` | `(region, gamePresets) -> ()` |
| `vpn_disconnect` | `() -> ()` |
| `vpn_get_throughput` | `() -> ThroughputResponse?` |
| `vpn_get_ping` | `() -> u32?` |
| `vpn_get_diagnostics` | `() -> DiagnosticsResponse?` |
| `vpn_list_network_adapters` | `() -> NetworkAdapterInfo[]` |

`vpn_get_ping` prefers in-tunnel relay RTT telemetry (control-plane ping/pong) and falls back to ICMP only when no relay sample is available.

### Servers (4)
| Command | Signature |
|---------|-----------|
| `server_get_list` | `() -> ServerListResponse` |
| `server_get_latencies` | `() -> LatencyEntry[]` |
| `server_refresh` | `() -> String` |
| `server_smart_select` | `(regionId) -> String?` |

### Optimizer (4)
| Command | Signature |
|---------|-----------|
| `boost_get_metrics` | `() -> PerformanceMetricsResponse` |
| `boost_update_config` | `(configJson) -> ()` |
| `boost_get_system_info` | `() -> SystemInfoResponse` |
| `boost_restart_roblox` | `() -> ()` |

### Network (3)
| Command | Signature |
|---------|-----------|
| `network_start_stability_test` | `(durationSecs) -> StabilityResultResponse` |
| `network_start_speed_test` | `() -> SpeedResultResponse` |
| `network_start_bufferbloat_test` | `() -> BufferbloatResultResponse` |

### Settings (3)
| Command | Signature |
|---------|-----------|
| `settings_load` | `() -> { json: string }` |
| `settings_save` | `(settingsJson) -> ()` |
| `settings_generate_network_diagnostics_bundle` | `() -> NetworkDiagnosticsBundleResponse` |

### Updater (2)
| Command | Signature |
|---------|-----------|
| `updater_check_channel` | `(channel) -> UpdaterCheckResponse` |
| `updater_install_channel` | `(channel, expectedVersion) -> UpdaterInstallResponse` |

### System (5)
| Command | Signature |
|---------|-----------|
| `system_is_admin` | `() -> AdminCheckResponse` |
| `system_check_driver` | `() -> DriverCheckResponse` |
| `system_install_driver` | `() -> ()` |
| `system_open_url` | `(url) -> ()` |
| `system_restart_as_admin` | `() -> ()` |

`system_install_driver` behavior:
- Uses bundled `WinpkFilter-x64.msi` first.
- Falls back to pinned download `Windows.Packet.Filter.3.6.2.1.x64.msi` from `wiresock/ndisapi`.
- Verifies SHA-256 before invoking `msiexec`.

### Proxy (2)
| Command | Signature |
|---------|-----------|
| `proxy_get_state` | `() -> ProxyStateResponse` |
| `proxy_toggle` | `(enabled) -> ()` |

## Tauri Events (5)

| Event | Payload | Direction |
|-------|---------|-----------|
| `vpn-state-changed` | `VpnStateEvent` | Backend -> Frontend |
| `auth-state-changed` | `AuthStateEvent` | Backend -> Frontend |
| `server-list-updated` | `String` (source) | Backend -> Frontend |
| `throughput-update` | `ThroughputEvent` | Backend -> Frontend |
| `performance-metrics-update` | `PerformanceMetricsEvent` | Backend -> Frontend |

## Tauri Plugins

| Plugin | Purpose |
|--------|---------|
| `tauri-plugin-single-instance` | Prevent multiple app instances, focus existing window |
| `tauri-plugin-notification` | System notifications |
| `tauri-plugin-shell` | Open URLs in browser |
| `tauri-plugin-updater` | Auto-update via GitHub Releases |

## VPN Mode

The app is **V3-only** (V1/V2 WireGuard was removed from the connection flow).

| Mode | Encryption | Latency | Port |
|------|-----------|---------|------|
| V3 | None (UDP relay) | ~0.5-1ms | 51821/UDP |

## Game Presets (Split Tunneling)

| Preset | Processes |
|--------|-----------|
| Roblox | robloxplayerbeta.exe, robloxplayer.exe, windows10universal.exe, robloxplayerlauncher.exe, robloxstudiobeta.exe, robloxstudio.exe, robloxstudiolauncherbeta.exe, robloxstudiolauncher.exe |
| Valorant | valorant-win64-shipping.exe, valorant.exe, riotclientservices.exe, riotclientux.exe, riotclientuxrender.exe |
| Fortnite | fortniteclient-win64-shipping.exe, fortnitelauncher.exe, epicgameslauncher.exe, epicwebhelper.exe |

## Connection States

```
Disconnected -> FetchingConfig -> ConfiguringSplitTunnel -> Connected
                                                         -> Error
Connected -> Disconnecting -> Disconnected
```

| State | Description |
|-------|-------------|
| `Disconnected` | No VPN connection |
| `FetchingConfig` | Resolving relay endpoint |
| `ConfiguringSplitTunnel` | Setting up ndisapi + parallel interceptor |
| `Connected` | Active relay session with split tunnel |
| `Disconnecting` | Tearing down connection |
| `Error` | Connection failed (with error message) |

## Data Flow

### Login Flow
```
App launch -> AuthManager checks file storage + keyring
    |
No session: Show LoginScreen -> "Login with SwiftTunnel"
    |
Start OAuth server (localhost:17435)
    |
Browser: swifttunnel.net/login?desktop=true&state=X&provider=google&redirect_port=17435
    |
User authenticates -> callback to localhost:17435/callback?token=X&state=Y
    |
Exchange token via PUT /api/auth/desktop/exchange
    |
Verify magic link via POST {SUPABASE_URL}/auth/v1/verify
    |
Fetch profile via GET /api/user/profile (is_tester check)
    |
Store in file (XOR-obfuscated + base64) + keyring (Windows Credential Manager)
    |
UI: "Connected as user@example.com"
```

### VPN Connection (V3)
```
User clicks Connect -> VpnConnection::connect(token, region, game_presets)
    |
State: FetchingConfig
    Fetch relay ticket: POST /api/vpn/relay-ticket
    Probe relay candidates (ICMP ping)
    Select lowest-latency server
    |
State: ConfiguringSplitTunnel
    SplitTunnelDriver::configure()
    -> ndisapi + ParallelInterceptor (per-CPU workers)
    -> ProcessCache (lock-free RCU)
    -> ETW ProcessWatcher (instant game detection)
    |
State: Connected {
    server_region, server_endpoint, assigned_ip,
    relay_auth_mode, split_tunnel_active, tunneled_processes
}
```

### Packet Processing (Split Tunnel)
```
Game (Roblox.exe) sends UDP packet to game server
    |
ndisapi intercepts on physical adapter
    |
ParallelInterceptor dispatches by hash(src_ip, src_port) to worker
    |
Worker (pinned to CPU core):
    1. Parse headers -> (src_ip, src_port, dst_ip, dst_port)
    2. LockFreeProcessCache lookup -> PID (O(1))
    3. Check if PID in tunnel_apps
    |
NOT in tunnel_apps -> PASSTHROUGH (inject back to physical adapter)
    |
IN tunnel_apps -> TUNNEL:
    1. Wrap: [8-byte session_id][original IP packet]
    2. Send to relay server (port 51821)
    |
Server relays -> forwards to game server
    |
Response: [session_id][reconstructed IP packet] -> inject to game
```

### Auto-Routing
```
When enabled (auto_routing_enabled in settings):
    |
AutoRouter monitors game server IPs during active connection
    |
Detects game server region change (via IP geolocation / Roblox IP ranges)
    |
If new region has a closer relay server:
    -> Switch relay endpoint automatically
    -> Show toast notification (e.g., "Switched relay: Singapore -> Tokyo")
    |
Whitelisted regions bypass VPN entirely
```

### System Optimization
```
RobloxWatcher detects Roblox.exe via ETW
    |
SystemOptimizer::apply_optimizations():
    - SetPriorityClass(HIGH_PRIORITY_CLASS)
    - Timer resolution: 0.5ms (NtSetTimerResolution)
    - MMCSS gaming profile
    - Power plan: High Performance
    - Windows Game Mode
    - Clear standby memory
    |
RobloxOptimizer::optimize():
    - FPS unlock (target FPS setting)
    - Graphics quality adjustment
    - Ultraboost: all performance FFlags
    |
NetworkBooster::reconcile_optimizations():
    - Disable Nagle (TCP_NODELAY)
    - Disable network throttling
    - MTU optimization
    - Gaming QoS (DSCP EF marking for Roblox + tunnel relay UDP traffic)
    - Restores disabled toggles back to Windows defaults

On startup, the desktop app calls `boost_update_config` with saved settings so enabled per-boost toggles are applied automatically (no master boost switch).
```

## APIs Called

| Endpoint | Method | Purpose |
|----------|--------|---------|
| `{SUPABASE_URL}/auth/v1/token?grant_type=password` | POST | Email/password sign-in |
| `{SUPABASE_URL}/auth/v1/token?grant_type=refresh_token` | POST | Token refresh |
| `{SUPABASE_URL}/auth/v1/verify` | POST | Verify magic link token |
| `swifttunnel.net/api/auth/desktop/exchange` | PUT | Exchange OAuth code for magic link |
| `swifttunnel.net/api/user/profile` | GET | Fetch user profile (is_tester, is_admin) |
| `swifttunnel.net/api/vpn/generate-config` | POST | Get VPN config (keys, server, IP) |
| `swifttunnel.net/api/vpn/relay-ticket` | POST | Get relay auth ticket (JWT, key_id, connection_policy) |
| `swifttunnel.net/api/vpn/servers` | GET | List available servers + relay status |
| `github.com/Swift-tunnel/swifttunnel-app/releases` | GET | Check for updates (GitHub Releases API) |

Note: `SUPABASE_URL` = `https://auth.swifttunnel.net`

## Performance Optimizations

| Optimization | Location |
|--------------|----------|
| Per-CPU packet workers | parallel_interceptor.rs |
| Lock-free RCU cache (<0.1ms) | process_cache.rs |
| Stack-allocated buffers (ArrayVec) | parallel_interceptor.rs |
| Batch packet reading | parallel_interceptor.rs |
| ETW instant game detection | process_watcher.rs |
| Thread CPU affinity | parallel_interceptor.rs |
| Crossbeam channels (lock-free) | parallel_interceptor.rs |
| Arc-swap (BSOD-safe RCU) | process_cache.rs |
| Roblox IP range fast-path | process_cache.rs (is_roblox_game_server) |

## Settings

Stored at `%APPDATA%\SwiftTunnel\settings.json`. Key fields:

```json
{
    "theme": "dark",
    "selected_region": "singapore",
    "selected_server": "singapore",
    "selected_game_presets": ["roblox"],
    "window_state": {"x": 100, "y": 200, "width": 1200, "height": 800, "maximized": false},
    "update_channel": "Stable",
    "minimize_to_tray": false,
    "run_on_startup": true,
    "auto_reconnect": true,
    "enable_discord_rpc": true,
    "auto_routing_enabled": false,
    "whitelisted_regions": [],
    "forced_servers": {},
    "experimental_mode": false,
    "artificial_latency_ms": 0,
    "preferred_physical_adapter_guid": null
}
```

Auth session stored at `%LOCALAPPDATA%\SwiftTunnel\auth_session.dat` (XOR-obfuscated + base64). Server cache at `%APPDATA%\SwiftTunnel\servers.json` (1-hour TTL).

## Building

```bash
# Build Rust backend only
cargo build --release

# Build full desktop app (NSIS installer)
cd swifttunnel-desktop
npm install
npm run tauri:build
# Output: src-tauri/target/release/bundle/nsis/SwiftTunnel_*.exe

# Development
npm run tauri:dev        # Launch with hot-reload (port 1420)

# Tests
npm run test             # Frontend tests (vitest)
cargo test --workspace   # Rust tests
```

## Testing Policy

- Always write automated tests to validate findings, bug fixes, and behavior changes (tests should fail before the fix and pass after).
- If a change is genuinely hard to test automatically (e.g. tray/taskbar visuals), document why and add a manual validation checklist, and still add the closest feasible automated coverage around the underlying logic.
- Run the relevant test suites (see the Windows testbench flow below) and report the results.

## Requirements

- Windows 10/11 (64-bit)
- Administrator privileges (for ndisapi, WFP, and system optimizations)
- ndisapi.sys (Windows Packet Filter driver) - auto-installed (bundled MSI first, pinned download fallback with SHA-256 verification)

## Key Modules

| Module | Purpose |
|--------|---------|
| `vpn/connection.rs` | State machine for VPN lifecycle + UI telemetry accessors |
| `vpn/parallel_interceptor.rs` | Core packet processing (<0.5ms latency) |
| `vpn/process_cache.rs` | Lock-free process lookup (RCU pattern) |
| `vpn/udp_relay.rs` | V3 unencrypted relay (auth + dedicated sender thread + ping RTT/jitter telemetry) |
| `vpn/split_tunnel.rs` | Per-process routing with game presets |
| `vpn/auto_routing.rs` | Automatic relay switching based on game server region |
| `vpn/process_watcher.rs` | ETW-based instant game process detection |
| `vpn/wfp_block.rs` | WFP per-process traffic blocking |
| `vpn/tso_recovery.rs` | TSO crash recovery on startup |
| `system_optimizer.rs` | Windows performance tweaks |
| `roblox_optimizer.rs` | Roblox-specific optimizations (FPS, FFlags) |
| `roblox_proxy/` | Local TCP relay to bypass restrictive networks (DoH + SNI fragmentation) |
| `network_booster.rs` | Network optimizations (DNS, MTU, QoS, Nagle) |
| `geolocation.rs` | IP geolocation and Roblox region mapping |
| `discord_rpc/` | Discord Rich Presence integration |
| `updater/` | Dual-channel (Stable/Live) update system |

## AppState (Tauri Managed State)

All shared state is in `swifttunnel-desktop/src-tauri/src/state.rs`:

| Field | Type | Mutex |
|-------|------|-------|
| `auth_manager` | `AuthManager` | `tokio::sync::Mutex` |
| `vpn_connection` | `VpnConnection` | `tokio::sync::Mutex` |
| `server_list` | `DynamicServerList` | `parking_lot::Mutex` |
| `region_latencies` | `HashMap<String, (String, u32)>` | `parking_lot::Mutex` |
| `settings` | `AppSettings` | `parking_lot::Mutex` |
| `performance_monitor` | `PerformanceMonitor` | `parking_lot::Mutex` |
| `system_optimizer` | `SystemOptimizer` | `parking_lot::Mutex` |
| `roblox_optimizer` | `RobloxOptimizer` | `parking_lot::Mutex` |
| `network_booster` | `NetworkBooster` | `parking_lot::Mutex` |
| `discord_manager` | `DiscordManager` | `parking_lot::Mutex` |
| `roblox_proxy` | `RobloxProxy` | `tokio::sync::Mutex` |
| `runtime` | `tokio::runtime::Runtime` | `Arc` (no mutex) |

## Windows Testbench (Default)

Use this as the default machine for all Windows validation (tests, UAC/admin behavior, updater/install checks).

### Access

- Host: `51.79.128.68`
- User: `testbench`
- Password: `testbench123`

Quick connect:

```bash
sshpass -p 'testbench123' ssh -o StrictHostKeyChecking=no testbench@51.79.128.68
```

Run one remote PowerShell command:

```bash
sshpass -p 'testbench123' ssh -o StrictHostKeyChecking=no testbench@51.79.128.68 "powershell -NoProfile -Command \"<COMMAND_HERE>\""
```

### Remote Workspace Convention

- Preferred repo path: `C:\Users\testbench\swifttunnel-testbench-run`
- If missing/stale, recreate it:

```bash
sshpass -p 'testbench123' ssh -o StrictHostKeyChecking=no testbench@51.79.128.68 "powershell -NoProfile -Command \"Remove-Item -Recurse -Force 'C:\Users\testbench\swifttunnel-testbench-run' -ErrorAction SilentlyContinue; git clone https://github.com/Swift-tunnel/swifttunnel-app.git C:\Users\testbench\swifttunnel-testbench-run; Set-Location C:\Users\testbench\swifttunnel-testbench-run; git checkout main\""
```

### Standard Testbench Validation Flow

1. Rust format check:
```bash
sshpass -p 'testbench123' ssh -o StrictHostKeyChecking=no testbench@51.79.128.68 "powershell -NoProfile -Command \"Set-Location 'C:\Users\testbench\swifttunnel-testbench-run'; cargo fmt --all -- --check\""
```

2. Core library tests:
```bash
sshpass -p 'testbench123' ssh -o StrictHostKeyChecking=no testbench@51.79.128.68 "powershell -NoProfile -Command \"Set-Location 'C:\Users\testbench\swifttunnel-testbench-run'; cargo test -p swifttunnel-core --all-targets --all-features\""
```

3. Full workspace tests:
```bash
sshpass -p 'testbench123' ssh -o StrictHostKeyChecking=no testbench@51.79.128.68 "powershell -NoProfile -Command \"Set-Location 'C:\Users\testbench\swifttunnel-testbench-run'; cargo test --workspace --all-targets --all-features\""
```

4. Frontend build:
```bash
sshpass -p 'testbench123' ssh -o StrictHostKeyChecking=no testbench@51.79.128.68 "powershell -NoProfile -Command \"Set-Location 'C:\Users\testbench\swifttunnel-testbench-run\swifttunnel-desktop'; cmd /c npm ci; cmd /c npm run build\""
```

Notes:
- Use `cmd /c npm ...` to avoid PowerShell execution policy issues with `npm.ps1`.

### UAC/Admin Quick Checks

Check if current session is elevated:

```bash
sshpass -p 'testbench123' ssh -o StrictHostKeyChecking=no testbench@51.79.128.68 "powershell -NoProfile -Command \"([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)\""
```

Collect identity/group context:

```bash
sshpass -p 'testbench123' ssh -o StrictHostKeyChecking=no testbench@51.79.128.68 "whoami /all"
```
