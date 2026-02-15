//! VPN Connection Manager
//!
//! Manages the lifecycle of VPN connections, coordinating:
//! - Relay endpoint resolution
//! - Split tunneling via ndisapi (process-based per-app routing)
//! - UDP relay for game traffic forwarding
//! - Connection state tracking

use super::parallel_interceptor::ThroughputStats;
use super::process_watcher::{ProcessStartEvent, ProcessWatcher};
use super::routes::get_internet_interface_ip;
use super::split_tunnel::{SplitTunnelConfig, SplitTunnelDriver};
use super::{VpnError, VpnResult};
use crate::auth::types::VpnConfig;
use crossbeam_channel::Receiver;
use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};
use tokio::sync::Mutex;

/// Refresh interval for process exclusion scanning (ms)
/// Lower = faster detection of new processes, slightly higher CPU
/// 500ms balances detection speed with CPU usage
const REFRESH_INTERVAL_MS: u64 = 500;

fn pick_lowest_latency_server<'a>(
    candidates: impl Iterator<Item = &'a (String, SocketAddr, Option<u32>)>,
) -> Option<&'a (String, SocketAddr, Option<u32>)> {
    candidates.min_by_key(|(_, _, latency_ms)| latency_ms.unwrap_or(u32::MAX))
}

pub(crate) fn resolve_relay_server_for_region(
    selected_region: &str,
    available_servers: &[(String, SocketAddr, Option<u32>)],
    forced_server: Option<&str>,
) -> Option<(String, SocketAddr)> {
    // If a specific server is pinned for this region, use it directly
    if let Some(pinned) = forced_server {
        if let Some((server_region, relay_addr, _)) = available_servers
            .iter()
            .find(|(server_region, _, _)| server_region == pinned)
        {
            log::info!(
                "Using pinned server '{}' for region '{}'",
                pinned,
                selected_region
            );
            return Some((server_region.clone(), *relay_addr));
        }
        log::warn!(
            "Pinned server '{}' not found in server list, falling back to best latency",
            pinned
        );
    }

    if let Some((server_region, relay_addr, _)) = pick_lowest_latency_server(
        available_servers
            .iter()
            .filter(|(server_region, _, _)| server_region == selected_region),
    ) {
        return Some((server_region.clone(), *relay_addr));
    }

    let prefix = format!("{selected_region}-");
    pick_lowest_latency_server(
        available_servers
            .iter()
            .filter(|(server_region, _, _)| server_region.starts_with(&prefix)),
    )
    .map(|(server_region, relay_addr, _)| (server_region.clone(), *relay_addr))
}

/// Quick-ping candidate relay servers and return the best one.
/// Pings all candidates in parallel using ICMP (same as GUI latency measurement).
/// Returns (region_name, addr, latency_ms) for the fastest responder.
async fn ping_and_select_best(
    candidates: &[(String, SocketAddr)],
) -> Option<(String, SocketAddr, u32)> {
    use crate::vpn::servers::measure_latency_icmp;

    let mut tasks = Vec::new();
    for (region, addr) in candidates {
        let region = region.clone();
        let addr = *addr;
        tasks.push(tokio::spawn(async move {
            let ip = addr.ip().to_string();
            // Use ICMP ping — reliable for all server types.
            // The previous UDP probe ([0u8; 1] to relay port 51821) never got responses
            // because relay servers only respond to valid session ID packets.
            let result = tokio::task::spawn_blocking(move || measure_latency_icmp(&ip)).await;

            match result {
                Ok(Some(ms)) => {
                    log::info!("Auto-routing ping: {} ({}) = {}ms", region, addr, ms);
                    Some((region, addr, ms))
                }
                _ => {
                    log::info!("Auto-routing ping: {} ({}) = timeout", region, addr);
                    None
                }
            }
        }));
    }

    let mut best: Option<(String, SocketAddr, u32)> = None;
    for task in tasks {
        if let Ok(Some((region, addr, ms))) = task.await {
            if best.as_ref().map_or(true, |(_, _, best_ms)| ms < *best_ms) {
                best = Some((region, addr, ms));
            }
        }
    }

    if let Some((ref region, ref addr, ms)) = best {
        log::info!(
            "Auto-routing: Best candidate: {} ({}) at {}ms",
            region,
            addr,
            ms
        );
    }
    best
}

/// VPN connection state
#[derive(Debug, Clone, PartialEq)]
pub enum ConnectionState {
    Disconnected,
    FetchingConfig,
    CreatingAdapter,
    Connecting,
    ConfiguringSplitTunnel,
    /// Adding routes through VPN interface
    ConfiguringRoutes,
    Connected {
        since: Instant,
        server_region: String,
        server_endpoint: String,
        assigned_ip: String,
        split_tunnel_active: bool,
        tunneled_processes: Vec<String>,
    },
    Disconnecting,
    Error(String),
}

impl ConnectionState {
    pub fn is_connected(&self) -> bool {
        matches!(self, ConnectionState::Connected { .. })
    }

    pub fn is_connecting(&self) -> bool {
        matches!(
            self,
            ConnectionState::FetchingConfig
                | ConnectionState::CreatingAdapter
                | ConnectionState::Connecting
                | ConnectionState::ConfiguringSplitTunnel
                | ConnectionState::ConfiguringRoutes
        )
    }

    pub fn is_error(&self) -> bool {
        matches!(self, ConnectionState::Error(_))
    }

    pub fn error_message(&self) -> Option<&str> {
        match self {
            ConnectionState::Error(msg) => Some(msg),
            _ => None,
        }
    }

    pub fn status_text(&self) -> &'static str {
        match self {
            ConnectionState::Disconnected => "Disconnected",
            ConnectionState::FetchingConfig => "Resolving relay endpoint...",
            ConnectionState::CreatingAdapter => "Creating network adapter...",
            ConnectionState::Connecting => "Connecting to server...",
            ConnectionState::ConfiguringSplitTunnel => "Configuring split tunnel...",
            ConnectionState::ConfiguringRoutes => "Setting up routes...",
            ConnectionState::Connected { .. } => "Connected",
            ConnectionState::Disconnecting => "Disconnecting...",
            ConnectionState::Error(_) => "Error",
        }
    }
}

impl Default for ConnectionState {
    fn default() -> Self {
        ConnectionState::Disconnected
    }
}

/// VPN Connection manager
pub struct VpnConnection {
    state: Arc<Mutex<ConnectionState>>,
    split_tunnel: Option<Arc<Mutex<SplitTunnelDriver>>>,
    config: Option<VpnConfig>,
    process_monitor_stop: Arc<AtomicBool>,
    /// ETW process watcher for instant game detection
    etw_watcher: Option<ProcessWatcher>,
    /// Auto-router for automatic relay switching based on game server region
    auto_router: Option<Arc<super::auto_routing::AutoRouter>>,
}

impl VpnConnection {
    pub fn new() -> Self {
        Self {
            state: Arc::new(Mutex::new(ConnectionState::Disconnected)),
            split_tunnel: None,
            config: None,
            process_monitor_stop: Arc::new(AtomicBool::new(false)),
            etw_watcher: None,
            auto_router: None,
        }
    }

    pub async fn state(&self) -> ConnectionState {
        self.state.lock().await.clone()
    }

    pub fn state_handle(&self) -> Arc<Mutex<ConnectionState>> {
        Arc::clone(&self.state)
    }

    /// Get throughput stats for GUI display
    ///
    /// Returns the ThroughputStats handle if split tunnel is active and using parallel mode.
    /// Uses try_lock() to avoid blocking the GUI thread.
    pub fn get_throughput_stats(&self) -> Option<ThroughputStats> {
        self.split_tunnel.as_ref().and_then(|st| {
            st.try_lock()
                .ok()
                .and_then(|driver| driver.get_throughput_stats())
        })
    }

    /// Get split tunnel diagnostic info for UI display
    ///
    /// Returns: (adapter_name, has_default_route, packets_tunneled, packets_bypassed)
    /// Uses try_lock() to avoid blocking the GUI thread.
    pub fn get_split_tunnel_diagnostics(&self) -> Option<(Option<String>, bool, u64, u64)> {
        self.split_tunnel.as_ref().and_then(|st| {
            st.try_lock()
                .ok()
                .and_then(|driver| driver.get_diagnostics())
        })
    }

    /// Get the current config ID (for latency updates)
    pub fn get_config_id(&self) -> Option<String> {
        self.config.as_ref().map(|c| c.id.clone())
    }

    /// Get detected game server IPs for notifications (Bloxstrap-style)
    ///
    /// Returns a list of Roblox game server IPs that have been tunneled.
    /// Uses try_lock() to avoid blocking the GUI thread.
    pub fn get_detected_game_servers(&self) -> Vec<std::net::Ipv4Addr> {
        self.split_tunnel
            .as_ref()
            .and_then(|st| {
                st.try_lock()
                    .ok()
                    .map(|driver| driver.get_detected_game_servers())
            })
            .unwrap_or_default()
    }

    /// Clear detected game servers (call on disconnect)
    pub fn clear_detected_game_servers(&self) {
        if let Some(st) = self.split_tunnel.as_ref() {
            if let Ok(driver) = st.try_lock() {
                driver.clear_detected_game_servers();
            }
        }
    }

    /// Get the auto-router for GUI display or external access
    pub fn auto_router(&self) -> Option<&Arc<super::auto_routing::AutoRouter>> {
        self.auto_router.as_ref()
    }

    async fn set_state(&self, state: ConnectionState) {
        log::info!("Connection state: {:?}", state);
        *self.state.lock().await = state;
    }

    /// Connect to VPN server using UDP relay (V3 mode)
    ///
    /// Sets up ndisapi packet interception with UDP relay forwarding.
    /// No Wintun adapter, no WireGuard encryption — lowest latency.
    ///
    /// # Arguments
    /// * `_access_token` - Reserved for future authenticated relay/session APIs
    /// * `region` - Server region to connect to
    /// * `tunnel_apps` - Apps that SHOULD use VPN (games). Everything else bypasses.
    pub async fn connect(
        &mut self,
        _access_token: &str,
        region: &str,
        tunnel_apps: Vec<String>,
        custom_relay_server: Option<String>,
        auto_routing_enabled: bool,
        available_servers: Vec<(String, std::net::SocketAddr, Option<u32>)>,
        whitelisted_regions: Vec<String>,
        forced_servers: std::collections::HashMap<String, String>,
    ) -> VpnResult<()> {
        {
            let state = self.state.lock().await;
            if state.is_connected() {
                return Err(VpnError::Connection("Already connected".to_string()));
            }
            if state.is_connecting() {
                return Err(VpnError::Connection("Connection in progress".to_string()));
            }
        }

        log::info!("Starting VPN connection to region: {}", region);
        log::info!("Apps to tunnel: {:?}", tunnel_apps);

        log::info!("========================================");
        log::info!("V3 MODE: Lightweight UDP Relay");
        log::info!("========================================");
        log::info!("  - No Wintun adapter");
        log::info!("  - No WireGuard encryption");
        log::info!("  - No route configuration");
        log::info!("  - Direct UDP relay to game servers");
        log::info!("========================================");

        // Step 1: Resolve initial relay endpoint from available servers
        self.set_state(ConnectionState::FetchingConfig).await;
        let forced_for_region = forced_servers.get(region).map(|s| s.as_str());
        let (resolved_server_region, selected_relay_addr) =
            match resolve_relay_server_for_region(region, &available_servers, forced_for_region) {
                Some((server_region, relay_addr)) => (server_region, relay_addr),
                None => {
                    let error = VpnError::ConfigFetch(format!(
                        "Selected region '{}' is unavailable in server list",
                        region
                    ));
                    self.set_state(ConnectionState::Error(error.to_string()))
                        .await;
                    return Err(error);
                }
            };

        if resolved_server_region != region {
            log::info!(
                "Resolved selected region '{}' to relay server '{}'",
                region,
                resolved_server_region
            );
        }

        let config = VpnConfig {
            // In V3 we only need region + endpoint for relay bootstrap.
            // Use the resolved server id (e.g. "us-east-nj") so UI can show the exact server.
            region: resolved_server_region.clone(),
            endpoint: selected_relay_addr.to_string(),
            ..Default::default()
        };

        log::info!(
            "V3: Server endpoint: {} (resolved via server '{}')",
            config.endpoint,
            resolved_server_region
        );
        // V3 no longer creates/stores vpn_configs records via generate-config.
        self.config = None;

        // Initialize WFP block filter engine (for instant process blocking)
        if let Err(e) = super::wfp_block::init() {
            log::warn!(
                "WFP block filter init failed (will use speculative tunneling): {}",
                e
            );
        }

        // Step 2: Skip Wintun - go directly to split tunnel
        // V3 doesn't need a virtual adapter
        self.set_state(ConnectionState::ConfiguringSplitTunnel)
            .await;

        let (tunneled_processes, split_tunnel_active) = if !tunnel_apps.is_empty() {
            match self
                .setup_split_tunnel(
                    &config,
                    tunnel_apps.clone(),
                    custom_relay_server,
                    auto_routing_enabled,
                    available_servers,
                    whitelisted_regions,
                    forced_servers,
                )
                .await
            {
                Ok(processes) => {
                    log::info!("V3 split tunnel setup succeeded");
                    (processes, true)
                }
                Err(e) => {
                    log::error!("V3 split tunnel setup FAILED: {}", e);
                    self.cleanup().await;
                    self.set_state(ConnectionState::Error(format!(
                        "V3 split tunnel failed: {}",
                        e
                    )))
                    .await;
                    return Err(e);
                }
            }
        } else {
            log::warn!("No tunnel apps specified");
            (Vec::new(), false)
        };

        // Step 3: Skip routes - V3 doesn't need them
        // Traffic is intercepted at NDIS layer and forwarded via relay

        // Step 4: Mark as connected
        self.set_state(ConnectionState::Connected {
            since: Instant::now(),
            server_region: config.region.clone(),
            server_endpoint: config.endpoint.clone(),
            assigned_ip: "V3-Relay".to_string(), // No VPN IP in V3 mode
            split_tunnel_active,
            tunneled_processes,
        })
        .await;

        log::info!("V3 connected successfully (no encryption, lowest latency)");
        Ok(())
    }

    /// Split tunnel setup - ndisapi + UDP relay
    ///
    /// Simplified flow:
    /// 1. Check driver availability
    /// 2. Open/initialize driver
    /// 3. Create UDP relay to server
    /// 4. Configure with relay context (no WireGuard)
    /// 5. Start process monitor
    async fn setup_split_tunnel(
        &mut self,
        config: &VpnConfig,
        tunnel_apps: Vec<String>,
        custom_relay_server: Option<String>,
        auto_routing_enabled: bool,
        available_servers: Vec<(String, std::net::SocketAddr, Option<u32>)>,
        whitelisted_regions: Vec<String>,
        forced_servers: std::collections::HashMap<String, String>,
    ) -> VpnResult<Vec<String>> {
        log::info!("Setting up V3 split tunnel (no Wintun)...");

        // Get internet interface IP for NAT rewriting on inbound packets
        let internet_ip = get_internet_interface_ip().map_err(|e| {
            VpnError::SplitTunnelSetupFailed(format!("Failed to get internet interface IP: {}", e))
        })?;
        log::info!("V3: Internet interface IP: {}", internet_ip);

        // Check if driver is available
        if !SplitTunnelDriver::check_driver_available() {
            return Err(VpnError::SplitTunnelNotAvailable);
        }

        // Create and configure driver
        let mut driver = SplitTunnelDriver::new();

        // Open driver
        driver.open().map_err(|e| {
            VpnError::SplitTunnelSetupFailed(format!("Failed to open driver: {}", e))
        })?;
        log::info!("V3: Split tunnel driver opened");

        // Initialize driver
        driver.initialize().map_err(|e| {
            let _ = driver.close();
            VpnError::SplitTunnelSetupFailed(format!("Failed to initialize driver: {}", e))
        })?;
        log::info!("V3: Split tunnel driver initialized");

        // Create UDP relay to relay server
        // Use custom relay if configured (experimental feature), otherwise auto-detect from VPN server
        let relay_addr: SocketAddr = if let Some(ref custom) = custom_relay_server {
            // Custom relay configured - resolve with DNS support
            log::info!("V3: Using CUSTOM relay server: {}", custom);

            // Parse host:port and resolve via Cloudflare DNS (1.1.1.1)
            let (host, port) = if let Some((h, p)) = custom.rsplit_once(':') {
                let port: u16 = p.parse().map_err(|e| {
                    let _ = driver.close();
                    VpnError::SplitTunnelSetupFailed(format!("Invalid port in '{}': {}", custom, e))
                })?;
                (h, port)
            } else {
                let _ = driver.close();
                return Err(VpnError::SplitTunnelSetupFailed(format!(
                    "Custom relay '{}' must include a port (e.g. host:51821)",
                    custom
                )));
            };

            // Try parsing as IP first to skip DNS for raw IPs
            if let Ok(ip) = host.parse::<std::net::IpAddr>() {
                let addr = SocketAddr::new(ip, port);
                log::info!("V3: Custom relay is IP address: {}", addr);
                addr
            } else {
                // Resolve hostname via system DNS
                match tokio::net::lookup_host(format!("{}:{}", host, port)).await {
                    Ok(mut addrs) => {
                        if let Some(addr) = addrs.next() {
                            log::info!("V3: Resolved custom relay to {}", addr);
                            addr
                        } else {
                            let _ = driver.close();
                            return Err(VpnError::SplitTunnelSetupFailed(format!(
                                "DNS resolution returned no addresses for '{}'",
                                custom
                            )));
                        }
                    }
                    Err(e) => {
                        let _ = driver.close();
                        return Err(VpnError::SplitTunnelSetupFailed(format!(
                            "Failed to resolve custom relay '{}': {}",
                            custom, e
                        )));
                    }
                }
            }
        } else {
            // No custom relay = use resolved server endpoint, forcing relay port 51821.
            if let Ok(addr) = config.endpoint.parse::<SocketAddr>() {
                SocketAddr::new(addr.ip(), 51821)
            } else if let Ok(ip) = config.endpoint.parse::<std::net::IpAddr>() {
                SocketAddr::new(ip, 51821)
            } else {
                let vpn_ip = config
                    .endpoint
                    .split(':')
                    .next()
                    .unwrap_or(&config.endpoint);
                format!("{}:51821", vpn_ip).parse().map_err(|e| {
                    VpnError::SplitTunnelSetupFailed(format!(
                        "Invalid VPN server IP for relay: {}",
                        e
                    ))
                })?
            }
        };

        log::info!("V3: Creating UDP relay to {}", relay_addr);

        let relay = match super::udp_relay::UdpRelay::new(relay_addr) {
            Ok(r) => std::sync::Arc::new(r),
            Err(e) => {
                let _ = driver.close();
                return Err(VpnError::SplitTunnelSetupFailed(format!(
                    "Failed to create V3 relay: {}",
                    e
                )));
            }
        };

        let relay_for_lookup = Arc::clone(&relay);
        driver.set_relay_context(relay);
        log::info!("V3: UDP relay context set");

        // Set up auto-routing
        let auto_router = Arc::new(super::auto_routing::AutoRouter::new(
            auto_routing_enabled,
            &config.region,
        ));
        auto_router.set_current_relay(relay_addr, &config.region);
        auto_router.set_available_servers(available_servers);
        if !whitelisted_regions.is_empty() {
            auto_router.set_whitelisted_regions(whitelisted_regions);
        }
        if !forced_servers.is_empty() {
            auto_router.set_forced_servers(forced_servers);
        }

        // Spawn background task for async ipinfo.io region lookups
        if auto_routing_enabled {
            let (lookup_tx, mut lookup_rx) =
                tokio::sync::mpsc::unbounded_channel::<std::net::Ipv4Addr>();
            auto_router.set_lookup_channel(lookup_tx);

            let router_for_lookup = Arc::clone(&auto_router);
            let state_for_lookup = Arc::clone(&self.state);
            tokio::spawn(async move {
                while let Some(ip) = lookup_rx.recv().await {
                    match crate::geolocation::lookup_game_server_region(ip).await {
                        Some((region, location)) => {
                            log::info!(
                                "Auto-routing: {} resolved to {} ({})",
                                ip,
                                location,
                                region.display_name()
                            );
                            let old_region = router_for_lookup.current_region();

                            // Step 1: Resolve the best relay server for this region (same
                            // selection logic as manual region connect).
                            if let Some((selected_region, selected_addr)) =
                                router_for_lookup.get_best_server_for_region(&region)
                            {
                                // Step 2: Commit the switch
                                if let Some((new_addr, new_region)) = router_for_lookup
                                    .commit_switch(region, selected_region, selected_addr)
                                {
                                    log::info!(
                                        "Auto-routing: SWITCHING relay {} -> {} (addr: {})",
                                        old_region,
                                        new_region,
                                        new_addr
                                    );
                                    relay_for_lookup.switch_relay(new_addr);
                                    // Keep UI state in sync (shows the actual server id and endpoint).
                                    {
                                        let mut state = state_for_lookup.lock().await;
                                        if let ConnectionState::Connected {
                                            ref mut server_region,
                                            ref mut server_endpoint,
                                            ..
                                        } = *state
                                        {
                                            *server_region = new_region.clone();
                                            *server_endpoint = new_addr.to_string();
                                        }
                                    }
                                    // Send burst of keepalives to new relay to:
                                    // 1. Establish session on new relay ASAP
                                    // 2. Punch through NAT/firewall quickly (3 packets at 50ms intervals)
                                    if let Err(e) = relay_for_lookup.send_keepalive_burst() {
                                        log::warn!(
                                            "Auto-routing: Failed to send keepalive burst to new relay: {}",
                                            e
                                        );
                                    }
                                    log::info!(
                                        "Auto-routing: Relay addr is now {}",
                                        relay_for_lookup.relay_addr()
                                    );
                                    crate::notification::show_relay_switch(
                                        &old_region,
                                        &new_region,
                                        &location,
                                    );
                                }
                            } else {
                                log::info!(
                                    "Auto-routing: No switch needed (already on best region for {})",
                                    location
                                );
                            }
                            // Release held packets — lookup is done, relay is now correct
                            router_for_lookup.clear_pending_lookup(ip);
                        }
                        None => {
                            log::warn!(
                                "Auto-routing: ipinfo.io lookup failed for {}, releasing packets on current relay",
                                ip
                            );
                            // Release packets even on failure — better to route through
                            // wrong relay than hold packets forever
                            router_for_lookup.clear_pending_lookup(ip);
                        }
                    }
                }
                log::debug!("Auto-routing: Lookup task exiting (channel closed)");
            });
            log::info!("V3: Auto-routing lookup task spawned");
        }

        driver.set_auto_router(Arc::clone(&auto_router));
        self.auto_router = Some(Arc::clone(&auto_router));
        log::info!(
            "V3: Auto-router initialized for region {} (enabled: {})",
            config.region,
            auto_routing_enabled
        );

        // Configure split tunnel driver
        // tunnel_interface_luid = 0 (no Wintun), tunnel_ip = internet_ip (no NAT needed for UDP relay)
        let split_config = SplitTunnelConfig::new(
            tunnel_apps.clone(),
            internet_ip.to_string(), // Use internet IP as "tunnel IP" (no NAT rewriting)
            internet_ip.to_string(),
            0, // No Wintun LUID needed for UDP relay
        );

        driver.configure(split_config).map_err(|e| {
            let _ = driver.close();
            VpnError::SplitTunnelSetupFailed(format!("Failed to configure V3 split tunnel: {}", e))
        })?;

        // CACHE WARMUP: Do an immediate refresh to populate process snapshot
        // This handles the case where Roblox is ALREADY running when the user connects.
        // Without this, the snapshot is empty until the first periodic refresh (up to 2s),
        // and all traffic would rely on speculative IP matching which misses STUN/voice.
        if let Err(e) = driver.refresh_exclusions() {
            log::warn!("V3: Initial cache warmup failed: {}", e);
        } else {
            log::info!("V3: Initial cache warmup completed - process snapshot populated");
        }

        let running = driver.get_running_tunnel_apps();
        if !running.is_empty() {
            log::info!("V3: Currently tunneling: {:?}", running);
        }

        let driver = Arc::new(Mutex::new(driver));
        self.split_tunnel = Some(Arc::clone(&driver));

        // Start ETW process watcher for instant game detection
        let watch_list: std::collections::HashSet<String> =
            tunnel_apps.iter().map(|s| s.to_lowercase()).collect();

        let etw_receiver: Option<Receiver<ProcessStartEvent>> =
            match ProcessWatcher::start(watch_list) {
                Ok(watcher) => {
                    log::info!("V3: ETW process watcher started");
                    let receiver = watcher.receiver().clone();
                    self.etw_watcher = Some(watcher);
                    Some(receiver)
                }
                Err(e) => {
                    log::warn!(
                        "V3: ETW process watcher failed (continuing with polling): {}",
                        e
                    );
                    None
                }
            };

        // Bridge ETW (crossbeam) receiver into a tokio channel so the async monitor can
        // `select!` without repeatedly spawning blocking tasks.
        let mut etw_tokio_rx: Option<tokio::sync::mpsc::UnboundedReceiver<ProcessStartEvent>> =
            None;
        if let Some(receiver) = etw_receiver {
            let (tx, rx) = tokio::sync::mpsc::unbounded_channel::<ProcessStartEvent>();
            match std::thread::Builder::new()
                .name("v3-etw-forwarder".to_string())
                .spawn(move || {
                    while let Ok(event) = receiver.recv() {
                        if tx.send(event).is_err() {
                            break;
                        }
                    }
                    log::debug!("V3 ETW: Forwarder thread exiting");
                }) {
                Ok(_handle) => {
                    etw_tokio_rx = Some(rx);
                }
                Err(e) => {
                    log::warn!(
                        "V3: Failed to spawn ETW forwarder thread (continuing with polling): {}",
                        e
                    );
                }
            }
        }

        // Start process monitor (event-driven ETW + periodic refresh)
        self.process_monitor_stop.store(false, Ordering::SeqCst);
        let stop_flag = Arc::clone(&self.process_monitor_stop);
        let state_handle = Arc::clone(&self.state);
        let auto_router_for_monitor = self.auto_router.clone();

        tokio::spawn(async move {
            log::info!("V3: Process monitor started");
            // Match previous behavior: first periodic refresh occurs after the interval.
            let first_tick =
                tokio::time::Instant::now() + Duration::from_millis(REFRESH_INTERVAL_MS);
            let mut refresh_tick =
                tokio::time::interval_at(first_tick, Duration::from_millis(REFRESH_INTERVAL_MS));
            let mut stop_tick = tokio::time::interval(Duration::from_millis(100));
            let mut etw_rx = etw_tokio_rx;

            loop {
                if stop_flag.load(Ordering::SeqCst) {
                    break;
                }
                tokio::select! {
                    // ETW event-driven path
                    event = async {
                        match etw_rx.as_mut() {
                            Some(rx) => rx.recv().await,
                            None => std::future::pending::<Option<ProcessStartEvent>>().await,
                        }
                    } => {
                        match event {
                            Some(first_event) => {
                                let mut etw_events_received = false;
                                let mut blocked_paths: Vec<String> = Vec::new();

                                // Process the first event (if any) and drain remaining queued events.
                                let mut pending_events: Vec<ProcessStartEvent> = Vec::new();
                                pending_events.push(first_event);
                                if let Some(ref mut rx) = etw_rx {
                                    while let Ok(event) = rx.try_recv() {
                                        pending_events.push(event);
                                    }
                                }

                                for event in pending_events {
                                    log::info!(
                                        "V3 ETW: Detected {} (PID: {}) - blocking and registering",
                                        event.name,
                                        event.pid
                                    );

                                    // STEP 1: IMMEDIATELY block the process with WFP filter
                                    // This prevents ANY packets (including STUN) from escaping before we're ready
                                    if !event.image_path.is_empty() {
                                        if let Err(e) = super::wfp_block::block_process_by_path(&event.image_path) {
                                            log::warn!(
                                                "V3: WFP block failed for {}: {} (using speculative tunneling)",
                                                event.name,
                                                e
                                            );
                                        } else {
                                            blocked_paths.push(event.image_path.clone());
                                        }
                                    }

                                    // STEP 2: Register with the driver's process cache (also wakes cache refresher)
                                    let driver_guard = driver.lock().await;
                                    driver_guard.register_process_immediate(event.pid, event.name.clone());
                                    drop(driver_guard);
                                    etw_events_received = true;
                                }

                                // CRITICAL: If we received ETW events, IMMEDIATELY refresh connection tables
                                // before releasing the WFP block, to guarantee first-packet tunneling.
                                if etw_events_received {
                                    let mut driver_guard = driver.lock().await;
                                    let refresh_ok = driver_guard.refresh_exclusions().is_ok();
                                    let running_names = driver_guard.get_running_tunnel_apps();
                                    drop(driver_guard);

                                    if refresh_ok {
                                        log::info!("V3 ETW: Immediate connection table refresh completed");
                                    } else {
                                        log::warn!("V3: Immediate refresh after ETW failed");
                                    }

                                    // Short sleep to allow process to initialize sockets, then refresh again
                                    tokio::time::sleep(Duration::from_millis(2)).await;
                                    let mut driver_guard = driver.lock().await;
                                    let _ = driver_guard.refresh_exclusions();
                                    drop(driver_guard);

                                    // Update UI state promptly when games start/stop
                                    let mut state = state_handle.lock().await;
                                    if let ConnectionState::Connected { ref mut tunneled_processes, .. } = *state {
                                        if *tunneled_processes != running_names {
                                            if !running_names.is_empty() && tunneled_processes.is_empty() {
                                                log::info!("V3: Game detected, relaying: {:?}", running_names);
                                            } else if running_names.is_empty() && !tunneled_processes.is_empty() {
                                                log::info!("V3: All games exited");
                                            }
                                            *tunneled_processes = running_names;
                                        }
                                    }
                                    drop(state);

                                    // STEP 3: Remove WFP block filters - packets now flow through VPN relay
                                    for path in blocked_paths {
                                        if let Err(e) = super::wfp_block::unblock_process_by_path(&path) {
                                            log::warn!("V3: WFP unblock failed for {}: {}", path, e);
                                        }
                                    }
                                }
                            }
                            None => {
                                // ETW channel closed (watcher stopped or failed). Fall back to polling only.
                                etw_rx = None;
                                log::warn!("V3: ETW process watcher channel closed (falling back to polling)");
                            }
                        }
                    }

                    // Periodic refresh path
                    _ = refresh_tick.tick() => {
                        let mut driver_guard = driver.lock().await;
                        match driver_guard.refresh_exclusions() {
                            Ok(_) => {
                                let running_names = driver_guard.get_running_tunnel_apps();
                                drop(driver_guard);

                                let mut state = state_handle.lock().await;
                                if let ConnectionState::Connected { ref mut tunneled_processes, .. } = *state {
                                    if *tunneled_processes != running_names {
                                        if !running_names.is_empty() && tunneled_processes.is_empty() {
                                            log::info!("V3: Game detected, relaying: {:?}", running_names);
                                        } else if running_names.is_empty() && !tunneled_processes.is_empty() {
                                            log::info!("V3: All games exited");
                                        }
                                        *tunneled_processes = running_names;
                                    }
                                }
                            }
                            Err(e) => {
                                log::warn!("V3: Exclusion refresh error: {}", e);
                            }
                        }

                        // Sync auto-routing state to connection state
                        if let Some(ref auto_router) = auto_router_for_monitor {
                            let current_auto_region = auto_router.current_region();
                            let mut state = state_handle.lock().await;
                            if let ConnectionState::Connected { ref mut server_region, .. } = *state {
                                if *server_region != current_auto_region && !current_auto_region.is_empty() {
                                    log::info!(
                                        "Auto-routing: Syncing UI state to region '{}'",
                                        current_auto_region
                                    );
                                    *server_region = current_auto_region;
                                }
                            }
                        }
                    }

                    // Wake periodically to check stop_flag promptly without spawning tasks.
                    _ = stop_tick.tick() => {}
                }
            }

            log::info!("V3: Process monitor stopped");
        });

        log::info!("V3 split tunnel configured - game traffic relayed via UDP");
        Ok(running)
    }

    pub async fn disconnect(&mut self) -> VpnResult<()> {
        log::info!("Disconnecting VPN");
        self.set_state(ConnectionState::Disconnecting).await;
        self.cleanup().await;
        self.set_state(ConnectionState::Disconnected).await;
        log::info!("VPN disconnected");
        Ok(())
    }

    async fn cleanup(&mut self) {
        // Stop process monitor
        self.process_monitor_stop.store(true, Ordering::SeqCst);

        // Stop ETW watcher (cleans up ETW session)
        if let Some(mut watcher) = self.etw_watcher.take() {
            log::info!("Stopping ETW process watcher...");
            watcher.stop();
        }

        // Cleanup WFP block filters
        super::wfp_block::cleanup();

        // Reset auto-router
        if let Some(ref auto_router) = self.auto_router {
            auto_router.reset();
        }
        self.auto_router = None;

        // Clear split tunnel
        if let Some(ref driver) = self.split_tunnel {
            let mut guard = driver.lock().await;
            if let Err(e) = guard.close() {
                log::warn!("Error closing split tunnel: {}", e);
            }
        }
        self.split_tunnel = None;

        self.config = None;
    }

    pub fn config(&self) -> Option<&VpnConfig> {
        self.config.as_ref()
    }

    /// Switch relay server without disconnecting (Auto Routing).
    ///
    /// This atomically swaps the relay address used by all packet workers.
    /// The split tunnel (ndisapi), process cache, and all worker threads
    /// stay running. Only the relay destination changes.
    ///
    /// NOTE: Currently unused - auto-routing switches happen directly in worker
    /// threads via relay.switch_relay(). This method is kept for future GUI-initiated
    /// manual server switching, as it correctly updates ConnectionState.
    ///
    /// Returns Ok(()) if the switch was successful.
    pub async fn switch_server(
        &self,
        new_relay_addr: std::net::SocketAddr,
        new_region: &str,
    ) -> VpnResult<()> {
        // Must be connected
        {
            let state = self.state.lock().await;
            if !state.is_connected() {
                return Err(VpnError::Connection(
                    "Not connected - cannot switch server".to_string(),
                ));
            }
        }

        // Switch the relay via the split tunnel driver
        let switched = if let Some(ref st) = self.split_tunnel {
            match st.try_lock() {
                Ok(driver) => driver.switch_relay_addr(new_relay_addr),
                Err(_) => {
                    return Err(VpnError::Connection(
                        "Split tunnel locked - try again".to_string(),
                    ));
                }
            }
        } else {
            return Err(VpnError::Connection("No split tunnel active".to_string()));
        };

        if !switched {
            return Err(VpnError::Connection(
                "Failed to switch relay address".to_string(),
            ));
        }

        // Update connection state with new server info
        {
            let mut state = self.state.lock().await;
            if let ConnectionState::Connected {
                ref mut server_region,
                ref mut server_endpoint,
                ..
            } = *state
            {
                *server_region = new_region.to_string();
                *server_endpoint = new_relay_addr.to_string();
            }
        }

        log::info!(
            "Auto-routing: Switched relay to {} ({})",
            new_relay_addr,
            new_region
        );

        Ok(())
    }

    /// Get the current relay address for auto-routing comparison
    pub fn current_relay_addr(&self) -> Option<std::net::SocketAddr> {
        self.split_tunnel.as_ref().and_then(|st| {
            st.try_lock()
                .ok()
                .and_then(|driver| driver.current_relay_addr())
        })
    }

    pub fn is_split_tunnel_active(&self) -> bool {
        self.split_tunnel.is_some()
    }

    pub async fn add_tunnel_app(&mut self, exe_name: &str) -> VpnResult<()> {
        if let Some(ref driver) = self.split_tunnel {
            let mut guard = driver.lock().await;
            if let Some(config) = guard.config.as_mut() {
                config.tunnel_apps.insert(exe_name.to_lowercase());
            }
            guard.refresh_exclusions()?;
            Ok(())
        } else {
            Err(VpnError::SplitTunnel("Split tunnel not active".to_string()))
        }
    }

    pub async fn remove_tunnel_app(&mut self, exe_name: &str) -> VpnResult<()> {
        if let Some(ref driver) = self.split_tunnel {
            let mut guard = driver.lock().await;
            if let Some(config) = guard.config.as_mut() {
                config.tunnel_apps.remove(&exe_name.to_lowercase());
            }
            guard.refresh_exclusions()?;
            Ok(())
        } else {
            Err(VpnError::SplitTunnel("Split tunnel not active".to_string()))
        }
    }

    // Legacy compatibility
    pub async fn add_split_tunnel_app(&mut self, exe_path: &str) -> VpnResult<()> {
        self.add_tunnel_app(exe_path).await
    }

    pub async fn remove_split_tunnel_app(&mut self, exe_path: &str) -> VpnResult<()> {
        self.remove_tunnel_app(exe_path).await
    }
}

impl Default for VpnConnection {
    fn default() -> Self {
        Self::new()
    }
}

impl Drop for VpnConnection {
    fn drop(&mut self) {
        self.process_monitor_stop.store(true, Ordering::SeqCst);

        // Stop ETW watcher
        if let Some(mut watcher) = self.etw_watcher.take() {
            watcher.stop();
        }

        if let Some(ref driver) = self.split_tunnel {
            if let Ok(mut guard) = driver.try_lock() {
                let _ = guard.close();
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_is_disconnected() {
        let state = ConnectionState::default();
        assert_eq!(state, ConnectionState::Disconnected);
    }

    #[test]
    fn test_is_connected_true_for_connected() {
        let state = ConnectionState::Connected {
            since: Instant::now(),
            server_region: "us-east".to_string(),
            server_endpoint: "1.2.3.4:51820".to_string(),
            assigned_ip: "10.0.0.2".to_string(),
            split_tunnel_active: true,
            tunneled_processes: vec!["RobloxPlayerBeta.exe".to_string()],
        };
        assert!(state.is_connected());
    }

    #[test]
    fn test_is_connected_false_for_other_states() {
        assert!(!ConnectionState::Disconnected.is_connected());
        assert!(!ConnectionState::FetchingConfig.is_connected());
        assert!(!ConnectionState::CreatingAdapter.is_connected());
        assert!(!ConnectionState::Connecting.is_connected());
        assert!(!ConnectionState::ConfiguringSplitTunnel.is_connected());
        assert!(!ConnectionState::ConfiguringRoutes.is_connected());
        assert!(!ConnectionState::Disconnecting.is_connected());
        assert!(!ConnectionState::Error("err".to_string()).is_connected());
    }

    #[test]
    fn test_is_connecting_true_for_connecting_states() {
        assert!(ConnectionState::FetchingConfig.is_connecting());
        assert!(ConnectionState::CreatingAdapter.is_connecting());
        assert!(ConnectionState::Connecting.is_connecting());
        assert!(ConnectionState::ConfiguringSplitTunnel.is_connecting());
        assert!(ConnectionState::ConfiguringRoutes.is_connecting());
    }

    #[test]
    fn test_is_connecting_false_for_non_connecting_states() {
        assert!(!ConnectionState::Disconnected.is_connecting());
        assert!(!ConnectionState::Disconnecting.is_connecting());
        assert!(!ConnectionState::Error("err".to_string()).is_connecting());

        let connected = ConnectionState::Connected {
            since: Instant::now(),
            server_region: "eu-west".to_string(),
            server_endpoint: "5.6.7.8:51820".to_string(),
            assigned_ip: "10.0.0.3".to_string(),
            split_tunnel_active: false,
            tunneled_processes: vec![],
        };
        assert!(!connected.is_connecting());
    }

    #[test]
    fn test_is_error() {
        assert!(ConnectionState::Error("something broke".to_string()).is_error());
        assert!(!ConnectionState::Disconnected.is_error());
        assert!(!ConnectionState::Connecting.is_error());
    }

    #[test]
    fn test_error_message_some_for_error() {
        let state = ConnectionState::Error("timeout".to_string());
        assert_eq!(state.error_message(), Some("timeout"));
    }

    #[test]
    fn test_error_message_none_for_other_states() {
        assert_eq!(ConnectionState::Disconnected.error_message(), None);
        assert_eq!(ConnectionState::FetchingConfig.error_message(), None);
        assert_eq!(ConnectionState::Connecting.error_message(), None);
        assert_eq!(ConnectionState::Disconnecting.error_message(), None);

        let connected = ConnectionState::Connected {
            since: Instant::now(),
            server_region: "us-west".to_string(),
            server_endpoint: "1.2.3.4:51820".to_string(),
            assigned_ip: "10.0.0.2".to_string(),
            split_tunnel_active: false,
            tunneled_processes: vec![],
        };
        assert_eq!(connected.error_message(), None);
    }

    #[test]
    fn test_status_text_all_variants() {
        assert_eq!(ConnectionState::Disconnected.status_text(), "Disconnected");
        assert_eq!(
            ConnectionState::FetchingConfig.status_text(),
            "Resolving relay endpoint..."
        );
        assert_eq!(
            ConnectionState::CreatingAdapter.status_text(),
            "Creating network adapter..."
        );
        assert_eq!(
            ConnectionState::Connecting.status_text(),
            "Connecting to server..."
        );
        assert_eq!(
            ConnectionState::ConfiguringSplitTunnel.status_text(),
            "Configuring split tunnel..."
        );
        assert_eq!(
            ConnectionState::ConfiguringRoutes.status_text(),
            "Setting up routes..."
        );
        assert_eq!(
            ConnectionState::Disconnecting.status_text(),
            "Disconnecting..."
        );
        assert_eq!(
            ConnectionState::Error("x".to_string()).status_text(),
            "Error"
        );

        let connected = ConnectionState::Connected {
            since: Instant::now(),
            server_region: "us-east".to_string(),
            server_endpoint: "1.2.3.4:51820".to_string(),
            assigned_ip: "10.0.0.2".to_string(),
            split_tunnel_active: true,
            tunneled_processes: vec![],
        };
        assert_eq!(connected.status_text(), "Connected");
    }

    #[test]
    fn test_vpn_connection_new_starts_disconnected() {
        let conn = VpnConnection::new();
        // VpnConnection::new() creates Disconnected state
        // We can verify via state_handle by trying to lock it
        let state = conn.state_handle();
        let guard = state.try_lock().unwrap();
        assert_eq!(*guard, ConnectionState::Disconnected);
    }

    #[test]
    fn test_vpn_connection_default_is_new() {
        let conn = VpnConnection::default();
        let state = conn.state_handle();
        let guard = state.try_lock().unwrap();
        assert_eq!(*guard, ConnectionState::Disconnected);
    }

    #[test]
    fn test_vpn_connection_no_config_initially() {
        let conn = VpnConnection::new();
        assert!(conn.config().is_none());
        assert!(conn.get_config_id().is_none());
    }

    #[test]
    fn test_vpn_connection_split_tunnel_not_active_initially() {
        let conn = VpnConnection::new();
        assert!(!conn.is_split_tunnel_active());
    }

    fn parse_addr(addr: &str) -> SocketAddr {
        addr.parse().expect("invalid test socket addr")
    }

    #[test]
    fn test_resolve_relay_server_exact_match() {
        let available_servers = vec![
            (
                "germany".to_string(),
                parse_addr("10.0.0.1:51821"),
                Some(30),
            ),
            (
                "germany-01".to_string(),
                parse_addr("10.0.0.2:51821"),
                Some(8),
            ),
        ];

        let resolved = resolve_relay_server_for_region("germany", &available_servers, None);
        assert_eq!(
            resolved,
            Some(("germany".to_string(), parse_addr("10.0.0.1:51821")))
        );
    }

    #[test]
    fn test_resolve_relay_server_prefix_fallback() {
        let available_servers = vec![
            (
                "germany-01".to_string(),
                parse_addr("10.0.0.11:51821"),
                Some(8),
            ),
            (
                "germany-03".to_string(),
                parse_addr("10.0.0.13:51821"),
                Some(12),
            ),
        ];

        let resolved = resolve_relay_server_for_region("germany", &available_servers, None);
        assert_eq!(
            resolved,
            Some(("germany-01".to_string(), parse_addr("10.0.0.11:51821")))
        );
    }

    #[test]
    fn test_resolve_relay_server_returns_none_when_unavailable() {
        let available_servers = vec![
            (
                "tokyo-01".to_string(),
                parse_addr("10.0.1.1:51821"),
                Some(20),
            ),
            (
                "paris-03".to_string(),
                parse_addr("10.0.1.2:51821"),
                Some(14),
            ),
        ];

        let resolved = resolve_relay_server_for_region("germany", &available_servers, None);
        assert_eq!(resolved, None);
    }

    #[test]
    fn test_resolve_relay_server_prefers_lowest_known_latency() {
        let available_servers = vec![
            ("paris-02".to_string(), parse_addr("10.0.2.2:51821"), None),
            (
                "paris-01".to_string(),
                parse_addr("10.0.2.1:51821"),
                Some(17),
            ),
            (
                "paris-03".to_string(),
                parse_addr("10.0.2.3:51821"),
                Some(9),
            ),
        ];

        let resolved = resolve_relay_server_for_region("paris", &available_servers, None);
        assert_eq!(
            resolved,
            Some(("paris-03".to_string(), parse_addr("10.0.2.3:51821")))
        );
    }

    #[test]
    fn test_resolve_relay_server_forced_server_used() {
        let available_servers = vec![
            (
                "germany-01".to_string(),
                parse_addr("10.0.0.1:51821"),
                Some(5),
            ),
            (
                "germany-02".to_string(),
                parse_addr("10.0.0.2:51821"),
                Some(20),
            ),
            (
                "germany-03".to_string(),
                parse_addr("10.0.0.3:51821"),
                Some(50),
            ),
        ];

        // Force germany-03 even though it has the worst latency
        let resolved =
            resolve_relay_server_for_region("germany", &available_servers, Some("germany-03"));
        assert_eq!(
            resolved,
            Some(("germany-03".to_string(), parse_addr("10.0.0.3:51821")))
        );
    }

    #[test]
    fn test_resolve_relay_server_forced_server_not_found_falls_back() {
        let available_servers = vec![
            (
                "germany-01".to_string(),
                parse_addr("10.0.0.1:51821"),
                Some(5),
            ),
            (
                "germany-02".to_string(),
                parse_addr("10.0.0.2:51821"),
                Some(20),
            ),
        ];

        // Force a server that doesn't exist — should fall back to best latency
        let resolved =
            resolve_relay_server_for_region("germany", &available_servers, Some("germany-99"));
        assert_eq!(
            resolved,
            Some(("germany-01".to_string(), parse_addr("10.0.0.1:51821")))
        );
    }

    #[test]
    fn test_resolve_relay_server_us_region_prefix_matching() {
        // Regression test: US servers use "us-east-nj", "us-west-la" naming.
        // The gaming region IDs are "us-east", "us-west", "us-central".
        // Prefix matching "us-east-" must find "us-east-nj".
        let available_servers = vec![
            (
                "us-east-nj".to_string(),
                parse_addr("108.61.7.6:51821"),
                Some(30),
            ),
            (
                "us-west-la".to_string(),
                parse_addr("45.63.55.139:51821"),
                Some(45),
            ),
            (
                "us-central-dallas".to_string(),
                parse_addr("108.61.205.6:51821"),
                Some(40),
            ),
        ];

        // "us-east" has no exact match -> falls to prefix "us-east-" -> finds "us-east-nj"
        let resolved = resolve_relay_server_for_region("us-east", &available_servers, None);
        assert_eq!(
            resolved,
            Some(("us-east-nj".to_string(), parse_addr("108.61.7.6:51821")))
        );

        let resolved = resolve_relay_server_for_region("us-west", &available_servers, None);
        assert_eq!(
            resolved,
            Some(("us-west-la".to_string(), parse_addr("45.63.55.139:51821")))
        );

        let resolved = resolve_relay_server_for_region("us-central", &available_servers, None);
        assert_eq!(
            resolved,
            Some((
                "us-central-dallas".to_string(),
                parse_addr("108.61.205.6:51821")
            ))
        );
    }

    #[test]
    fn test_resolve_relay_server_legacy_america_finds_nothing() {
        // Documents the bug: "america" as a region name finds no servers
        // in the current API naming scheme.
        let available_servers = vec![
            (
                "us-east-nj".to_string(),
                parse_addr("108.61.7.6:51821"),
                Some(30),
            ),
            (
                "us-west-la".to_string(),
                parse_addr("45.63.55.139:51821"),
                Some(45),
            ),
        ];

        let resolved = resolve_relay_server_for_region("america", &available_servers, None);
        assert_eq!(resolved, None);
    }
}
