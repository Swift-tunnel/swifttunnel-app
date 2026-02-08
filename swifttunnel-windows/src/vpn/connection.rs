//! VPN Connection Manager
//!
//! Manages the lifecycle of VPN connections, coordinating:
//! - Configuration fetching
//! - Split tunneling via ndisapi (process-based per-app routing)
//! - UDP relay for game traffic forwarding
//! - Connection state tracking

use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};
use tokio::sync::Mutex;
use crate::auth::types::VpnConfig;
use crate::dns::CloudflareDns;
use super::split_tunnel::{SplitTunnelDriver, SplitTunnelConfig};
use super::parallel_interceptor::ThroughputStats;
use super::process_watcher::{ProcessWatcher, ProcessStartEvent};
use super::routes::get_internet_interface_ip;
use super::config::fetch_vpn_config;
use super::{VpnError, VpnResult};
use crossbeam_channel::Receiver;

/// Refresh interval for process exclusion scanning (ms)
/// Lower = faster detection of new processes, slightly higher CPU
/// 50ms ensures game traffic is tunneled almost instantly on launch
const REFRESH_INTERVAL_MS: u64 = 50;

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
            ConnectionState::FetchingConfig => "Fetching configuration...",
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
}

impl VpnConnection {
    pub fn new() -> Self {
        Self {
            state: Arc::new(Mutex::new(ConnectionState::Disconnected)),
            split_tunnel: None,
            config: None,
            process_monitor_stop: Arc::new(AtomicBool::new(false)),
            etw_watcher: None,
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
            st.try_lock().ok().and_then(|driver| driver.get_throughput_stats())
        })
    }

    /// Get split tunnel diagnostic info for UI display
    ///
    /// Returns: (adapter_name, has_default_route, packets_tunneled, packets_bypassed)
    /// Uses try_lock() to avoid blocking the GUI thread.
    pub fn get_split_tunnel_diagnostics(&self) -> Option<(Option<String>, bool, u64, u64)> {
        self.split_tunnel.as_ref().and_then(|st| {
            st.try_lock().ok().and_then(|driver| driver.get_diagnostics())
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
        self.split_tunnel.as_ref().and_then(|st| {
            st.try_lock().ok().map(|driver| driver.get_detected_game_servers())
        }).unwrap_or_default()
    }

    /// Clear detected game servers (call on disconnect)
    pub fn clear_detected_game_servers(&self) {
        if let Some(st) = self.split_tunnel.as_ref() {
            if let Ok(driver) = st.try_lock() {
                driver.clear_detected_game_servers();
            }
        }
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
    /// * `access_token` - Bearer token for API authentication
    /// * `region` - Server region to connect to
    /// * `tunnel_apps` - Apps that SHOULD use VPN (games). Everything else bypasses.
    pub async fn connect(
        &mut self,
        access_token: &str,
        region: &str,
        tunnel_apps: Vec<String>,
        custom_relay_server: Option<String>,
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

        // Step 1: Fetch configuration (we still need server endpoint)
        self.set_state(ConnectionState::FetchingConfig).await;
        let config = match fetch_vpn_config(access_token, region).await {
            Ok(c) => c,
            Err(e) => {
                self.set_state(ConnectionState::Error(e.to_string())).await;
                return Err(e);
            }
        };

        log::info!("V3: Server endpoint: {}", config.endpoint);
        self.config = Some(config.clone());

        // Initialize WFP block filter engine (for instant process blocking)
        if let Err(e) = super::wfp_block::init() {
            log::warn!("WFP block filter init failed (will use speculative tunneling): {}", e);
        }

        // Step 2: Skip Wintun - go directly to split tunnel
        // V3 doesn't need a virtual adapter
        self.set_state(ConnectionState::ConfiguringSplitTunnel).await;

        let (tunneled_processes, split_tunnel_active) = if !tunnel_apps.is_empty() {
            match self.setup_split_tunnel(&config, tunnel_apps.clone(), custom_relay_server).await {
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
                    ))).await;
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
        }).await;

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
    ) -> VpnResult<Vec<String>> {
        log::info!("Setting up V3 split tunnel (no Wintun)...");

        // Get internet interface IP for NAT rewriting on inbound packets
        let internet_ip = get_internet_interface_ip().map_err(|e| {
            VpnError::SplitTunnelSetupFailed(format!(
                "Failed to get internet interface IP: {}",
                e
            ))
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
                return Err(VpnError::SplitTunnelSetupFailed(
                    format!("Custom relay '{}' must include a port (e.g. host:51821)", custom)
                ));
            };

            // Try parsing as IP first to skip DNS for raw IPs
            if let Ok(ip) = host.parse::<std::net::IpAddr>() {
                let addr = SocketAddr::new(ip, port);
                log::info!("V3: Custom relay is IP address: {}", addr);
                addr
            } else {
                // Resolve hostname via Cloudflare DNS
                let dns = CloudflareDns::shared();
                match dns.resolve_host(host, port).await {
                    Ok(addrs) => {
                        let addr = addrs[0];
                        log::info!("V3: Resolved custom relay to {}", addr);
                        addr
                    }
                    Err(e) => {
                        let _ = driver.close();
                        return Err(VpnError::SplitTunnelSetupFailed(
                            format!("Failed to resolve custom relay '{}': {}", custom, e)
                        ));
                    }
                }
            }
        } else {
            // No custom relay = auto mode (use VPN server IP with default port 51821)
            let vpn_ip = config.endpoint.split(':').next().unwrap_or(&config.endpoint);
            format!("{}:51821", vpn_ip)
                .parse()
                .map_err(|e| VpnError::SplitTunnelSetupFailed(
                    format!("Invalid VPN server IP for relay: {}", e)
                ))?
        };

        log::info!("V3: Creating UDP relay to {}", relay_addr);

        let relay = match super::udp_relay::UdpRelay::new(relay_addr) {
            Ok(r) => std::sync::Arc::new(r),
            Err(e) => {
                let _ = driver.close();
                return Err(VpnError::SplitTunnelSetupFailed(
                    format!("Failed to create V3 relay: {}", e)
                ));
            }
        };

        driver.set_relay_context(relay);
        log::info!("V3: UDP relay context set");

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
        let watch_list: std::collections::HashSet<String> = tunnel_apps.iter()
            .map(|s| s.to_lowercase())
            .collect();

        let etw_receiver: Option<Receiver<ProcessStartEvent>> = match ProcessWatcher::start(watch_list) {
            Ok(watcher) => {
                log::info!("V3: ETW process watcher started");
                let receiver = watcher.receiver().clone();
                self.etw_watcher = Some(watcher);
                Some(receiver)
            }
            Err(e) => {
                log::warn!("V3: ETW process watcher failed (continuing with polling): {}", e);
                None
            }
        };

        // Start process monitor (same as V1/V2)
        self.process_monitor_stop.store(false, Ordering::SeqCst);
        let stop_flag = Arc::clone(&self.process_monitor_stop);
        let state_handle = Arc::clone(&self.state);

        tokio::spawn(async move {
            log::info!("V3: Process monitor started");

            let mut last_refresh = std::time::Instant::now();
            const ETW_POLL_INTERVAL_MS: u64 = 5;

            loop {
                if stop_flag.load(Ordering::SeqCst) {
                    break;
                }

                // Poll ETW events (instant detection) - runs every 5ms
                // This handles processes that started since last iteration
                let mut etw_events_received = false;
                let mut blocked_paths: Vec<String> = Vec::new();

                if let Some(ref receiver) = etw_receiver {
                    while let Ok(event) = receiver.try_recv() {
                        log::info!(
                            "V3 ETW: Detected {} (PID: {}) - blocking and registering",
                            event.name, event.pid
                        );

                        // STEP 1: IMMEDIATELY block the process with WFP filter
                        // This prevents ANY packets (including STUN) from escaping before we're ready
                        if !event.image_path.is_empty() {
                            if let Err(e) = super::wfp_block::block_process_by_path(&event.image_path) {
                                log::warn!("V3: WFP block failed for {}: {} (using speculative tunneling)", event.name, e);
                            } else {
                                blocked_paths.push(event.image_path.clone());
                            }
                        }

                        // STEP 2: Register with the driver's process cache
                        let driver_guard = driver.lock().await;
                        driver_guard.register_process_immediate(event.pid, event.name.clone());
                        drop(driver_guard);
                        etw_events_received = true;
                    }
                }

                // CRITICAL: If we received ETW events, IMMEDIATELY refresh connection tables
                // This ensures first-packet tunneling (including STUN on port 3478)
                // by populating connection→PID mappings before the WFP block is released
                if etw_events_received {
                    let mut driver_guard = driver.lock().await;
                    if let Err(e) = driver_guard.refresh_exclusions() {
                        log::warn!("V3: Immediate refresh after ETW failed: {}", e);
                    } else {
                        log::info!("V3 ETW: Immediate connection table refresh completed");
                    }
                    drop(driver_guard);

                    // Short sleep to allow process to initialize sockets, then refresh again
                    tokio::time::sleep(Duration::from_millis(2)).await;
                    let mut driver_guard = driver.lock().await;
                    let _ = driver_guard.refresh_exclusions();
                    drop(driver_guard);

                    // STEP 3: Remove WFP block filters - packets now flow through VPN relay
                    for path in blocked_paths {
                        if let Err(e) = super::wfp_block::unblock_process_by_path(&path) {
                            log::warn!("V3: WFP unblock failed for {}: {}", path, e);
                        }
                    }

                    // Reset refresh timer since we just did a full refresh
                    last_refresh = std::time::Instant::now();
                }

                tokio::time::sleep(Duration::from_millis(ETW_POLL_INTERVAL_MS)).await;

                if stop_flag.load(Ordering::SeqCst) {
                    break;
                }

                // Periodic refresh
                if last_refresh.elapsed().as_millis() < REFRESH_INTERVAL_MS as u128 {
                    continue;
                }
                last_refresh = std::time::Instant::now();

                let mut driver_guard = driver.lock().await;
                match driver_guard.refresh_exclusions() {
                    Ok(_) => {
                        let running_names = driver_guard.get_running_tunnel_apps();
                        drop(driver_guard);

                        let mut state = state_handle.lock().await;
                        if let ConnectionState::Connected {
                            ref mut tunneled_processes,
                            ..
                        } = *state {
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
