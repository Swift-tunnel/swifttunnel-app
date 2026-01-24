//! VPN Connection Manager
//!
//! Manages the lifecycle of VPN connections, coordinating:
//! - Configuration fetching
//! - Wintun adapter creation
//! - WireGuard tunnel establishment
//! - Split tunneling via ndisapi (process-based per-app routing)
//! - Route management
//! - Connection state tracking

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};
use tokio::sync::Mutex;
use crate::auth::types::VpnConfig;
use super::adapter::WintunAdapter;
use super::tunnel::{WireguardTunnel, TunnelStats};
use super::split_tunnel::{SplitTunnelDriver, SplitTunnelConfig};
use super::parallel_interceptor::{ThroughputStats, VpnEncryptContext};
use super::process_watcher::{ProcessWatcher, ProcessStartEvent};
use super::routes::{RouteManager, get_interface_index, get_internet_interface_ip};
use super::config::{fetch_vpn_config, parse_ip_cidr};
use super::packet_interceptor::WireguardContext;
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
    adapter: Option<Arc<WintunAdapter>>,
    tunnel: Option<Arc<WireguardTunnel>>,
    split_tunnel: Option<Arc<Mutex<SplitTunnelDriver>>>,
    route_manager: Option<RouteManager>,
    config: Option<VpnConfig>,
    process_monitor_stop: Arc<AtomicBool>,
}

impl VpnConnection {
    pub fn new() -> Self {
        Self {
            state: Arc::new(Mutex::new(ConnectionState::Disconnected)),
            adapter: None,
            tunnel: None,
            split_tunnel: None,
            route_manager: None,
            config: None,
            process_monitor_stop: Arc::new(AtomicBool::new(false)),
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

    /// Connect to VPN server
    ///
    /// # Arguments
    /// * `access_token` - Bearer token for API authentication
    /// * `region` - Server region to connect to
    /// * `tunnel_apps` - Apps that SHOULD use VPN (games). Everything else bypasses.
    /// * `routing_mode` - V1 (process-based) or V2 (hybrid/ExitLag-style)
    pub async fn connect(
        &mut self,
        access_token: &str,
        region: &str,
        tunnel_apps: Vec<String>,
        routing_mode: crate::settings::RoutingMode,
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
        log::info!("Apps to tunnel through VPN: {:?}", tunnel_apps);

        // Step 1: Fetch configuration
        self.set_state(ConnectionState::FetchingConfig).await;
        let config = match fetch_vpn_config(access_token, region).await {
            Ok(c) => c,
            Err(e) => {
                self.set_state(ConnectionState::Error(e.to_string())).await;
                return Err(e);
            }
        };

        log::info!("VPN config received: endpoint={}", config.endpoint);
        self.config = Some(config.clone());

        // Step 2: Create Wintun adapter
        self.set_state(ConnectionState::CreatingAdapter).await;
        let (ip, cidr) = match parse_ip_cidr(&config.assigned_ip) {
            Ok(parsed) => parsed,
            Err(e) => {
                self.set_state(ConnectionState::Error(e.to_string())).await;
                return Err(e);
            }
        };

        let adapter = match WintunAdapter::create(ip, cidr) {
            Ok(a) => Arc::new(a),
            Err(e) => {
                self.set_state(ConnectionState::Error(e.to_string())).await;
                return Err(e);
            }
        };

        // Set DNS and MTU
        if !config.dns.is_empty() {
            if let Err(e) = adapter.set_dns(&config.dns) {
                log::warn!("Failed to set DNS: {}", e);
            }
        }
        if let Err(e) = adapter.set_mtu(super::adapter::DEFAULT_MTU) {
            log::warn!("Failed to set MTU: {}", e);
        }

        self.adapter = Some(Arc::clone(&adapter));

        // Step 3: Create and start WireGuard tunnel
        self.set_state(ConnectionState::Connecting).await;
        let tunnel = match WireguardTunnel::new(config.clone()) {
            Ok(t) => Arc::new(t),
            Err(e) => {
                self.cleanup().await;
                self.set_state(ConnectionState::Error(e.to_string())).await;
                return Err(e);
            }
        };

        // Start tunnel
        let tunnel_clone = Arc::clone(&tunnel);
        let adapter_clone = Arc::clone(&adapter);
        let state_clone = Arc::clone(&self.state);

        tokio::spawn(async move {
            if let Err(e) = tunnel_clone.start(adapter_clone).await {
                log::error!("Tunnel error: {}", e);
                *state_clone.lock().await = ConnectionState::Error(e.to_string());
            }
        });

        self.tunnel = Some(tunnel);

        // Give tunnel a moment to establish
        tokio::time::sleep(Duration::from_millis(500)).await;

        // Step 4: Configure split tunneling (process-based via ndisapi)
        self.set_state(ConnectionState::ConfiguringSplitTunnel).await;
        // Split tunnel is the ONLY mode (like ExitLag) - no full tunnel option
        let (tunneled_processes, split_tunnel_active) = if !tunnel_apps.is_empty() {
            match self.setup_split_tunnel(&config, &adapter, tunnel_apps.clone(), routing_mode).await {
                Ok(processes) => {
                    log::info!("Split tunnel setup succeeded");
                    (processes, true)
                }
                Err(e) => {
                    log::error!("Split tunnel setup FAILED: {}", e);
                    log::error!("Aborting connection - cannot proceed without split tunnel");
                    self.cleanup().await;
                    self.set_state(ConnectionState::Error(format!(
                        "Split tunnel failed: {}",
                        e
                    ))).await;
                    return Err(e);
                }
            }
        } else {
            // No apps to tunnel - this should be blocked by GUI, but handle gracefully
            log::warn!("No tunnel apps specified - connection will work but no traffic will use VPN");
            (Vec::new(), false)
        };

        // Step 5: Setup routes AFTER split tunnel exclusions
        self.set_state(ConnectionState::ConfiguringRoutes).await;
        if let Err(e) = self.setup_routes(&config, &adapter).await {
            log::warn!("Failed to setup routes: {}", e);
            // Continue anyway - split tunnel might still work partially
        }

        // Step 6: Mark as connected
        self.set_state(ConnectionState::Connected {
            since: Instant::now(),
            server_region: config.region.clone(),
            server_endpoint: config.endpoint.clone(),
            assigned_ip: config.assigned_ip.clone(),
            split_tunnel_active,  // True when apps specified, false otherwise
            tunneled_processes,
        }).await;

        log::info!("VPN connected successfully");
        Ok(())
    }

    /// Setup routes through VPN interface
    ///
    /// Only adds VPN server route - split tunnel (via ndisapi) handles app routing.
    async fn setup_routes(
        &mut self,
        config: &VpnConfig,
        _adapter: &WintunAdapter,  // Reserved for future use
    ) -> VpnResult<()> {
        // Parse VPN server IP
        let endpoint = &config.endpoint;
        let server_ip: std::net::Ipv4Addr = endpoint
            .split(':')
            .next()
            .ok_or_else(|| VpnError::Route("Invalid endpoint format".to_string()))?
            .parse()
            .map_err(|e| VpnError::Route(format!("Invalid server IP: {}", e)))?;

        // Get interface index
        let if_index = match get_interface_index("SwiftTunnel") {
            Ok(idx) => idx,
            Err(e) => {
                log::warn!("Could not get interface index: {}", e);
                1 // Default fallback
            }
        };

        log::info!("Setting up VPN routes (server: {}, interface: {})", server_ip, if_index);

        let mut route_manager = RouteManager::new(server_ip, if_index);

        if let Err(e) = route_manager.apply_routes() {
            log::error!("Failed to apply VPN routes: {}", e);
            return Err(e);
        }

        self.route_manager = Some(route_manager);
        log::info!("VPN routes configured successfully");
        Ok(())
    }

    /// Setup split tunneling with ndisapi-based approach
    ///
    /// Simplified initialization (no WFP complexity):
    /// 1. Check driver availability
    /// 2. Open driver
    /// 3. Initialize driver
    /// 4. Set Wintun injection context
    /// 5. Configure with tunnel apps
    async fn setup_split_tunnel(
        &mut self,
        config: &VpnConfig,
        adapter: &WintunAdapter,
        tunnel_apps: Vec<String>,
        routing_mode: crate::settings::RoutingMode,
    ) -> VpnResult<Vec<String>> {
        let interface_luid = adapter.get_luid();
        log::info!("Setting up split tunnel (LUID: {})...", interface_luid);

        // Get internet interface IP for socket redirection
        let internet_ip = get_internet_interface_ip().map_err(|e| {
            VpnError::SplitTunnelSetupFailed(format!(
                "Failed to get internet interface IP: {}",
                e
            ))
        })?;
        log::info!("Internet interface IP for split tunnel: {}", internet_ip);

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
        log::info!("Split tunnel driver opened");

        // Initialize driver
        driver.initialize().map_err(|e| {
            let _ = driver.close();
            VpnError::SplitTunnelSetupFailed(format!("Failed to initialize driver: {}", e))
        })?;
        log::info!("Split tunnel driver initialized");

        // Create WireGuard context for packet injection into Wintun
        // Tunnel app packets will be injected here, then tunnel.rs will encrypt and send to VPN
        let wg_ctx = Arc::new(WireguardContext {
            session: adapter.session(),
            packets_injected: std::sync::atomic::AtomicU64::new(0),
        });
        driver.set_wireguard_context(wg_ctx);
        log::info!("Wintun injection context set for split tunnel");

        // Set up direct encryption context BEFORE configure() since threads start during configure()
        // This allows workers to encrypt packets directly and send via UDP (faster than Wintun injection)
        if let Some(ref tunnel_ref) = self.tunnel {
            if let Some(tunn) = tunnel_ref.get_tunn() {
                let endpoint = tunnel_ref.get_endpoint();
                log::info!("Setting up direct encryption to {} (before configure)", endpoint);

                match std::net::UdpSocket::bind("0.0.0.0:0") {
                    Ok(socket) => {
                        // Increase socket receive buffer for bulk traffic (1MB)
                        // This helps prevent packet loss when the VPN server sends responses in bursts
                        #[cfg(windows)]
                        {
                            use std::os::windows::io::AsRawSocket;
                            use windows::Win32::Networking::WinSock::{setsockopt, SOL_SOCKET, SO_RCVBUF};
                            let raw = socket.as_raw_socket() as usize;
                            let buf_size: i32 = 1024 * 1024; // 1MB
                            let result = unsafe {
                                setsockopt(
                                    windows::Win32::Networking::WinSock::SOCKET(raw),
                                    SOL_SOCKET as i32,
                                    SO_RCVBUF as i32,
                                    Some(std::slice::from_raw_parts(
                                        &buf_size as *const i32 as *const u8,
                                        std::mem::size_of::<i32>(),
                                    )),
                                )
                            };
                            if result == 0 {
                                log::info!("Socket receive buffer set to 1MB for bulk traffic");
                            } else {
                                log::warn!("Failed to set socket receive buffer size");
                            }
                        }

                        // Set socket timeout for inbound receiver loop (100ms to match timer interval)
                        // This allows periodic keepalive checking without blocking forever
                        socket.set_read_timeout(Some(Duration::from_millis(100)))
                            .unwrap_or_else(|e| log::warn!("Failed to set socket read timeout: {}", e));

                        if let Err(e) = socket.connect(endpoint) {
                            log::warn!("Failed to connect encryption socket: {}", e);
                        } else {
                            let ctx = VpnEncryptContext {
                                tunn,
                                socket: Arc::new(socket),
                                server_addr: endpoint,
                            };
                            driver.set_vpn_encrypt_context(ctx);
                            log::info!("Direct encryption enabled for split tunnel (inbound receiver will start with keepalives)");
                        }
                    }
                    Err(e) => {
                        log::warn!("Failed to bind encryption socket: {}", e);
                        log::warn!("Falling back to Wintun injection (no direct encryption)");
                    }
                }
            }
        }

        // Configure driver - this starts worker threads and inbound receiver
        let split_config = SplitTunnelConfig::new(
            tunnel_apps.clone(),
            config.assigned_ip.clone(),
            internet_ip.to_string(),
            interface_luid,
            routing_mode,
        );

        driver.configure(split_config).map_err(|e| {
            let _ = driver.close();
            VpnError::SplitTunnelSetupFailed(format!("Failed to configure split tunnel: {}", e))
        })?;

        let running = driver.get_running_tunnel_apps();
        if !running.is_empty() {
            log::info!("Currently tunneling: {:?}", running);
        }

        let driver = Arc::new(Mutex::new(driver));
        self.split_tunnel = Some(Arc::clone(&driver));

        // Start ETW process watcher for INSTANT process detection
        // This solves Error 279 when launching Roblox from browser:
        // - Browser spawns RobloxPlayerBeta.exe
        // - ETW notifies us within MICROSECONDS
        // - We register the process BEFORE it makes any network calls
        // - First packet is tunneled correctly!
        let watch_list: std::collections::HashSet<String> = tunnel_apps.iter()
            .map(|s| s.to_lowercase())
            .collect();

        let etw_receiver: Option<Receiver<ProcessStartEvent>> = match ProcessWatcher::start(watch_list) {
            Ok(watcher) => {
                log::info!("ETW process watcher started for instant game detection");
                // Leak the watcher to keep it running (will be cleaned up on disconnect)
                // We only need the receiver channel
                let receiver = watcher.receiver().clone();
                std::mem::forget(watcher); // Keep ETW session alive
                Some(receiver)
            }
            Err(e) => {
                // ETW failure is not fatal - we still have 50ms polling as backup
                log::warn!("ETW process watcher failed (continuing with polling): {}", e);
                None
            }
        };

        // Start fast refresh loop (50ms for instant game detection)
        self.process_monitor_stop.store(false, Ordering::SeqCst);
        let stop_flag = Arc::clone(&self.process_monitor_stop);
        let state_handle = Arc::clone(&self.state);

        tokio::spawn(async move {
            log::info!("Process monitor started ({}ms interval + ETW instant detection)", REFRESH_INTERVAL_MS);

            loop {
                if stop_flag.load(Ordering::SeqCst) {
                    break;
                }

                // Poll ETW events FIRST (instant detection)
                // This handles processes that started since last iteration
                if let Some(ref receiver) = etw_receiver {
                    while let Ok(event) = receiver.try_recv() {
                        log::info!(
                            "ETW: Instantly detected {} (PID: {}) - registering for tunneling",
                            event.name, event.pid
                        );

                        // Immediately register with the driver's process cache
                        let driver_guard = driver.lock().await;
                        driver_guard.register_process_immediate(event.pid, event.name.clone());
                        drop(driver_guard);
                    }
                }

                tokio::time::sleep(Duration::from_millis(REFRESH_INTERVAL_MS)).await;

                if stop_flag.load(Ordering::SeqCst) {
                    break;
                }

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
                                    log::info!("Game detected, tunneling: {:?}", running_names);
                                } else if running_names.is_empty() && !tunneled_processes.is_empty() {
                                    log::info!("All games exited");
                                }
                                *tunneled_processes = running_names;
                            }
                        }
                    }
                    Err(e) => {
                        log::warn!("Exclusion refresh error: {}", e);
                    }
                }
            }

            log::info!("Process monitor stopped");
        });

        log::info!("Split tunnel configured successfully - only selected games use VPN");
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

        // Remove routes first
        if let Some(ref mut route_manager) = self.route_manager {
            if let Err(e) = route_manager.remove_routes() {
                log::warn!("Error removing routes: {}", e);
            }
        }
        self.route_manager = None;

        // Stop tunnel
        if let Some(ref tunnel) = self.tunnel {
            tunnel.stop();
        }
        self.tunnel = None;

        // Clear split tunnel
        if let Some(ref driver) = self.split_tunnel {
            let mut guard = driver.lock().await;
            if let Err(e) = guard.close() {
                log::warn!("Error closing split tunnel: {}", e);
            }
        }
        self.split_tunnel = None;

        // Shutdown adapter
        if let Some(ref adapter) = self.adapter {
            adapter.shutdown();
        }
        self.adapter = None;

        self.config = None;
    }

    pub fn stats(&self) -> Option<TunnelStats> {
        self.tunnel.as_ref().map(|t| t.stats())
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

        // Remove routes synchronously
        if let Some(ref mut route_manager) = self.route_manager {
            let _ = route_manager.remove_routes();
        }

        if let Some(ref tunnel) = self.tunnel {
            tunnel.stop();
        }
        if let Some(ref driver) = self.split_tunnel {
            if let Ok(mut guard) = driver.try_lock() {
                let _ = guard.close();
            }
        }
        if let Some(ref adapter) = self.adapter {
            adapter.shutdown();
        }
    }
}
