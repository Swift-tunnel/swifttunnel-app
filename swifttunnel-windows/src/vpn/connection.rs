//! VPN Connection Manager
//!
//! Manages the lifecycle of VPN connections, coordinating:
//! - Configuration fetching
//! - Wintun adapter creation
//! - WireGuard tunnel establishment
//! - Split tunneling setup (exclude-all-except mode)
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
use super::wfp::{WfpEngine, setup_wfp_for_split_tunnel};
use super::routes::{RouteManager, get_interface_index, get_internet_interface_ip};
use super::config::{fetch_vpn_config, parse_ip_cidr};
use super::{VpnError, VpnResult};

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
    wfp_engine: Option<WfpEngine>,
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
            wfp_engine: None,
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
    pub async fn connect(
        &mut self,
        access_token: &str,
        region: &str,
        tunnel_apps: Vec<String>,
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

        // Step 4: Configure split tunneling (BEFORE routes)
        // CRITICAL: Split tunnel MUST succeed - we fail the connection if it doesn't
        // This prevents the user from thinking they're protected when they're not
        self.set_state(ConnectionState::ConfiguringSplitTunnel).await;
        let (split_tunnel_active, tunneled_processes) = if !tunnel_apps.is_empty() {
            match self.setup_split_tunnel(&config, &adapter, tunnel_apps).await {
                Ok(processes) => {
                    log::info!("Split tunnel setup succeeded");
                    (true, processes)
                }
                Err(e) => {
                    log::error!("Split tunnel setup FAILED: {}", e);
                    log::error!("Aborting connection - cannot proceed without split tunnel");
                    // Clean up and fail the connection
                    self.cleanup().await;
                    self.set_state(ConnectionState::Error(format!(
                        "Split tunnel failed: {}",
                        e
                    ))).await;
                    return Err(e);
                }
            }
        } else {
            log::info!("No tunnel apps specified, all traffic will use VPN");
            (false, Vec::new())
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
            split_tunnel_active,
            tunneled_processes,
        }).await;

        log::info!("VPN connected successfully");
        Ok(())
    }

    /// Setup routes through VPN interface
    async fn setup_routes(&mut self, config: &VpnConfig, adapter: &WintunAdapter) -> VpnResult<()> {
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
                // Try to get LUID-based index as fallback
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

    /// Setup split tunneling with exclude-all-except logic
    ///
    /// CRITICAL: This function now FAILS the connection if split tunnel setup fails.
    /// The user expects split tunneling - proceeding without it could leak traffic.
    ///
    /// Initialization order (IMPORTANT - fixes WFP error 0x80320027):
    /// 1. Check driver availability
    /// 2. Open driver
    /// 3. Initialize driver (registers WFP callouts)
    /// 4. Setup WFP filters (now callouts exist, so filters can reference them)
    /// 5. Configure driver (register processes, IPs, set config)
    async fn setup_split_tunnel(
        &mut self,
        config: &VpnConfig,
        adapter: &WintunAdapter,
        tunnel_apps: Vec<String>,
    ) -> VpnResult<Vec<String>> {
        // Step 1: Check if driver is available (MSI installer must have set it up)
        if !SplitTunnelDriver::check_driver_available() {
            return Err(VpnError::SplitTunnelNotAvailable);
        }

        let interface_luid = adapter.get_luid();
        log::info!("Setting up split tunnel (LUID: {})...", interface_luid);

        // Step 2: Open driver FIRST
        let mut driver = SplitTunnelDriver::new();
        driver.open().map_err(|e| {
            VpnError::SplitTunnelSetupFailed(format!("Failed to open driver: {}", e))
        })?;
        log::info!("Split tunnel driver opened");

        // Step 3: Initialize driver - this registers WFP callouts
        // MUST happen BEFORE WFP filter setup
        driver.initialize().map_err(|e| {
            VpnError::SplitTunnelSetupFailed(format!("Failed to initialize driver: {}", e))
        })?;
        log::info!("Split tunnel driver initialized (WFP callouts registered)");

        // Step 4: Setup WFP AFTER driver initialization
        // Now the callouts exist, so filters can reference them
        log::info!("Setting up WFP filters for split tunnel...");
        match setup_wfp_for_split_tunnel(interface_luid) {
            Ok(engine) => {
                log::info!("WFP setup complete");
                self.wfp_engine = Some(engine);
            }
            Err(e) => {
                // WFP setup is critical - fail the connection
                let _ = driver.close();
                return Err(VpnError::WfpSetupFailed(e.to_string()));
            }
        }

        // Step 5: Get internet interface IP for socket redirection
        // This tells the driver where to redirect excluded app traffic
        let internet_ip = get_internet_interface_ip().map_err(|e| {
            let _ = driver.close();
            self.wfp_engine = None;
            VpnError::SplitTunnelSetupFailed(format!(
                "Failed to get internet interface IP: {}",
                e
            ))
        })?;
        log::info!("Internet interface IP for split tunnel: {}", internet_ip);

        // Step 6: Configure driver (register processes, IPs, set config)
        let split_config = SplitTunnelConfig::new(
            tunnel_apps,
            config.assigned_ip.clone(),
            internet_ip.to_string(),
            interface_luid,
        );

        if let Err(e) = driver.configure(split_config) {
            // Configuration failed - clean up and fail
            self.wfp_engine = None;
            let _ = driver.close();
            return Err(VpnError::SplitTunnelSetupFailed(format!(
                "Failed to configure split tunnel: {}",
                e
            )));
        }

        let running = driver.get_running_tunnel_apps();
        if !running.is_empty() {
            log::info!("Currently tunneling: {:?}", running);
        }

        let driver = Arc::new(Mutex::new(driver));
        self.split_tunnel = Some(Arc::clone(&driver));

        // Start fast refresh loop (50ms for instant game detection)
        self.process_monitor_stop.store(false, Ordering::SeqCst);
        let stop_flag = Arc::clone(&self.process_monitor_stop);
        let state_handle = Arc::clone(&self.state);

        tokio::spawn(async move {
            log::info!("Process monitor started ({}ms interval)", REFRESH_INTERVAL_MS);

            loop {
                if stop_flag.load(Ordering::SeqCst) {
                    break;
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

        // Clean up WFP
        self.wfp_engine = None;

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
