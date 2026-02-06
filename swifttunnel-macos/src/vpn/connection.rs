//! VPN Connection Manager (macOS)
//!
//! Manages the lifecycle of VPN connections on macOS, coordinating:
//! - Configuration fetching
//! - utun adapter creation
//! - WireGuard tunnel establishment
//! - Split tunneling via BPF/pf (process-based per-app routing)
//! - Route management
//! - Connection state tracking

use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};
use tokio::sync::Mutex;
use crate::auth::types::VpnConfig;
use super::adapter::UtunAdapter;
use super::tunnel::WireguardTunnel;
use super::routes::RouteManager;
use super::config::{fetch_vpn_config, parse_ip_cidr};
use super::{VpnError, VpnResult};
use super::split_tunnel::MacSplitTunnel;
use super::packet_interceptor::ThroughputStats;

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
    adapter: Option<Arc<UtunAdapter>>,
    tunnel: Option<Arc<WireguardTunnel>>,
    route_manager: Option<RouteManager>,
    config: Option<VpnConfig>,
    process_monitor_stop: Arc<AtomicBool>,
    split_tunnel: Option<Arc<std::sync::Mutex<MacSplitTunnel>>>,
}

impl VpnConnection {
    pub fn new() -> Self {
        Self {
            state: Arc::new(Mutex::new(ConnectionState::Disconnected)),
            adapter: None,
            tunnel: None,
            route_manager: None,
            config: None,
            process_monitor_stop: Arc::new(AtomicBool::new(false)),
            split_tunnel: None,
        }
    }

    pub async fn state(&self) -> ConnectionState {
        self.state.lock().await.clone()
    }

    pub fn state_handle(&self) -> Arc<Mutex<ConnectionState>> {
        Arc::clone(&self.state)
    }

    /// Get throughput statistics from the split tunnel
    pub fn get_throughput_stats(&self) -> Option<ThroughputStats> {
        self.split_tunnel.as_ref().and_then(|st| {
            st.try_lock().ok().map(|driver| driver.get_throughput_stats())
        })
    }

    /// Get split tunnel diagnostic info for UI display
    pub fn get_split_tunnel_diagnostics(&self) -> Option<(Option<String>, bool, u64, u64)> {
        // Return basic diagnostics: (adapter_name, has_default_route, tunneled, bypassed)
        self.split_tunnel.as_ref().and_then(|st| {
            st.try_lock().ok().map(|_driver| {
                (self.adapter.as_ref().map(|a| a.interface_name().to_string()), false, 0u64, 0u64)
            })
        })
    }

    /// Get the current config ID (for latency updates)
    pub fn get_config_id(&self) -> Option<String> {
        self.config.as_ref().map(|c| c.id.clone())
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
    /// * `routing_mode` - V1 (process-based), V2 (hybrid), or V3 (unencrypted relay)
    pub async fn connect(
        &mut self,
        access_token: &str,
        region: &str,
        tunnel_apps: Vec<String>,
        routing_mode: crate::settings::RoutingMode,
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

        log::info!("Starting VPN connection to region: {} (mode: {:?})", region, routing_mode);
        log::info!("Apps to tunnel: {:?}", tunnel_apps);

        // V3 mode: Skip utun/WireGuard entirely - just use UDP relay
        if routing_mode == crate::settings::RoutingMode::V3 {
            return self.connect_v3(access_token, region, tunnel_apps, custom_relay_server).await;
        }

        // V1/V2: Full WireGuard tunnel with encryption

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

        // Step 2: Create utun adapter
        self.set_state(ConnectionState::CreatingAdapter).await;
        let (ip, cidr) = match parse_ip_cidr(&config.assigned_ip) {
            Ok(parsed) => parsed,
            Err(e) => {
                self.set_state(ConnectionState::Error(e.to_string())).await;
                return Err(e);
            }
        };

        let adapter = match UtunAdapter::create(ip, cidr) {
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

        // Step 3.5: Stop tunnel tasks before split tunnel setup
        // Split tunnel workers will take over all packet handling on macOS.
        if let Some(ref tunnel) = self.tunnel {
            log::info!("Stopping tunnel tasks for split tunnel handoff...");
            tunnel.stop();
            tokio::time::sleep(Duration::from_millis(100)).await;
            log::info!("Tunnel tasks stopped, proceeding with split tunnel setup");
        }

        // Step 4: Configure split tunneling (process-based via BPF/pf on macOS)
        self.set_state(ConnectionState::ConfiguringSplitTunnel).await;
        let (tunneled_processes, split_tunnel_active) = if !tunnel_apps.is_empty() {
            // TODO: MacSplitTunnel will be implemented by Task #3
            // For now, log that split tunnel would be configured
            log::info!("Split tunnel apps: {:?} (BPF/pf implementation pending)", tunnel_apps);
            log::warn!("macOS split tunnel not yet implemented - traffic will use full tunnel");
            (Vec::new(), false)
        } else {
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
            split_tunnel_active,
            tunneled_processes,
        }).await;

        log::info!("VPN connected successfully");
        Ok(())
    }

    /// V3 connection - lightweight UDP relay without utun/WireGuard
    ///
    /// This is ~500ms faster than V1/V2 because it skips:
    /// - utun adapter creation
    /// - WireGuard tunnel initialization
    /// - Route configuration
    ///
    /// Just sets up BPF/pf packet interception with UDP relay forwarding.
    async fn connect_v3(
        &mut self,
        access_token: &str,
        region: &str,
        tunnel_apps: Vec<String>,
        custom_relay_server: Option<String>,
    ) -> VpnResult<()> {
        log::info!("========================================");
        log::info!("V3 MODE: Lightweight UDP Relay");
        log::info!("========================================");
        log::info!("  - No utun adapter");
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

        // Step 2: Skip utun - go directly to split tunnel
        // V3 doesn't need a virtual adapter
        self.set_state(ConnectionState::ConfiguringSplitTunnel).await;

        let (tunneled_processes, split_tunnel_active) = if !tunnel_apps.is_empty() {
            // Resolve relay address
            let relay_addr: SocketAddr = if let Some(ref custom) = custom_relay_server {
                log::info!("V3: Using CUSTOM relay server: {}", custom);
                match tokio::net::lookup_host(custom).await {
                    Ok(mut addrs) => {
                        match addrs.next() {
                            Some(addr) => {
                                log::info!("V3: Resolved custom relay to {}", addr);
                                addr
                            }
                            None => {
                                self.set_state(ConnectionState::Error(
                                    format!("DNS resolution returned no addresses for '{}'", custom)
                                )).await;
                                return Err(VpnError::SplitTunnelSetupFailed(
                                    format!("DNS resolution returned no addresses for '{}'", custom)
                                ));
                            }
                        }
                    }
                    Err(e) => {
                        self.set_state(ConnectionState::Error(
                            format!("Failed to resolve relay: {}", e)
                        )).await;
                        return Err(VpnError::SplitTunnelSetupFailed(
                            format!("Failed to resolve custom relay '{}': {}", custom, e)
                        ));
                    }
                }
            } else {
                let vpn_ip = config.endpoint.split(':').next().unwrap_or(&config.endpoint);
                format!("{}:51821", vpn_ip)
                    .parse()
                    .map_err(|e| VpnError::SplitTunnelSetupFailed(
                        format!("Invalid VPN server IP for relay: {}", e)
                    ))?
            };

            log::info!("V3: Relay address resolved to {}", relay_addr);

            // TODO: MacSplitTunnel V3 setup will be implemented by Task #3
            // For now, create the UDP relay to verify connectivity
            log::info!("V3: Split tunnel apps: {:?} (BPF/pf implementation pending)", tunnel_apps);
            log::warn!("macOS V3 split tunnel not yet implemented");
            (Vec::new(), false)
        } else {
            log::warn!("No tunnel apps specified");
            (Vec::new(), false)
        };

        // Step 3: Skip routes - V3 doesn't need them

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

    /// Setup routes through VPN interface
    ///
    /// Only adds VPN server route - split tunnel (via BPF/pf) handles app routing.
    async fn setup_routes(
        &mut self,
        config: &VpnConfig,
        adapter: &UtunAdapter,
    ) -> VpnResult<()> {
        // Parse VPN server IP
        let endpoint = &config.endpoint;
        let server_ip: std::net::Ipv4Addr = endpoint
            .split(':')
            .next()
            .ok_or_else(|| VpnError::Route("Invalid endpoint format".to_string()))?
            .parse()
            .map_err(|e| VpnError::Route(format!("Invalid server IP: {}", e)))?;

        let utun_name = adapter.interface_name().to_string();

        log::info!("Setting up VPN routes (server: {}, interface: {})", server_ip, utun_name);

        let mut route_manager = RouteManager::new(server_ip, utun_name);

        if let Err(e) = route_manager.apply_routes() {
            log::error!("Failed to apply VPN routes: {}", e);
            return Err(e);
        }

        self.route_manager = Some(route_manager);
        log::info!("VPN routes configured successfully");
        Ok(())
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

        // TODO: Cleanup split tunnel (will be added by Task #3)
        // if let Some(ref split_tunnel) = self.split_tunnel {
        //     let mut guard = split_tunnel.lock().await;
        //     if let Err(e) = guard.close() {
        //         log::warn!("Error closing split tunnel: {}", e);
        //     }
        // }
        // self.split_tunnel = None;

        // Shutdown adapter
        if let Some(ref adapter) = self.adapter {
            adapter.shutdown();
        }
        self.adapter = None;

        self.config = None;
    }

    pub fn config(&self) -> Option<&VpnConfig> {
        self.config.as_ref()
    }

    pub async fn add_tunnel_app(&mut self, _exe_name: &str) -> VpnResult<()> {
        // TODO: Will be implemented when MacSplitTunnel is ready (Task #3)
        Err(VpnError::SplitTunnel("macOS split tunnel not yet implemented".to_string()))
    }

    pub async fn remove_tunnel_app(&mut self, _exe_name: &str) -> VpnResult<()> {
        // TODO: Will be implemented when MacSplitTunnel is ready (Task #3)
        Err(VpnError::SplitTunnel("macOS split tunnel not yet implemented".to_string()))
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
        if let Some(ref adapter) = self.adapter {
            adapter.shutdown();
        }
    }
}
