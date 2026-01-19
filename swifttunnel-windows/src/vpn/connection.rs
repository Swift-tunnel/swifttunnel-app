//! VPN Connection Manager
//!
//! Manages the lifecycle of VPN connections, coordinating:
//! - Configuration fetching
//! - Wintun adapter creation
//! - WireGuard tunnel establishment
//! - Split tunneling setup
//! - Connection state tracking
//! - Process monitoring for split tunneling

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};
use tokio::sync::Mutex;
use crate::auth::types::VpnConfig;
use super::adapter::WintunAdapter;
use super::tunnel::{WireguardTunnel, TunnelStats};
use super::split_tunnel::{SplitTunnelDriver, SplitTunnelConfig};
use super::config::{fetch_vpn_config, parse_ip_cidr};
use super::{VpnError, VpnResult};

/// VPN connection state
#[derive(Debug, Clone, PartialEq)]
pub enum ConnectionState {
    /// Not connected
    Disconnected,
    /// Fetching configuration from API
    FetchingConfig,
    /// Creating network adapter
    CreatingAdapter,
    /// Establishing WireGuard tunnel
    Connecting,
    /// Configuring split tunneling
    ConfiguringSplitTunnel,
    /// Connected and running
    Connected {
        since: Instant,
        server_region: String,
        server_endpoint: String,
        assigned_ip: String,
        split_tunnel_active: bool,
        /// Names of processes currently being tunneled (e.g., ["RobloxPlayerBeta.exe"])
        tunneled_processes: Vec<String>,
    },
    /// Disconnecting
    Disconnecting,
    /// Error state
    Error(String),
}

impl ConnectionState {
    /// Check if connected
    pub fn is_connected(&self) -> bool {
        matches!(self, ConnectionState::Connected { .. })
    }

    /// Check if in a connecting state (any state between Disconnected and Connected)
    pub fn is_connecting(&self) -> bool {
        matches!(
            self,
            ConnectionState::FetchingConfig
                | ConnectionState::CreatingAdapter
                | ConnectionState::Connecting
                | ConnectionState::ConfiguringSplitTunnel
        )
    }

    /// Check if in error state
    pub fn is_error(&self) -> bool {
        matches!(self, ConnectionState::Error(_))
    }

    /// Get error message if in error state
    pub fn error_message(&self) -> Option<&str> {
        match self {
            ConnectionState::Error(msg) => Some(msg),
            _ => None,
        }
    }

    /// Get status text for UI display
    pub fn status_text(&self) -> &'static str {
        match self {
            ConnectionState::Disconnected => "Disconnected",
            ConnectionState::FetchingConfig => "Fetching configuration...",
            ConnectionState::CreatingAdapter => "Creating network adapter...",
            ConnectionState::Connecting => "Connecting to server...",
            ConnectionState::ConfiguringSplitTunnel => "Configuring split tunnel...",
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
    config: Option<VpnConfig>,
    /// Flag to stop the process monitor task
    process_monitor_stop: Arc<AtomicBool>,
}

impl VpnConnection {
    /// Create a new VPN connection manager
    pub fn new() -> Self {
        Self {
            state: Arc::new(Mutex::new(ConnectionState::Disconnected)),
            adapter: None,
            tunnel: None,
            split_tunnel: None,
            config: None,
            process_monitor_stop: Arc::new(AtomicBool::new(false)),
        }
    }

    /// Get current connection state
    pub async fn state(&self) -> ConnectionState {
        self.state.lock().await.clone()
    }

    /// Get a clone of the state Arc for sharing
    pub fn state_handle(&self) -> Arc<Mutex<ConnectionState>> {
        Arc::clone(&self.state)
    }

    /// Set connection state
    async fn set_state(&self, state: ConnectionState) {
        log::info!("Connection state: {:?}", state);
        *self.state.lock().await = state;
    }

    /// Connect to VPN server
    ///
    /// # Arguments
    /// * `access_token` - Bearer token for API authentication
    /// * `region` - Server region to connect to
    /// * `split_tunnel_apps` - Applications to route through VPN (empty = all traffic)
    pub async fn connect(
        &mut self,
        access_token: &str,
        region: &str,
        split_tunnel_apps: Vec<String>,
    ) -> VpnResult<()> {
        // Check if already connected or connecting
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

        // Step 1: Fetch configuration
        self.set_state(ConnectionState::FetchingConfig).await;
        let config: VpnConfig = match fetch_vpn_config(access_token, region).await {
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

        // Set DNS servers
        if !config.dns.is_empty() {
            if let Err(e) = adapter.set_dns(&config.dns) {
                log::warn!("Failed to set DNS: {}", e);
            }
        }

        // Set MTU
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

        // Start tunnel in background task
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

        // Step 4: Configure split tunneling (if apps specified and driver available)
        self.set_state(ConnectionState::ConfiguringSplitTunnel).await;
        let (split_tunnel_active, tunneled_processes) = if !split_tunnel_apps.is_empty() {
            self.setup_split_tunnel(&config, &adapter, split_tunnel_apps).await
        } else {
            log::info!("No split tunnel apps specified, routing all traffic through VPN");
            (false, Vec::new())
        };

        // Step 5: Mark as connected
        self.set_state(ConnectionState::Connected {
            since: Instant::now(),
            server_region: config.region.clone(),
            server_endpoint: config.endpoint.clone(),
            assigned_ip: config.assigned_ip.clone(),
            split_tunnel_active,
            tunneled_processes,
        })
        .await;

        log::info!("VPN connected successfully");
        Ok(())
    }

    /// Setup split tunneling
    async fn setup_split_tunnel(
        &mut self,
        config: &VpnConfig,
        adapter: &WintunAdapter,
        apps: Vec<String>,
    ) -> (bool, Vec<String>) {
        // Check if driver is available
        if !SplitTunnelDriver::is_available() {
            log::warn!("Split tunnel driver not available, routing all traffic through VPN");
            return (false, Vec::new());
        }

        let mut driver = SplitTunnelDriver::new();

        // Open driver
        if let Err(e) = driver.open() {
            log::warn!("Failed to open split tunnel driver: {}", e);
            return (false, Vec::new());
        }

        // Configure
        let split_config = SplitTunnelConfig {
            include_apps: apps,
            tunnel_ip: config.assigned_ip.clone(),
            tunnel_interface_luid: adapter.get_luid(),
        };

        if let Err(e) = driver.configure(split_config) {
            log::warn!("Failed to configure split tunnel: {}", e);
            return (false, Vec::new());
        }

        // Get initial running processes
        let running = driver.get_running_target_names();
        if !running.is_empty() {
            log::info!("Currently tunneling processes: {:?}", running);
        }

        let driver = Arc::new(Mutex::new(driver));
        self.split_tunnel = Some(Arc::clone(&driver));

        // Start background process monitor
        self.process_monitor_stop.store(false, Ordering::SeqCst);
        let stop_flag = Arc::clone(&self.process_monitor_stop);
        let state_handle = Arc::clone(&self.state);

        tokio::spawn(async move {
            log::info!("Process monitor started - watching for Roblox");

            loop {
                // Check if we should stop
                if stop_flag.load(Ordering::SeqCst) {
                    log::info!("Process monitor stopping");
                    break;
                }

                // Wait before checking (1 second interval)
                tokio::time::sleep(Duration::from_secs(1)).await;

                // Check if still stopping
                if stop_flag.load(Ordering::SeqCst) {
                    break;
                }

                // Refresh processes
                let mut driver_guard = driver.lock().await;
                match driver_guard.refresh_processes() {
                    Ok(_has_processes) => {
                        // Update state with current tunneled processes
                        let running_names = driver_guard.get_running_target_names();
                        // Drop driver lock before acquiring state lock to avoid potential deadlock
                        drop(driver_guard);

                        // Update the connection state's tunneled_processes list
                        let mut state = state_handle.lock().await;
                        if let ConnectionState::Connected {
                            ref mut tunneled_processes,
                            ..
                        } = *state {
                            if *tunneled_processes != running_names {
                                if running_names.is_empty() && !tunneled_processes.is_empty() {
                                    log::info!("All target processes exited");
                                } else if !running_names.is_empty() && tunneled_processes.is_empty() {
                                    log::info!("Roblox detected and being tunneled: {:?}", running_names);
                                }
                                *tunneled_processes = running_names;
                            }
                        }
                    }
                    Err(e) => {
                        log::warn!("Error refreshing processes: {}", e);
                    }
                }
            }
        });

        log::info!("Split tunneling configured successfully");
        (true, running)
    }

    /// Disconnect from VPN
    pub async fn disconnect(&mut self) -> VpnResult<()> {
        log::info!("Disconnecting VPN");
        self.set_state(ConnectionState::Disconnecting).await;

        self.cleanup().await;

        self.set_state(ConnectionState::Disconnected).await;
        log::info!("VPN disconnected");
        Ok(())
    }

    /// Cleanup resources
    async fn cleanup(&mut self) {
        // Stop the process monitor task
        self.process_monitor_stop.store(true, Ordering::SeqCst);

        // Stop tunnel
        if let Some(ref tunnel) = self.tunnel {
            tunnel.stop();
        }
        self.tunnel = None;

        // Clear split tunnel
        if let Some(ref driver) = self.split_tunnel {
            let mut driver_guard = driver.lock().await;
            if let Err(e) = driver_guard.close() {
                log::warn!("Error closing split tunnel driver: {}", e);
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

    /// Get tunnel statistics
    pub fn stats(&self) -> Option<TunnelStats> {
        self.tunnel.as_ref().map(|t| t.stats())
    }

    /// Get current config
    pub fn config(&self) -> Option<&VpnConfig> {
        self.config.as_ref()
    }

    /// Check if split tunneling is active
    pub fn is_split_tunnel_active(&self) -> bool {
        self.split_tunnel.is_some()
    }

    /// Add an app to split tunnel (while connected)
    pub async fn add_split_tunnel_app(&mut self, exe_path: &str) -> VpnResult<()> {
        if let Some(ref driver) = self.split_tunnel {
            let mut driver_guard = driver.lock().await;
            driver_guard.add_app(exe_path)?;
            Ok(())
        } else {
            Err(VpnError::SplitTunnel("Split tunnel not active".to_string()))
        }
    }

    /// Remove an app from split tunnel (while connected)
    pub async fn remove_split_tunnel_app(&mut self, exe_path: &str) -> VpnResult<()> {
        if let Some(ref driver) = self.split_tunnel {
            let mut driver_guard = driver.lock().await;
            driver_guard.remove_app(exe_path)?;
            Ok(())
        } else {
            Err(VpnError::SplitTunnel("Split tunnel not active".to_string()))
        }
    }
}

impl Default for VpnConnection {
    fn default() -> Self {
        Self::new()
    }
}

impl Drop for VpnConnection {
    fn drop(&mut self) {
        // Signal process monitor to stop
        self.process_monitor_stop.store(true, Ordering::SeqCst);

        // Synchronous cleanup
        if let Some(ref tunnel) = self.tunnel {
            tunnel.stop();
        }
        if let Some(ref driver) = self.split_tunnel {
            // Use try_lock since we can't await in Drop
            if let Ok(mut driver_guard) = driver.try_lock() {
                let _ = driver_guard.close();
            } else {
                log::warn!("Could not acquire split tunnel lock during drop");
            }
        }
        if let Some(ref adapter) = self.adapter {
            adapter.shutdown();
        }
    }
}
