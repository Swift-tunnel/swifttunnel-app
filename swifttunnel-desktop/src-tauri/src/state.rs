use std::collections::HashMap;
use std::sync::Arc;

use parking_lot::{Mutex, RwLock};
use swifttunnel_core::auth::AuthManager;
use swifttunnel_core::discord_rpc::DiscordManager;
use swifttunnel_core::network_booster::NetworkBooster;
use swifttunnel_core::performance_monitor::PerformanceMonitor;
use swifttunnel_core::roblox_optimizer::RobloxOptimizer;
use swifttunnel_core::settings::AppSettings;
use swifttunnel_core::system_optimizer::SystemOptimizer;
use swifttunnel_core::vpn::SplitTunnelDriver;
use swifttunnel_core::vpn::connection::{ConnectionState, VpnConnection};
use swifttunnel_core::vpn::servers::DynamicServerList;
use tokio::sync::watch;

/// Shared application state managed by Tauri
///
/// Uses `tokio::sync::Mutex` for managers with async methods (auth, vpn)
/// and `parking_lot::Mutex` for synchronous-only managers.
///
/// `vpn_state_handle` and `split_tunnel_handle` are clones of the inner
/// state pointers held by `VpnConnection`. Read-only command handlers
/// (`vpn_get_state`, `vpn_get_throughput`, etc.) hit these directly so
/// they don't have to acquire the heavy `vpn_connection` mutex while a
/// connect or disconnect is in flight — that's what used to freeze the UI.
///
/// `vpn_state_handle` is a `watch::Receiver` so every state transition
/// published by `VpnConnection` (including in-place mutations from the
/// background monitor and auto-routing's `switch_server`) is observable.
/// A startup bridge task subscribes once and forwards every change to the
/// `VPN_STATE_CHANGED` Tauri event, so the UI can't get stuck displaying
/// a state the backend has silently left behind.
pub struct AppState {
    pub auth_manager: Arc<tokio::sync::Mutex<AuthManager>>,
    pub vpn_connection: Arc<tokio::sync::Mutex<VpnConnection>>,
    pub vpn_state_handle: watch::Receiver<ConnectionState>,
    pub split_tunnel_handle: Arc<RwLock<Option<Arc<tokio::sync::Mutex<SplitTunnelDriver>>>>>,
    pub server_list: Arc<Mutex<DynamicServerList>>,
    /// Map of region_id -> (server_name, latency_ms)
    pub region_latencies: Arc<Mutex<HashMap<String, (String, u32)>>>,
    pub settings: Arc<Mutex<AppSettings>>,
    pub performance_monitor: Arc<Mutex<PerformanceMonitor>>,
    pub system_optimizer: Arc<Mutex<SystemOptimizer>>,
    pub roblox_optimizer: Arc<Mutex<RobloxOptimizer>>,
    pub network_booster: Arc<Mutex<NetworkBooster>>,
    pub discord_manager: Arc<Mutex<DiscordManager>>,
    pub runtime: Arc<tokio::runtime::Runtime>,
    pub launched_from_startup: bool,
}

impl AppState {
    pub fn new(
        runtime: Arc<tokio::runtime::Runtime>,
        launched_from_startup: bool,
    ) -> Result<Self, String> {
        let auth_manager = AuthManager::new().map_err(|e| format!("Failed to init auth: {}", e))?;
        let mut settings = swifttunnel_core::settings::load_settings();
        let roblox_optimizer = RobloxOptimizer::new();

        if let Err(e) = roblox_optimizer.repair_global_basic_settings_permissions() {
            log::warn!("Failed to repair Roblox settings permissions: {}", e);
        }

        if let Ok(current) = roblox_optimizer.read_current_settings() {
            settings.config.roblox_settings.window_fullscreen = current.fullscreen;
            if let Some((width, height)) = current.window_size {
                settings.config.roblox_settings.window_width = width;
                settings.config.roblox_settings.window_height = height;
            }
        }

        let enable_discord_rpc = settings.enable_discord_rpc;

        let vpn_connection = VpnConnection::new();
        let vpn_state_handle = vpn_connection.state_handle();

        Ok(Self {
            auth_manager: Arc::new(tokio::sync::Mutex::new(auth_manager)),
            vpn_connection: Arc::new(tokio::sync::Mutex::new(vpn_connection)),
            vpn_state_handle,
            split_tunnel_handle: Arc::new(RwLock::new(None)),
            server_list: Arc::new(Mutex::new(DynamicServerList::new_empty())),
            region_latencies: Arc::new(Mutex::new(HashMap::new())),
            settings: Arc::new(Mutex::new(settings)),
            performance_monitor: Arc::new(Mutex::new(PerformanceMonitor::new())),
            system_optimizer: Arc::new(Mutex::new(SystemOptimizer::new())),
            roblox_optimizer: Arc::new(Mutex::new(roblox_optimizer)),
            network_booster: Arc::new(Mutex::new(NetworkBooster::new())),
            discord_manager: Arc::new(Mutex::new(DiscordManager::new(enable_discord_rpc))),
            runtime,
            launched_from_startup,
        })
    }
}
