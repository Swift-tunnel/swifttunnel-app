use std::collections::HashMap;
use std::sync::Arc;

use parking_lot::Mutex;
use swifttunnel_core::auth::AuthManager;
use swifttunnel_core::discord_rpc::DiscordManager;
use swifttunnel_core::network_booster::NetworkBooster;
use swifttunnel_core::performance_monitor::PerformanceMonitor;
use swifttunnel_core::roblox_optimizer::RobloxOptimizer;
use swifttunnel_core::settings::AppSettings;
use swifttunnel_core::system_optimizer::SystemOptimizer;
use swifttunnel_core::vpn::connection::VpnConnection;
use swifttunnel_core::vpn::servers::DynamicServerList;

/// Shared application state managed by Tauri
///
/// Uses `tokio::sync::Mutex` for managers with async methods (auth, vpn)
/// and `parking_lot::Mutex` for synchronous-only managers.
pub struct AppState {
    pub auth_manager: Arc<tokio::sync::Mutex<AuthManager>>,
    pub vpn_connection: Arc<tokio::sync::Mutex<VpnConnection>>,
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
}

impl AppState {
    pub fn new(runtime: Arc<tokio::runtime::Runtime>) -> Result<Self, String> {
        let auth_manager = AuthManager::new().map_err(|e| format!("Failed to init auth: {}", e))?;
        let mut settings = swifttunnel_core::settings::load_settings();
        let roblox_optimizer = RobloxOptimizer::new();

        if let Ok(current) = roblox_optimizer.read_current_settings() {
            settings.config.roblox_settings.window_fullscreen = current.fullscreen;
            if let Some((width, height)) = current.window_size {
                settings.config.roblox_settings.window_width = width;
                settings.config.roblox_settings.window_height = height;
            }
        }

        let enable_discord_rpc = settings.enable_discord_rpc;

        Ok(Self {
            auth_manager: Arc::new(tokio::sync::Mutex::new(auth_manager)),
            vpn_connection: Arc::new(tokio::sync::Mutex::new(VpnConnection::new())),
            server_list: Arc::new(Mutex::new(DynamicServerList::new_empty())),
            region_latencies: Arc::new(Mutex::new(HashMap::new())),
            settings: Arc::new(Mutex::new(settings)),
            performance_monitor: Arc::new(Mutex::new(PerformanceMonitor::new())),
            system_optimizer: Arc::new(Mutex::new(SystemOptimizer::new())),
            roblox_optimizer: Arc::new(Mutex::new(roblox_optimizer)),
            network_booster: Arc::new(Mutex::new(NetworkBooster::new())),
            discord_manager: Arc::new(Mutex::new(DiscordManager::new(enable_discord_rpc))),
            runtime,
        })
    }
}
