use std::collections::HashMap;
use std::sync::Arc;

use parking_lot::{Mutex, RwLock};
use swifttunnel_core::auth::AuthManager;
use swifttunnel_core::discord_rpc::DiscordManager;
use swifttunnel_core::fps_monitor::FpsMonitor;
use swifttunnel_core::network_booster::NetworkBooster;
use swifttunnel_core::performance_monitor::PerformanceMonitor;
use swifttunnel_core::roblox_optimizer::RobloxOptimizer;
use swifttunnel_core::settings::AppSettings;
use swifttunnel_core::system_optimizer::SystemOptimizer;
use swifttunnel_core::vpn::SplitTunnelDriver;
use swifttunnel_core::vpn::ThroughputStats;
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
    /// Clone of the interceptor's atomic throughput counters, published on
    /// connect. Reading these never takes the driver mutex, so the UI's
    /// throughput poll can't be starved by a busy driver (`try_lock` misses
    /// used to make the graph read zero on some machines).
    pub throughput_stats: Arc<RwLock<Option<ThroughputStats>>>,
    pub server_list: Arc<Mutex<DynamicServerList>>,
    /// Map of region_id -> (server_name, latency_ms)
    pub region_latencies: Arc<Mutex<HashMap<String, (String, u32)>>>,
    pub settings: Arc<Mutex<AppSettings>>,
    pub performance_monitor: Arc<Mutex<PerformanceMonitor>>,
    /// Anti-cheat-safe in-game FPS via ETW DXGI present counting. Long-lived;
    /// the optimizer points it at the Roblox PID and reads presents/sec.
    pub fps_monitor: Arc<FpsMonitor>,
    pub system_optimizer: Arc<Mutex<SystemOptimizer>>,
    pub roblox_optimizer: Arc<Mutex<RobloxOptimizer>>,
    pub network_booster: Arc<Mutex<NetworkBooster>>,
    pub discord_manager: Arc<Mutex<DiscordManager>>,
    pub runtime: Arc<tokio::runtime::Runtime>,
    pub launched_from_startup: bool,
    /// Flips to `true` once startup crash-recovery (stale adapter/tunnel-mode
    /// reset) finishes in the background. `vpn_connect` waits on it so a fast
    /// click can't start a tunnel mid-reset; everything else ignores it.
    pub startup_recovery_done: watch::Receiver<bool>,
    /// Sender side for the setup background task.
    pub startup_recovery_signal: watch::Sender<bool>,
}

impl AppState {
    pub fn new(
        runtime: Arc<tokio::runtime::Runtime>,
        launched_from_startup: bool,
    ) -> Result<Self, String> {
        // Keep this constructor FAST: it runs inside Tauri's setup hook, and
        // the window cannot even appear until setup returns. Anything slow
        // (network, child processes, ACL repair, process scans) belongs in
        // the background startup task in lib.rs.
        let auth_manager = AuthManager::new().map_err(|e| format!("Failed to init auth: {}", e))?;
        let settings = swifttunnel_core::settings::load_settings();
        let roblox_optimizer = RobloxOptimizer::new();

        let enable_discord_rpc = settings.enable_discord_rpc;

        // The ETW FPS session is demand-driven (its callback fires for every
        // present from every process system-wide) - run it only while the
        // in-game overlay wants FPS. `settings_save` keeps it in sync after
        // toggles.
        let fps_monitor = Arc::new(FpsMonitor::new());
        fps_monitor.set_enabled(settings.config.overlay.enabled);

        let vpn_connection = VpnConnection::new();
        let vpn_state_handle = vpn_connection.state_handle();
        let (startup_recovery_signal, startup_recovery_done) = watch::channel(false);

        Ok(Self {
            auth_manager: Arc::new(tokio::sync::Mutex::new(auth_manager)),
            vpn_connection: Arc::new(tokio::sync::Mutex::new(vpn_connection)),
            vpn_state_handle,
            split_tunnel_handle: Arc::new(RwLock::new(None)),
            throughput_stats: Arc::new(RwLock::new(None)),
            server_list: Arc::new(Mutex::new(DynamicServerList::new_empty())),
            region_latencies: Arc::new(Mutex::new(HashMap::new())),
            settings: Arc::new(Mutex::new(settings)),
            performance_monitor: Arc::new(Mutex::new(PerformanceMonitor::new())),
            fps_monitor,
            system_optimizer: Arc::new(Mutex::new(SystemOptimizer::new())),
            roblox_optimizer: Arc::new(Mutex::new(roblox_optimizer)),
            network_booster: Arc::new(Mutex::new(NetworkBooster::new())),
            discord_manager: Arc::new(Mutex::new(DiscordManager::new(enable_discord_rpc))),
            runtime,
            launched_from_startup,
            startup_recovery_done,
            startup_recovery_signal,
        })
    }

    /// Sync the Roblox client's on-disk window settings into the in-memory
    /// config. Moved out of `new()`: it repairs file ACLs (spawns icacls) and
    /// reads Roblox's settings file, which is too slow for the setup path.
    pub fn sync_roblox_window_settings(&self) {
        let optimizer = self.roblox_optimizer.lock();
        if let Err(e) = optimizer.repair_global_basic_settings_permissions() {
            log::warn!("Failed to repair Roblox settings permissions: {}", e);
        }
        if let Ok(current) = optimizer.read_current_settings() {
            drop(optimizer);
            let mut settings = self.settings.lock();
            settings.config.roblox_settings.window_fullscreen = current.fullscreen;
            if let Some((width, height)) = current.window_size {
                settings.config.roblox_settings.window_width = width;
                settings.config.roblox_settings.window_height = height;
            }
        }
    }
}
