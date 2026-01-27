//! SwiftTunnel GUI module
//!
//! This module contains the desktop app GUI built with egui/eframe.
//! Split into submodules for maintainability:
//! - theme: Color constants and design tokens
//! - animations: Animation system for smooth UI transitions
//! - connect_tab: VPN connection UI
//! - boost_tab: PC optimization boosts UI
//! - network_tab: Network analyzer UI
//! - settings_tab: Settings panel UI
//! - login: Authentication screens UI

mod theme;
mod animations;
mod connect_tab;
mod boost_tab;
mod network_tab;
mod settings_tab;
mod login;

// Re-export theme colors and animation helpers for use in submodules
pub use theme::*;
pub use animations::*;

use crate::auth::{AuthManager, AuthState, UserInfo};
use crate::geolocation::get_ip_location;
use crate::hidden_command;
use swifttunnel_fps_booster::notification::show_server_location;
use swifttunnel_fps_booster::roblox_watcher::{RobloxWatcher, RobloxEvent};
use swifttunnel_fps_booster::utils::{PendingConnection, is_administrator, save_pending_connection, relaunch_elevated, pending_connection_path};
use crate::network_analyzer::{
    NetworkAnalyzerState, StabilityTestProgress, SpeedTestProgress,
    run_stability_test, run_speed_test, speed_test::format_speed,
};
use crate::performance_monitor::SystemInfo;
use crate::roblox_optimizer::RobloxOptimizer;
use crate::settings::{load_settings, save_settings, AppSettings, WindowState};
use crate::structs::*;
use crate::system_optimizer::SystemOptimizer;
use crate::tray::SystemTray;
use crate::updater::{UpdateChecker, UpdateInfo, UpdateSettings, UpdateState, download_update, download_checksum, verify_checksum, install_update};
use crate::vpn::{ConnectionState, VpnConnection, DynamicServerList, DynamicGamingRegion, load_server_list, ServerListSource, GamePreset, get_apps_for_preset_set, ThroughputStats};
use eframe::egui;
use std::collections::{HashMap, VecDeque};
use std::path::PathBuf;
use std::sync::{Arc, Mutex, OnceLock};
use std::sync::atomic::{AtomicBool, Ordering};

// ═══════════════════════════════════════════════════════════════════════════════
//  AUTO-CONNECT FROM ELEVATION
// ═══════════════════════════════════════════════════════════════════════════════

/// Static storage for pending connection from --resume-connect
static PENDING_AUTO_CONNECT: OnceLock<PendingConnection> = OnceLock::new();

/// Set pending auto-connect from main.rs after elevation
/// Call this before creating BoosterApp if --resume-connect was passed
pub fn set_auto_connect_pending(pending: PendingConnection) {
    if PENDING_AUTO_CONNECT.set(pending).is_err() {
        log::warn!("Auto-connect pending was already set (ignored duplicate)");
    }
}

/// Take the pending auto-connect (returns None after first call)
fn take_auto_connect_pending() -> Option<PendingConnection> {
    // OnceLock doesn't have take(), so we use get() and mark it as consumed
    // We'll handle this by checking a flag in BoosterApp
    PENDING_AUTO_CONNECT.get().cloned()
}

// ═══════════════════════════════════════════════════════════════════════════════
//  INTERNAL TYPES
// ═══════════════════════════════════════════════════════════════════════════════

#[derive(PartialEq, Clone, Copy, Debug)]
enum Tab { Connect, Boost, Network, Settings }

#[derive(PartialEq, Clone, Copy)]
enum SettingsSection { General, Performance, Account }

// ═══════════════════════════════════════════════════════════════════════════════
//  BOOSTER APP
// ═══════════════════════════════════════════════════════════════════════════════

pub struct BoosterApp {
    pub state: AppState,
    system_info: Option<SystemInfo>,
    selected_profile: OptimizationProfile,
    current_tab: Tab,
    roblox_optimizer: RobloxOptimizer,
    status_message: Option<(String, egui::Color32, std::time::Instant)>,

    auth_manager: Arc<Mutex<AuthManager>>,
    auth_state: AuthState,
    user_info: Option<UserInfo>,
    auth_error: Option<String>,
    login_email: String,
    login_password: String,

    settings_dirty: bool,
    last_save_time: std::time::Instant,
    settings_section: SettingsSection,

    system_tray: Option<SystemTray>,

    vpn_connection: Arc<Mutex<VpnConnection>>,
    vpn_state: ConnectionState,
    dynamic_server_list: Arc<Mutex<DynamicServerList>>,
    servers_loading: bool,
    server_list_source: ServerListSource,
    selected_region: String,
    selected_server: String,
    /// Maps gaming region ID -> (best_server_id, latency_ms)
    region_latencies: Arc<Mutex<HashMap<String, (String, u32)>>>,
    finding_best_server: Arc<AtomicBool>,
    /// Selected game presets for split tunneling (multi-select)
    selected_game_presets: std::collections::HashSet<GamePreset>,

    // Performance: reuse tokio runtime
    runtime: Arc<tokio::runtime::Runtime>,
    // Track if we need continuous updates
    needs_repaint: bool,
    last_vpn_check: std::time::Instant,

    // Performance: cached values to avoid per-frame mutex locks
    cached_latencies: HashMap<String, (String, u32)>,
    cached_regions: Vec<DynamicGamingRegion>,
    last_cache_update: std::time::Instant,

    // Restore point status message
    restore_point_status: Option<(String, egui::Color32, std::time::Instant)>,

    // Auto-updater state
    update_state: Arc<Mutex<UpdateState>>,
    update_settings: UpdateSettings,
    update_check_started: bool,

    // Minimize to tray setting
    minimize_to_tray: bool,

    // Channel for immediate auth state updates from async operations
    auth_update_tx: std::sync::mpsc::Sender<AuthState>,
    auth_update_rx: std::sync::mpsc::Receiver<AuthState>,

    // Animation system for smooth UI transitions
    animations: AnimationManager,
    // App start time for pulse animation
    app_start_time: std::time::Instant,
    // Expanded boost info panels (toggle IDs that have expanded details)
    expanded_boost_info: std::collections::HashSet<String>,
    // Last successfully connected region (for "LAST USED" badge)
    last_connected_region: Option<String>,
    // Process detection notification (message, timestamp)
    process_notification: Option<(String, std::time::Instant)>,
    // Previously detected tunneled processes (for notification on new process)
    previously_tunneled: std::collections::HashSet<String>,
    // Previously detected game server IPs (to avoid duplicate notifications)
    detected_game_servers: std::collections::HashSet<std::net::Ipv4Addr>,
    // Channel for game server location lookups (ip, location)
    game_server_location_rx: std::sync::mpsc::Receiver<(std::net::Ipv4Addr, String)>,
    game_server_location_tx: std::sync::mpsc::Sender<(std::net::Ipv4Addr, String)>,
    // Roblox log watcher for game server detection (Bloxstrap-style)
    roblox_watcher: Option<RobloxWatcher>,
    // Flag to force quit (bypass minimize-to-tray)
    force_quit: bool,
    // Forced server selection per region (region_id -> server_id)
    // When set, this server is used instead of auto-selecting best ping
    forced_servers: HashMap<String, String>,
    // Which region's server selection popup is open (None = no popup)
    server_selection_popup: Option<String>,

    // Network Analyzer state
    network_analyzer_state: NetworkAnalyzerState,
    // Channels for stability test progress
    stability_progress_tx: std::sync::mpsc::Sender<StabilityTestProgress>,
    stability_progress_rx: std::sync::mpsc::Receiver<StabilityTestProgress>,
    // Channels for speed test progress
    speed_progress_tx: std::sync::mpsc::Sender<SpeedTestProgress>,
    speed_progress_rx: std::sync::mpsc::Receiver<SpeedTestProgress>,
    // Animation state for speed gauges
    download_gauge_animation: Option<Animation>,
    upload_gauge_animation: Option<Animation>,

    // Network throughput graph state
    /// Throughput stats handle (when connected)
    throughput_stats: Option<ThroughputStats>,
    /// History of throughput readings (bytes/sec) for graph
    /// Each entry: (timestamp, tx_bytes_per_sec, rx_bytes_per_sec)
    throughput_history: VecDeque<(std::time::Instant, f64, f64)>,
    /// Last bytes values for calculating rate
    last_throughput_bytes: Option<(u64, u64, std::time::Instant)>,
    /// Artificial latency to add to VPN connection (0-100ms)
    artificial_latency_ms: u32,
    /// Current VPN config ID (from API, used for latency updates)
    current_config_id: Option<String>,
    /// Flag indicating latency update is in progress
    updating_latency: bool,
    /// Pending latency value and when it was set (for 5s debounce anti-abuse)
    /// Format: (target_latency_ms, time_when_set)
    pending_latency: Option<(u32, std::time::Instant)>,
    /// Last applied latency (to avoid redundant API calls)
    last_applied_latency: u32,
    /// Enable experimental features (Practice Mode, etc.)
    experimental_mode: bool,
    /// Logo texture handle (loaded from embedded PNG)
    logo_texture: Option<egui::TextureHandle>,
    /// Routing mode for split tunnel (V1 = process-based, V2 = hybrid/ExitLag-style)
    routing_mode: crate::settings::RoutingMode,
    /// Pending auto-connect from elevation (--resume-connect flag)
    /// Set when app is relaunched with admin privileges to continue connection
    auto_connect_pending: Option<PendingConnection>,
    /// Flag indicating auto-connect is consumed (to prevent double-connect)
    auto_connect_consumed: bool,
    /// Instant when user clicked Connect (for immediate UI feedback before VPN state updates)
    /// This provides instant visual feedback while the VPN state machine catches up (500ms poll)
    connecting_initiated: Option<std::time::Instant>,
}

impl BoosterApp {
    pub fn new(cc: &eframe::CreationContext<'_>) -> Self {
        let saved_settings = load_settings();
        Self::configure_style(&cc.egui_ctx);

        // Create a single shared runtime for async operations
        let runtime = Arc::new(
            tokio::runtime::Builder::new_multi_thread()
                .worker_threads(2)
                .enable_all()
                .build()
                .expect("Failed to create tokio runtime")
        );

        // Create channel for immediate auth state notifications from async operations
        let (auth_update_tx, auth_update_rx) = std::sync::mpsc::channel::<AuthState>();

        // Create channels for network analyzer progress updates
        let (stability_tx, stability_rx) = std::sync::mpsc::channel::<StabilityTestProgress>();
        let (speed_tx, speed_rx) = std::sync::mpsc::channel::<SpeedTestProgress>();

        // Create channel for game server location lookups (Bloxstrap-style notifications)
        let (game_server_tx, game_server_rx) = std::sync::mpsc::channel::<(std::net::Ipv4Addr, String)>();

        // Initialize auth manager - this can only fail if Windows DPAPI is unavailable,
        // which indicates a fundamental system issue. In that case, panic is acceptable.
        let auth_manager = AuthManager::new().unwrap_or_else(|e| {
            log::error!("Critical: Failed to initialize auth manager: {}", e);
            log::error!("This usually means Windows credential storage (DPAPI) is unavailable.");
            panic!("Cannot initialize authentication: {}. Please ensure Windows credential storage is working.", e)
        });
        let auth_state = auth_manager.get_state();
        let user_info = auth_manager.get_user();

        let mut app_state = AppState::default();
        app_state.config = saved_settings.config.clone();
        app_state.optimizations_active = saved_settings.optimizations_active;

        let current_tab = match saved_settings.current_tab.as_str() {
            "boost" => Tab::Boost,
            "network" => Tab::Network,
            "settings" => Tab::Settings,
            _ => Tab::Connect,
        };

        // Initialize empty server list (will be populated from API)
        let dynamic_server_list = Arc::new(Mutex::new(DynamicServerList::new_empty()));
        let region_latencies = Arc::new(Mutex::new(HashMap::new()));
        let finding_best_server = Arc::new(AtomicBool::new(false));

        // Spawn async task to fetch server list AND ping all regions at startup
        let server_list_clone = Arc::clone(&dynamic_server_list);
        let latencies_clone = Arc::clone(&region_latencies);
        let finding_clone = Arc::clone(&finding_best_server);
        let rt_clone = Arc::clone(&runtime);

        std::thread::spawn(move || {
            rt_clone.block_on(async {
                match load_server_list().await {
                    Ok((servers, regions, source)) => {
                        log::info!("Server list loaded from {}", source);

                        // Store the list
                        if let Ok(mut list) = server_list_clone.lock() {
                            list.update(servers.clone(), regions.clone(), source);
                        }

                        // Now ping all regions in the background
                        finding_clone.store(true, Ordering::SeqCst);
                        log::info!("Starting background latency measurement for {} regions...", regions.len());

                        for region in &regions {
                            let server_ips: Vec<(String, String)> = region.servers.iter()
                                .filter_map(|server_id| {
                                    servers.iter()
                                        .find(|s| &s.region == server_id)
                                        .map(|s| (server_id.clone(), s.ip.clone()))
                                })
                                .collect();

                            log::info!("Pinging region '{}' with {} servers: {:?}", region.id, server_ips.len(),
                                server_ips.iter().map(|(id, ip)| format!("{}={}", id, ip)).collect::<Vec<_>>());

                            if server_ips.is_empty() {
                                log::warn!("Region '{}' has no pingable servers! region.servers={:?}", region.id, region.servers);
                                continue;
                            }

                            if let Some((best_server_id, latency)) = ping_region_async(&server_ips).await {
                                if let Ok(mut lat) = latencies_clone.lock() {
                                    lat.insert(region.id.clone(), (best_server_id.clone(), latency));
                                    log::info!("Region {} best server: {} ({}ms)", region.id, best_server_id, latency);
                                } else {
                                    log::error!("Region '{}' failed to store latency - mutex poisoned", region.id);
                                }
                            } else {
                                log::warn!("Region '{}' ping failed - no servers responded", region.id);
                            }
                        }

                        finding_clone.store(false, Ordering::SeqCst);
                        log::info!("Background latency measurement complete");
                    }
                    Err(e) => {
                        log::error!("Failed to load server list: {}", e);
                        if let Ok(mut list) = server_list_clone.lock() {
                            *list = DynamicServerList::new_error(e);
                        }
                    }
                }
            });
        });

        Self {
            state: app_state,
            system_info: None,
            selected_profile: saved_settings.config.profile,
            current_tab,
            roblox_optimizer: RobloxOptimizer::new(),
            status_message: None,
            auth_manager: Arc::new(Mutex::new(auth_manager)),
            auth_state,
            user_info,
            auth_error: None,
            login_email: String::new(),
            login_password: String::new(),
            settings_dirty: false,
            last_save_time: std::time::Instant::now(),
            settings_section: SettingsSection::General,
            system_tray: Self::init_system_tray(saved_settings.optimizations_active, saved_settings.minimize_to_tray),
            vpn_connection: Arc::new(Mutex::new(VpnConnection::new())),
            vpn_state: ConnectionState::Disconnected,
            dynamic_server_list,
            servers_loading: true,
            server_list_source: ServerListSource::Loading,
            selected_region: saved_settings.selected_region.clone(),
            selected_server: saved_settings.selected_server.clone(),
            region_latencies,
            finding_best_server,
            // Convert saved game preset strings to HashSet<GamePreset>
            selected_game_presets: saved_settings.selected_game_presets.iter()
                .filter_map(|s| match s.as_str() {
                    "roblox" => Some(GamePreset::Roblox),
                    "valorant" => Some(GamePreset::Valorant),
                    "fortnite" => Some(GamePreset::Fortnite),
                    _ => None,
                })
                .collect(),
            runtime,
            needs_repaint: true,
            last_vpn_check: std::time::Instant::now(),
            // Performance: initialize caches
            cached_latencies: HashMap::new(),
            cached_regions: Vec::new(),
            last_cache_update: std::time::Instant::now(),

            // Restore point status
            restore_point_status: None,

            // Auto-updater
            update_state: Arc::new(Mutex::new(UpdateState::Idle)),
            update_settings: saved_settings.update_settings.clone(),
            update_check_started: false,

            // Minimize to tray
            minimize_to_tray: saved_settings.minimize_to_tray,

            // Auth state update channel
            auth_update_tx,
            auth_update_rx,

            // Animation system
            animations: AnimationManager::default(),
            app_start_time: std::time::Instant::now(),

            // Expanded boost info panels (restore from settings)
            expanded_boost_info: saved_settings.expanded_boost_info.into_iter().collect(),

            // Last connected region for "LAST USED" badge
            last_connected_region: saved_settings.last_connected_region,

            // Process detection notification
            process_notification: None,
            previously_tunneled: std::collections::HashSet::new(),
            detected_game_servers: std::collections::HashSet::new(),
            game_server_location_rx: game_server_rx,
            game_server_location_tx: game_server_tx,
            // Roblox log watcher (always active for server region detection)
            roblox_watcher: {
                log::info!("Starting Roblox log watcher for game server detection...");
                match RobloxWatcher::new() {
                    Some(watcher) => {
                        log::info!("Roblox log watcher started successfully");
                        Some(watcher)
                    }
                    None => {
                        log::info!("Roblox logs directory not found - game server detection disabled");
                        None
                    }
                }
            },
            // Force quit flag (bypass minimize-to-tray)
            force_quit: false,
            // Forced server selection per region (restored from settings)
            forced_servers: saved_settings.forced_servers.clone(),
            // Server selection popup (none open initially)
            server_selection_popup: None,

            // Network Analyzer - initialize state and channels
            network_analyzer_state: {
                let mut state = NetworkAnalyzerState::default();
                // Load cached results from settings
                state.stability.results = saved_settings.network_test_results.last_stability.clone();
                state.speed.results = saved_settings.network_test_results.last_speed.clone();
                state
            },
            stability_progress_tx: stability_tx,
            stability_progress_rx: stability_rx,
            speed_progress_tx: speed_tx,
            speed_progress_rx: speed_rx,
            download_gauge_animation: None,
            upload_gauge_animation: None,

            // Network throughput graph
            throughput_stats: None,
            throughput_history: VecDeque::with_capacity(64), // 1 minute at 1 sample/sec (trimmed to 60)
            last_throughput_bytes: None,

            // Artificial latency for practice mode
            artificial_latency_ms: saved_settings.artificial_latency_ms,
            current_config_id: None,
            updating_latency: false,
            pending_latency: None,
            last_applied_latency: saved_settings.artificial_latency_ms,
            // Experimental mode
            experimental_mode: saved_settings.experimental_mode,
            // Routing mode for split tunnel
            routing_mode: saved_settings.routing_mode,
            // Logo texture (loaded from embedded PNG)
            logo_texture: Self::load_logo_texture(&cc.egui_ctx),
            // Auto-connect from elevation (take from static if --resume-connect was used)
            auto_connect_pending: take_auto_connect_pending(),
            auto_connect_consumed: false,
            // Instant connect feedback (for immediate UI response)
            connecting_initiated: None,
        }
    }

    /// Load the SwiftTunnel logo as an egui texture
    fn load_logo_texture(ctx: &egui::Context) -> Option<egui::TextureHandle> {
        // Embed the logo PNG at compile time
        let logo_bytes = include_bytes!("../../assets/logo.png");

        // Decode the PNG image
        match image::load_from_memory(logo_bytes) {
            Ok(image) => {
                let rgba = image.to_rgba8();
                let size = [rgba.width() as usize, rgba.height() as usize];
                let pixels = rgba.into_raw();

                let color_image = egui::ColorImage::from_rgba_unmultiplied(size, &pixels);
                Some(ctx.load_texture("swifttunnel-logo", color_image, egui::TextureOptions::LINEAR))
            }
            Err(e) => {
                log::warn!("Failed to load logo image: {}", e);
                None
            }
        }
    }

    fn configure_style(ctx: &egui::Context) {
        let mut style = (*ctx.style()).clone();
        style.visuals.dark_mode = true;
        style.visuals.panel_fill = BG_DARKEST;
        style.visuals.window_fill = BG_CARD;
        style.visuals.extreme_bg_color = BG_CARD;
        style.visuals.faint_bg_color = BG_ELEVATED;

        style.visuals.widgets.inactive.bg_fill = BG_CARD;
        style.visuals.widgets.inactive.fg_stroke = egui::Stroke::new(1.0, TEXT_SECONDARY);
        style.visuals.widgets.inactive.corner_radius = egui::CornerRadius::same(8);

        style.visuals.widgets.hovered.bg_fill = BG_HOVER;
        style.visuals.widgets.hovered.fg_stroke = egui::Stroke::new(1.0, TEXT_PRIMARY);
        style.visuals.widgets.hovered.corner_radius = egui::CornerRadius::same(8);

        style.visuals.widgets.active.bg_fill = ACCENT_PRIMARY;
        style.visuals.widgets.active.fg_stroke = egui::Stroke::new(1.0, TEXT_PRIMARY);
        style.visuals.widgets.active.corner_radius = egui::CornerRadius::same(8);

        style.visuals.widgets.noninteractive.fg_stroke = egui::Stroke::new(1.0, TEXT_PRIMARY);
        style.visuals.selection.bg_fill = ACCENT_PRIMARY.gamma_multiply(0.3);

        style.spacing.item_spacing = egui::vec2(12.0, 10.0);
        style.spacing.button_padding = egui::vec2(20.0, 10.0);
        style.spacing.window_margin = egui::Margin::same(20);

        ctx.set_style(style);
    }

    fn init_system_tray(optimizations_active: bool, minimize_to_tray: bool) -> Option<SystemTray> {
        match SystemTray::new(optimizations_active) {
            Ok(tray) => {
                tray.set_minimize_to_tray(minimize_to_tray);
                Some(tray)
            }
            Err(e) => {
                log::error!("Failed to initialize system tray: {}", e);
                None
            }
        }
    }

    pub fn set_system_info(&mut self, info: SystemInfo) {
        self.system_info = Some(info);
    }

    fn mark_dirty(&mut self) {
        self.settings_dirty = true;
    }

    fn save_if_needed(&mut self, ctx: &egui::Context) {
        if !self.settings_dirty || self.last_save_time.elapsed() < std::time::Duration::from_secs(2) {
            return;
        }

        let window_state = ctx.input(|i| {
            let rect = i.viewport().outer_rect;
            let maximized = i.viewport().maximized.unwrap_or(false);
            rect.map(|r| WindowState {
                x: Some(r.min.x), y: Some(r.min.y),
                width: r.width().max(400.0), height: r.height().max(500.0),
                maximized,
            }).unwrap_or_default()
        });

        let settings = AppSettings {
            theme: "dark".to_string(),
            config: self.state.config.clone(),
            optimizations_active: self.state.optimizations_active,
            window_state,
            selected_region: self.selected_region.clone(),
            selected_server: self.selected_server.clone(),
            current_tab: match self.current_tab {
                Tab::Connect => "connect", Tab::Boost => "boost", Tab::Network => "network", Tab::Settings => "settings",
            }.to_string(),
            update_settings: self.update_settings.clone(),
            minimize_to_tray: self.minimize_to_tray,
            last_connected_region: self.last_connected_region.clone(),
            expanded_boost_info: self.expanded_boost_info.iter().cloned().collect(),
            // Convert HashSet<GamePreset> to Vec<String> for storage
            selected_game_presets: self.selected_game_presets.iter()
                .map(|p| match p {
                    GamePreset::Roblox => "roblox",
                    GamePreset::Valorant => "valorant",
                    GamePreset::Fortnite => "fortnite",
                }.to_string())
                .collect(),
            // Save network test results
            network_test_results: crate::network_analyzer::NetworkTestResultsCache {
                last_stability: self.network_analyzer_state.stability.results.clone(),
                last_speed: self.network_analyzer_state.speed.results.clone(),
            },
            // Save forced server selections
            forced_servers: self.forced_servers.clone(),
            // Save artificial latency setting
            artificial_latency_ms: self.artificial_latency_ms,
            // Save experimental mode setting
            experimental_mode: self.experimental_mode,
            // Save routing mode setting
            routing_mode: self.routing_mode,
        };

        let _ = save_settings(&settings);
        self.settings_dirty = false;
        self.last_save_time = std::time::Instant::now();
    }

    fn set_status(&mut self, msg: &str, color: egui::Color32) {
        self.status_message = Some((msg.to_string(), color, std::time::Instant::now()));
    }
}

// ═══════════════════════════════════════════════════════════════════════════════
//  ASYNC PING HELPERS
// ═══════════════════════════════════════════════════════════════════════════════

/// Async ping function that doesn't block the main thread
/// Returns (best_server_id, latency_ms) for the server with lowest latency
async fn ping_region_async(servers: &[(String, String)]) -> Option<(String, u32)> {
    use crate::hidden_command;

    log::info!("ping_region_async: starting for {} servers", servers.len());

    let mut best_result: Option<(String, u32)> = None;

    for (server_id, server_ip) in servers {
        let mut total = 0u32;
        let mut count = 0u32;

        // Do 2 pings per server (faster than 3)
        for ping_num in 0..2 {
            // Use spawn_blocking to run the ping command without blocking the async runtime
            let ping_result = tokio::task::spawn_blocking({
                let ip = server_ip.clone();
                move || {
                    hidden_command("ping")
                        .args(["-n", "1", "-w", "2000", &ip])
                        .output()
                }
            }).await;

            // Handle spawn_blocking result
            let output = match ping_result {
                Ok(Ok(output)) => Some(output),
                Ok(Err(e)) => {
                    log::warn!("  Ping {} to {}: IO error: {}", ping_num + 1, server_ip, e);
                    None
                }
                Err(e) => {
                    log::warn!("  Ping {} to {}: spawn_blocking failed: {}", ping_num + 1, server_ip, e);
                    None
                }
            };

            if let Some(output) = output {
                let stdout = String::from_utf8_lossy(&output.stdout);
                let stderr = String::from_utf8_lossy(&output.stderr);

                if !output.status.success() {
                    log::debug!("  Ping {} failed: status={}, stderr={}", ping_num + 1, output.status, stderr.trim());
                    continue;
                }

                if let Some(ms) = parse_ping_output(&stdout) {
                    log::debug!("  Ping {} to {}: {}ms", ping_num + 1, server_ip, ms);
                    total += ms;
                    count += 1;
                } else {
                    log::warn!("  Ping {} to {}: failed to parse output: '{}'", ping_num + 1, server_ip, stdout.lines().next().unwrap_or("(empty)"));
                }
            }

            // Small delay between pings
            tokio::time::sleep(tokio::time::Duration::from_millis(50)).await;
        }

        // If ICMP failed, try TCP fallback on port 8082 (WebSocket echo port)
        if count == 0 {
            log::info!("  ICMP failed for {}, trying TCP fallback on port 8082", server_ip);
            if let Some(tcp_ms) = tcp_ping(server_ip, 8082).await {
                log::info!("  TCP ping to {}: {}ms", server_ip, tcp_ms);
                total = tcp_ms;
                count = 1;
            }
        }

        if count > 0 {
            let avg = total / count;
            log::info!("  Server {} latency: {}ms ({} pings)", server_id, avg, count);
            let is_better = match &best_result {
                None => true,
                Some((_, best_latency)) => avg < *best_latency,
            };
            if is_better {
                best_result = Some((server_id.clone(), avg));
            }
        } else {
            log::warn!("  Server {} all pings failed (ICMP + TCP)", server_id);
        }
    }

    log::info!("ping_region_async result: {:?}", best_result);
    best_result
}

fn parse_ping_output(stdout: &str) -> Option<u32> {
    for line in stdout.lines() {
        if let Some(idx) = line.find("time=") {
            let rest = &line[idx + 5..];
            if let Some(ms_idx) = rest.find("ms") {
                let time_str = rest[..ms_idx].trim();
                if let Ok(ms) = time_str.parse::<u32>() {
                    return Some(ms);
                }
            }
        } else if line.contains("time<1ms") {
            return Some(1);
        }
    }
    None
}

/// TCP connect timing fallback for when ICMP ping fails.
/// Uses port 8082 (WebSocket echo port) available on all VPN servers.
async fn tcp_ping(ip: &str, port: u16) -> Option<u32> {
    use std::net::SocketAddr;
    use tokio::net::TcpStream;
    use tokio::time::{timeout, Duration, Instant};

    let addr: SocketAddr = format!("{}:{}", ip, port).parse().ok()?;
    let start = Instant::now();

    match timeout(Duration::from_secs(2), TcpStream::connect(addr)).await {
        Ok(Ok(_stream)) => {
            let elapsed = start.elapsed().as_millis() as u32;
            // Subtract 1ms for TCP overhead (3-way handshake vs ICMP echo), min 1ms
            Some(elapsed.saturating_sub(1).max(1))
        }
        Ok(Err(e)) => {
            log::debug!("  TCP ping to {}:{} connect error: {}", ip, port, e);
            None
        }
        Err(_) => {
            log::debug!("  TCP ping to {}:{} timed out", ip, port);
            None
        }
    }
}

// ═══════════════════════════════════════════════════════════════════════════════
//  EFRAME APP IMPLEMENTATION
// ═══════════════════════════════════════════════════════════════════════════════

impl eframe::App for BoosterApp {
    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        // Handle keyboard shortcuts first
        let switch_to_tab = ctx.input(|i| {
            if i.modifiers.ctrl {
                if i.key_pressed(egui::Key::Num1) { Some(Tab::Connect) }
                else if i.key_pressed(egui::Key::Num2) { Some(Tab::Boost) }
                else if i.key_pressed(egui::Key::Num3) { Some(Tab::Network) }
                else if i.key_pressed(egui::Key::Num4) { Some(Tab::Settings) }
                else { None }
            } else { None }
        });
        if let Some(tab) = switch_to_tab {
            if matches!(self.auth_state, AuthState::LoggedIn(_)) {
                self.current_tab = tab;
                self.mark_dirty();
            }
        }

        // Ctrl+Shift+C for quick connect/disconnect
        let quick_toggle = ctx.input(|i| i.modifiers.ctrl && i.modifiers.shift && i.key_pressed(egui::Key::C));
        if quick_toggle && matches!(self.auth_state, AuthState::LoggedIn(_)) {
            if self.vpn_state.is_connected() || self.vpn_state.is_connecting() {
                self.disconnect_vpn();
            } else if matches!(self.vpn_state, ConnectionState::Disconnected) {
                self.connect_vpn();
            }
        }

        // Clean up completed animations
        self.animations.cleanup_completed();

        // Poll for OAuth callback from localhost server
        // This checks if the browser has redirected back to our localhost server
        let oauth_callback = if matches!(self.auth_state, AuthState::AwaitingOAuthCallback(_)) {
            if let Ok(auth) = self.auth_manager.lock() {
                auth.poll_oauth_callback()
            } else {
                None
            }
        } else {
            None
        };
        // Process callback outside the lock scope to avoid borrow checker issues
        if let Some(callback_data) = oauth_callback {
            log::info!("Received OAuth callback from localhost server");
            self.process_oauth_callback(&callback_data.token, &callback_data.state);
        }

        // Auto-connect from elevation (--resume-connect flag)
        // Triggers when: pending connection exists, logged in, servers loaded, not already consumed
        if !self.auto_connect_consumed {
            if let Some(pending) = &self.auto_connect_pending {
                let is_logged_in = matches!(self.auth_state, AuthState::LoggedIn(_));
                let servers_loaded = !self.servers_loading;
                let is_disconnected = matches!(self.vpn_state, ConnectionState::Disconnected);

                if is_logged_in && servers_loaded && is_disconnected {
                    log::info!(
                        "Auto-connecting from elevation: region={}, server={}",
                        pending.region, pending.server
                    );

                    // Apply pending connection settings
                    self.selected_region = pending.region.clone();
                    self.selected_server = pending.server.clone();

                    // Convert apps back to game presets
                    self.selected_game_presets.clear();
                    for app in &pending.apps {
                        match app.to_lowercase().as_str() {
                            "robloxplayerbeta.exe" | "robloxplayerlauncher.exe" => {
                                self.selected_game_presets.insert(crate::vpn::GamePreset::Roblox);
                            }
                            "valorant.exe" | "valorant-win64-shipping.exe" => {
                                self.selected_game_presets.insert(crate::vpn::GamePreset::Valorant);
                            }
                            "fortnite.exe" | "fortniteclient-win64-shipping.exe" => {
                                self.selected_game_presets.insert(crate::vpn::GamePreset::Fortnite);
                            }
                            _ => {}
                        }
                    }
                    // If no presets were matched, default to Roblox
                    if self.selected_game_presets.is_empty() {
                        self.selected_game_presets.insert(crate::vpn::GamePreset::Roblox);
                    }

                    // Set routing mode from pending
                    self.routing_mode = match pending.routing_mode {
                        1 => crate::settings::RoutingMode::V2,
                        _ => crate::settings::RoutingMode::V1,
                    };

                    // Mark as consumed before connecting to prevent loop
                    self.auto_connect_consumed = true;

                    // Trigger connection
                    self.connect_vpn();
                }
            }
        }

        // PERFORMANCE FIX: Only request continuous repaint when actually needed
        let is_loading = self.servers_loading || self.finding_best_server.load(Ordering::Relaxed);
        let is_vpn_transitioning = self.vpn_state.is_connecting()
            || matches!(self.vpn_state, ConnectionState::Disconnecting)
            || self.connecting_initiated.is_some(); // Include instant connect feedback
        let is_logging_in = matches!(self.auth_state, AuthState::LoggingIn);
        let is_awaiting_oauth_here = matches!(self.auth_state, AuthState::AwaitingOAuthCallback(_));
        let is_updating = self.update_state.lock().map(|s| s.is_downloading()).unwrap_or(false);
        let has_animations = self.animations.has_active_animations();
        let is_connected = self.vpn_state.is_connected();  // For pulse animation
        let is_network_testing = self.network_analyzer_state.stability.running || self.network_analyzer_state.speed.running;
        let has_pending_latency = self.pending_latency.is_some();  // For countdown display

        if is_loading || is_vpn_transitioning || is_logging_in || is_awaiting_oauth_here || is_updating || has_animations || is_network_testing {
            // Fast repaint for animations (60 FPS target)
            ctx.request_repaint_after(std::time::Duration::from_millis(16));
        } else if is_connected || has_pending_latency {
            // Slow repaint for pulse animation and latency countdown (10 FPS is enough)
            ctx.request_repaint_after(std::time::Duration::from_millis(100));
        }
        // Otherwise, egui will only repaint on user interaction (clicks, typing, etc.)

        // Handle tray events
        let (toggle_opt, quit, show_window) = if let Some(ref tray) = self.system_tray {
            (tray.check_toggle_optimizations(), tray.check_quit_requested(), tray.check_show_window())
        } else {
            (false, false, false)
        };

        if toggle_opt {
            self.state.optimizations_active = !self.state.optimizations_active;
            self.mark_dirty();
        }

        // Show window when tray icon clicked or "Show" menu item clicked
        if show_window {
            ctx.send_viewport_cmd(egui::ViewportCommand::Visible(true));
            ctx.send_viewport_cmd(egui::ViewportCommand::Minimized(false));
            ctx.send_viewport_cmd(egui::ViewportCommand::Focus);
        }

        // Only actually quit when tray "Quit" is clicked
        if quit && !self.force_quit {
            log::info!("Tray Quit clicked - forcing quit");
            self.force_quit = true;

            // Shutdown tray threads first
            if let Some(ref tray) = self.system_tray {
                tray.shutdown();
            }

            // Disconnect VPN before quitting to ensure proper adapter cleanup
            self.disconnect_vpn_sync();

            // Force save settings before quitting
            self.settings_dirty = true;
            self.last_save_time = std::time::Instant::now() - std::time::Duration::from_secs(10);
            self.save_if_needed(ctx);

            // Force immediate process exit - ViewportCommand::Close is unreliable after rt.block_on()
            log::info!("Exiting process...");
            std::process::exit(0);
        }

        // Handle close button - minimize to tray instead of closing if enabled
        // BUT only if we're not force quitting from the tray menu
        let close_requested = ctx.input(|i| i.viewport().close_requested());
        if close_requested && !self.force_quit && self.minimize_to_tray && self.system_tray.is_some() {
            // Cancel the close and minimize to tray instead
            ctx.send_viewport_cmd(egui::ViewportCommand::CancelClose);
            ctx.send_viewport_cmd(egui::ViewportCommand::Visible(false));
            log::info!("Close button pressed - minimizing to tray");
        }

        // Check for immediate auth state updates from async operations (non-blocking)
        while let Ok(new_state) = self.auth_update_rx.try_recv() {
            log::info!("Received immediate auth state update");

            // Sync auth error from AuthState::Error for display
            if let AuthState::Error(ref msg) = new_state {
                let user_friendly = match msg.as_str() {
                    m if m.contains("Invalid login credentials") => "Invalid email or password. Please try again.".to_string(),
                    m if m.contains("Email not confirmed") => "Please verify your email address before signing in.".to_string(),
                    m if m.contains("Network error") => "Unable to connect. Please check your internet connection.".to_string(),
                    m if m.contains("timeout") || m.contains("Timeout") => "Connection timed out. Please try again.".to_string(),
                    _ => msg.clone(),
                };
                self.auth_error = Some(user_friendly);
            } else if matches!(new_state, AuthState::LoggedIn(_)) {
                self.auth_error = None;
            }

            self.auth_state = new_state;
            if let Ok(auth) = self.auth_manager.try_lock() {
                self.user_info = auth.get_user();
            }
        }

        // Poll network analyzer stability test progress
        while let Ok(progress) = self.stability_progress_rx.try_recv() {
            match progress {
                StabilityTestProgress::PingSample(sample) => {
                    self.network_analyzer_state.stability.ping_samples.push(sample);
                }
                StabilityTestProgress::Progress(p) => {
                    self.network_analyzer_state.stability.progress = p;
                }
                StabilityTestProgress::Completed(results) => {
                    self.network_analyzer_state.stability.running = false;
                    self.network_analyzer_state.stability.progress = 1.0;
                    self.network_analyzer_state.stability.results = Some(results);
                    self.mark_dirty(); // Save results
                }
                StabilityTestProgress::Error(msg) => {
                    log::error!("Stability test error: {}", msg);
                    self.network_analyzer_state.stability.running = false;
                }
            }
        }

        // Poll network analyzer speed test progress
        while let Ok(progress) = self.speed_progress_rx.try_recv() {
            match progress {
                SpeedTestProgress::DownloadStarted => {
                    self.network_analyzer_state.speed.phase = crate::network_analyzer::SpeedTestPhase::Download;
                    self.network_analyzer_state.speed.phase_progress = 0.0;
                }
                SpeedTestProgress::DownloadProgress(speed, p) => {
                    self.network_analyzer_state.speed.download_speed = speed;
                    self.network_analyzer_state.speed.phase_progress = p;
                    // Update gauge animation
                    self.download_gauge_animation = Some(Animation::new(
                        self.network_analyzer_state.speed.download_speed.min(speed),
                        speed,
                        0.3
                    ));
                }
                SpeedTestProgress::DownloadComplete(speed) => {
                    self.network_analyzer_state.speed.download_speed = speed;
                    self.network_analyzer_state.speed.phase_progress = 1.0;
                }
                SpeedTestProgress::UploadStarted => {
                    self.network_analyzer_state.speed.phase = crate::network_analyzer::SpeedTestPhase::Upload;
                    self.network_analyzer_state.speed.phase_progress = 0.0;
                }
                SpeedTestProgress::UploadProgress(speed, p) => {
                    self.network_analyzer_state.speed.upload_speed = speed;
                    self.network_analyzer_state.speed.phase_progress = p;
                    // Update gauge animation
                    self.upload_gauge_animation = Some(Animation::new(
                        self.network_analyzer_state.speed.upload_speed.min(speed),
                        speed,
                        0.3
                    ));
                }
                SpeedTestProgress::UploadComplete(speed) => {
                    self.network_analyzer_state.speed.upload_speed = speed;
                    self.network_analyzer_state.speed.phase_progress = 1.0;
                }
                SpeedTestProgress::Completed(results) => {
                    self.network_analyzer_state.speed.running = false;
                    self.network_analyzer_state.speed.phase = crate::network_analyzer::SpeedTestPhase::Complete;
                    self.network_analyzer_state.speed.results = Some(results);
                    self.mark_dirty(); // Save results
                }
                SpeedTestProgress::Error(msg) => {
                    log::error!("Speed test error: {}", msg);
                    self.network_analyzer_state.speed.running = false;
                    self.network_analyzer_state.speed.phase = crate::network_analyzer::SpeedTestPhase::Idle;
                }
            }
        }

        // PERFORMANCE FIX: Only check VPN state every 500ms, not every frame
        // Use try_lock to avoid blocking the UI thread
        if self.last_vpn_check.elapsed() >= std::time::Duration::from_millis(500) {
            self.last_vpn_check = std::time::Instant::now();

            // Non-blocking VPN state check using try_lock
            let mut should_mark_dirty = false;
            let mut should_apply_latency = false;
            if let Ok(vpn) = self.vpn_connection.try_lock() {
                // Get state directly - the state() method is fast
                let new_state = self.runtime.block_on(vpn.state());

                // Clear connecting_initiated when VPN state transitions from disconnected
                // This ensures the optimistic animation stops once the real state takes over
                if self.connecting_initiated.is_some() {
                    let was_disconnected = matches!(self.vpn_state, ConnectionState::Disconnected);
                    let is_transitioning = new_state.is_connecting() || new_state.is_connected() || matches!(new_state, ConnectionState::Error(_));
                    if was_disconnected && is_transitioning {
                        log::debug!("VPN state changed, clearing connecting_initiated");
                        self.connecting_initiated = None;
                    }
                    // Also clear if it's been more than 5 seconds (timeout fallback)
                    if let Some(initiated) = self.connecting_initiated {
                        if initiated.elapsed() > std::time::Duration::from_secs(5) {
                            log::warn!("connecting_initiated timeout (5s), clearing");
                            self.connecting_initiated = None;
                        }
                    }
                }

                // Track when we first connect to save the last connected region
                if !self.vpn_state.is_connected() && new_state.is_connected() {
                    if let ConnectionState::Connected { server_region, .. } = &new_state {
                        // Only update if it's a new region
                        if self.last_connected_region.as_ref() != Some(server_region) {
                            self.last_connected_region = Some(server_region.clone());
                            should_mark_dirty = true;
                        }
                    }
                }

                // Process detection notifications - check for new tunneled processes
                if let ConnectionState::Connected { tunneled_processes, .. } = &new_state {
                    for process in tunneled_processes {
                        if !self.previously_tunneled.contains(process) {
                            // New process detected - show notification
                            log::info!("New process detected and tunneled: {}", process);
                            self.process_notification = Some((
                                format!("> Tunneling: {}", process),
                                std::time::Instant::now(),
                            ));
                            self.previously_tunneled.insert(process.clone());
                        }
                    }
                }

                // Clear state when disconnecting
                if new_state == ConnectionState::Disconnected {
                    self.previously_tunneled.clear();
                    self.detected_game_servers.clear();
                    // Clear throughput tracking
                    self.throughput_stats = None;
                    self.throughput_history.clear();
                    self.last_throughput_bytes = None;
                    // Clear config ID
                    self.current_config_id = None;
                    // Note: Roblox watcher stays active to detect server region without VPN
                }

                // Get throughput stats and config ID when first connecting
                if !self.vpn_state.is_connected() && new_state.is_connected() {
                    // Get throughput stats handle from VPN connection
                    self.throughput_stats = vpn.get_throughput_stats();
                    self.throughput_history.clear();
                    self.last_throughput_bytes = None;
                    log::info!("Throughput stats tracking: {:?}", self.throughput_stats.is_some());

                    // Store config ID for latency updates
                    self.current_config_id = vpn.get_config_id();
                    log::info!("Config ID for latency updates: {:?}", self.current_config_id);

                    // Apply artificial latency if configured (deferred until lock is released)
                    if self.artificial_latency_ms > 0 && self.current_config_id.is_some() {
                        log::info!("Will apply artificial latency: +{}ms", self.artificial_latency_ms);
                        should_apply_latency = true;
                    }
                }

                self.vpn_state = new_state;
            }
            // Mark dirty outside the lock scope to avoid borrow conflict
            if should_mark_dirty {
                self.mark_dirty();
            }
            // Apply latency after releasing the VPN lock
            if should_apply_latency {
                self.update_server_latency();
                self.last_applied_latency = self.artificial_latency_ms;
            }

            // Check if pending latency debounce has elapsed (5 second anti-abuse delay)
            if let Some((pending_value, pending_time)) = self.pending_latency {
                const DEBOUNCE_SECS: u64 = 5;
                if pending_time.elapsed().as_secs() >= DEBOUNCE_SECS {
                    // Debounce period elapsed - apply the latency
                    log::info!("Latency debounce complete, applying: {}ms", pending_value);
                    self.pending_latency = None;

                    // Only apply if still connected and value differs from last applied
                    if self.vpn_state.is_connected() && pending_value != self.last_applied_latency {
                        self.update_server_latency();
                        self.last_applied_latency = pending_value;
                    }
                }
            }

            // Update throughput history when connected
            self.update_throughput_history();

            // Update auth state only when timer fires (cheap but reduces lock contention)
            if let Ok(auth) = self.auth_manager.try_lock() {
                let new_state = auth.get_state();

                // Sync auth error from AuthState::Error for display
                if let AuthState::Error(ref msg) = new_state {
                    // Format user-friendly error messages
                    let user_friendly = match msg.as_str() {
                        m if m.contains("Invalid login credentials") => "Invalid email or password. Please try again.".to_string(),
                        m if m.contains("Email not confirmed") => "Please verify your email address before signing in.".to_string(),
                        m if m.contains("Network error") => "Unable to connect. Please check your internet connection.".to_string(),
                        m if m.contains("timeout") || m.contains("Timeout") => "Connection timed out. Please try again.".to_string(),
                        _ => msg.clone(),
                    };
                    self.auth_error = Some(user_friendly);
                } else if matches!(new_state, AuthState::LoggedIn(_)) {
                    // Clear error on successful login
                    self.auth_error = None;
                }

                self.auth_state = new_state;
                self.user_info = auth.get_user();
            }

            // Update server loading state and cache regions/latencies
            if let Ok(list) = self.dynamic_server_list.try_lock() {
                self.servers_loading = matches!(list.source, ServerListSource::Loading);
                self.server_list_source = list.source.clone();
                // Cache regions to avoid per-frame clone
                self.cached_regions = list.regions().to_vec();
            }

            // Cache latencies to avoid per-frame HashMap clone
            if let Ok(lat) = self.region_latencies.try_lock() {
                self.cached_latencies = lat.clone();
            }
        }

        // Clear old status
        if let Some((_, _, time)) = &self.status_message {
            if time.elapsed() > std::time::Duration::from_secs(4) {
                self.status_message = None;
            }
        }

        self.save_if_needed(ctx);

        // Auto-update check on startup (2 second delay to not block app startup)
        if !self.update_check_started && self.update_settings.auto_check {
            // Start update check after 2 seconds
            static START_TIME: std::sync::OnceLock<std::time::Instant> = std::sync::OnceLock::new();
            let start = START_TIME.get_or_init(std::time::Instant::now);
            if start.elapsed() >= std::time::Duration::from_secs(2) {
                self.update_check_started = true;
                self.start_update_check();
            }
        }

        // Poll Roblox watcher for game server detections (Bloxstrap-style)
        if let Some(ref watcher) = self.roblox_watcher {
            for event in watcher.poll() {
                match event {
                    RobloxEvent::GameServerDetected { ip } => {
                        if !self.detected_game_servers.contains(&ip) {
                            log::info!("Roblox game server detected: {}", ip);
                            self.detected_game_servers.insert(ip);

                            // Spawn async task to get location
                            let tx = self.game_server_location_tx.clone();
                            let runtime = Arc::clone(&self.runtime);
                            std::thread::spawn(move || {
                                runtime.block_on(async move {
                                    if let Some(location) = get_ip_location(ip).await {
                                        let _ = tx.send((ip, location));
                                    }
                                });
                            });
                        }
                    }
                }
            }
        }

        // Receive game server location lookups - show Windows toast notification (Bloxstrap-style)
        while let Ok((ip, location)) = self.game_server_location_rx.try_recv() {
            log::info!("Game server {} located: {}", ip, location);
            // Show Windows toast notification instead of in-app toast
            show_server_location(&location);
        }

        let is_logged_in = matches!(self.auth_state, AuthState::LoggedIn(_));
        let is_logging_in = matches!(self.auth_state, AuthState::LoggingIn);
        let is_awaiting_oauth = matches!(self.auth_state, AuthState::AwaitingOAuthCallback(_));

        egui::CentralPanel::default()
            .frame(egui::Frame::NONE.fill(BG_DARKEST))
            .show(ctx, |ui| {
                let available = ui.available_size();

                egui::ScrollArea::vertical()
                    .auto_shrink([false, false])
                    .show(ui, |ui| {
                        ui.set_min_width(available.x);
                        ui.add_space(16.0);

                        let side_margin = (available.x * 0.04).max(16.0).min(40.0);
                        let content_width = (available.x - side_margin * 2.0).max(480.0);

                        ui.horizontal(|ui| {
                            ui.add_space(side_margin);
                            ui.vertical(|ui| {
                                ui.set_max_width(content_width);

                                self.render_header(ui);
                                ui.add_space(24.0);

                                if !is_logged_in && !is_logging_in && !is_awaiting_oauth {
                                    self.render_full_login_screen(ui);
                                } else if is_logging_in {
                                    self.render_login_pending(ui);
                                } else if is_awaiting_oauth {
                                    self.render_awaiting_oauth_callback(ui);
                                } else {
                                    self.render_nav_tabs(ui);
                                    ui.add_space(20.0);

                                    match self.current_tab {
                                        Tab::Connect => self.render_connect_tab(ui),
                                        Tab::Boost => self.render_boost_tab(ui),
                                        Tab::Network => self.render_network_tab(ui),
                                        Tab::Settings => self.render_settings_tab(ui),
                                    }
                                }
                                ui.add_space(32.0);
                            });
                            ui.add_space(side_margin);
                        });
                    });
            });

        // Render process notification toast (overlay at top of screen)
        self.render_process_notification(ctx);
        // Game server notifications now use Windows toast via notification.rs
    }
}

// ═══════════════════════════════════════════════════════════════════════════════
//  CORE UI METHODS
// ═══════════════════════════════════════════════════════════════════════════════

impl BoosterApp {
    /// Render process detection notification toast at top of screen
    fn render_process_notification(&mut self, ctx: &egui::Context) {
        let should_show = if let Some((_, time)) = &self.process_notification {
            time.elapsed() < std::time::Duration::from_secs(3)
        } else {
            false
        };

        if should_show {
            if let Some((msg, time)) = &self.process_notification {
                // Calculate fade out animation
                let elapsed = time.elapsed().as_secs_f32();
                let alpha = if elapsed > 2.5 {
                    // Fade out in last 0.5 seconds
                    1.0 - ((elapsed - 2.5) / 0.5)
                } else {
                    1.0
                };

                egui::Area::new(egui::Id::new("process_notification"))
                    .anchor(egui::Align2::CENTER_TOP, [0.0, 60.0])
                    .order(egui::Order::Foreground)
                    .show(ctx, |ui| {
                        egui::Frame::NONE
                            .fill(STATUS_CONNECTED.gamma_multiply(0.9 * alpha))
                            .rounding(8.0)
                            .inner_margin(egui::Margin::symmetric(16, 10))
                            .shadow(egui::epaint::Shadow {
                                offset: [0, 2],
                                blur: 8,
                                spread: 0,
                                color: egui::Color32::from_black_alpha((40.0 * alpha) as u8),
                            })
                            .show(ui, |ui| {
                                ui.label(egui::RichText::new(msg)
                                    .color(egui::Color32::WHITE.gamma_multiply(alpha))
                                    .size(14.0)
                                    .strong());
                            });
                    });

                // Request repaint for animation
                ctx.request_repaint();
            }
        } else if self.process_notification.is_some() {
            // Clear expired notification
            self.process_notification = None;
        }
    }

    fn render_header(&self, ui: &mut egui::Ui) {
        // Header with subtle gradient background
        let header_rect = ui.allocate_exact_size(egui::vec2(ui.available_width(), 52.0), egui::Sense::hover()).0;

        // Subtle gradient line at bottom
        let line_rect = egui::Rect::from_min_size(
            egui::pos2(header_rect.min.x, header_rect.max.y - 1.0),
            egui::vec2(header_rect.width(), 1.0)
        );
        ui.painter().rect_filled(line_rect, 0.0, BG_ELEVATED);

        // Put cursor back at start
        ui.allocate_rect(header_rect, egui::Sense::hover());
        ui.put(header_rect, |ui: &mut egui::Ui| {
            ui.horizontal(|ui| {
                ui.spacing_mut().item_spacing.x = 0.0;

                // SwiftTunnel logo from embedded PNG
                let logo_size = 36.0;
                if let Some(texture) = &self.logo_texture {
                    let image = egui::Image::new(texture)
                        .fit_to_exact_size(egui::vec2(logo_size, logo_size))
                        .rounding(egui::CornerRadius::same(8));
                    ui.add(image);
                } else {
                    // Fallback: simple colored circle if texture failed to load
                    let (rect, _) = ui.allocate_exact_size(egui::vec2(logo_size, logo_size), egui::Sense::hover());
                    ui.painter().circle_filled(rect.center(), logo_size * 0.45, ACCENT_CYAN);
                }

                ui.add_space(12.0);

                // App name with subtle gradient text effect (approximated)
                ui.vertical(|ui| {
                    ui.spacing_mut().item_spacing.y = 0.0;
                    ui.label(egui::RichText::new("SwiftTunnel")
                        .size(20.0)
                        .color(TEXT_PRIMARY)
                        .strong());

                    // Subtitle
                    ui.label(egui::RichText::new("Game Booster")
                        .size(10.0)
                        .color(TEXT_DIMMED));
                });

                // Show boost count badge when on Connect or Settings tabs (not on Boost tab)
                if self.current_tab != Tab::Boost && self.state.optimizations_active {
                    let active_count = self.count_active_boosts();
                    if active_count > 0 {
                        ui.add_space(10.0);
                        egui::Frame::NONE
                            .fill(ACCENT_PRIMARY.gamma_multiply(0.15))
                            .stroke(egui::Stroke::new(1.0, ACCENT_PRIMARY.gamma_multiply(0.3)))
                            .rounding(12.0)
                            .inner_margin(egui::Margin::symmetric(10, 4))
                            .show(ui, |ui| {
                                ui.horizontal(|ui| {
                                    ui.spacing_mut().item_spacing.x = 4.0;
                                    ui.label(egui::RichText::new(">").size(10.0));
                                    ui.label(egui::RichText::new(format!("{} boosts", active_count))
                                        .size(11.0)
                                        .color(ACCENT_PRIMARY)
                                        .strong());
                                });
                            });
                    }
                }

                ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                    // Status badge with modern styling
                    let is_connected = self.vpn_state.is_connected();
                    let is_connecting = self.vpn_state.is_connecting();

                    let (status_text, status_color, show_pulse) = if is_connected {
                        ("PROTECTED", STATUS_CONNECTED, true)
                    } else if is_connecting {
                        ("CONNECTING", STATUS_WARNING, false)
                    } else {
                        ("OFFLINE", STATUS_INACTIVE, false)
                    };

                    // Status badge container
                    let badge_bg = if is_connected {
                        STATUS_CONNECTED.gamma_multiply(0.12)
                    } else if is_connecting {
                        STATUS_WARNING.gamma_multiply(0.12)
                    } else {
                        BG_ELEVATED
                    };

                    let badge_border = if is_connected {
                        STATUS_CONNECTED.gamma_multiply(0.3)
                    } else if is_connecting {
                        STATUS_WARNING.gamma_multiply(0.3)
                    } else {
                        BG_HOVER
                    };

                    egui::Frame::NONE
                        .fill(badge_bg)
                        .stroke(egui::Stroke::new(1.0, badge_border))
                        .rounding(14.0)
                        .inner_margin(egui::Margin::symmetric(12, 6))
                        .show(ui, |ui| {
                            ui.horizontal(|ui| {
                                ui.spacing_mut().item_spacing.x = 6.0;

                                // Animated indicator
                                let indicator_size = 8.0;
                                let (indicator_rect, _) = ui.allocate_exact_size(egui::vec2(indicator_size, indicator_size), egui::Sense::hover());

                                if show_pulse {
                                    // Breathing pulse animation
                                    let elapsed = self.app_start_time.elapsed().as_secs_f32();
                                    let pulse = ((elapsed * std::f32::consts::PI / PULSE_ANIMATION_DURATION).sin() + 1.0) / 2.0;
                                    let glow_radius = 3.0 + pulse * 2.0;
                                    let glow_alpha = 0.4 + pulse * 0.3;

                                    ui.painter().circle_filled(indicator_rect.center(), glow_radius, status_color.gamma_multiply(glow_alpha));
                                    ui.painter().circle_filled(indicator_rect.center(), 3.0, status_color);
                                } else if is_connecting {
                                    // Spinning indicator for connecting
                                    let elapsed = self.app_start_time.elapsed().as_secs_f32();
                                    let angle = elapsed * 4.0;
                                    for i in 0..3 {
                                        let a = angle + i as f32 * std::f32::consts::TAU / 3.0;
                                        let r = 3.0;
                                        let pos = egui::pos2(
                                            indicator_rect.center().x + a.cos() * r,
                                            indicator_rect.center().y + a.sin() * r
                                        );
                                        let alpha = 0.3 + (1.0 - i as f32 / 3.0) * 0.7;
                                        ui.painter().circle_filled(pos, 1.5, status_color.gamma_multiply(alpha));
                                    }
                                } else {
                                    ui.painter().circle_filled(indicator_rect.center(), 3.0, status_color);
                                }

                                ui.label(egui::RichText::new(status_text)
                                    .size(11.0)
                                    .color(status_color)
                                    .strong());
                            });
                        });
                });
            }).response
        });
    }

    /// Count how many boosts are currently enabled
    fn count_active_boosts(&self) -> usize {
        let sys = &self.state.config.system_optimization;
        let net = &self.state.config.network_settings;
        let mut count = 0;
        if sys.set_high_priority { count += 1; }
        if sys.timer_resolution_1ms { count += 1; }
        if sys.mmcss_gaming_profile { count += 1; }
        if sys.game_mode_enabled { count += 1; }
        if net.disable_nagle { count += 1; }
        if net.disable_network_throttling { count += 1; }
        if net.optimize_mtu { count += 1; }
        count
    }

    fn render_nav_tabs(&mut self, ui: &mut egui::Ui) {
        // Tab container with subtle background
        egui::Frame::NONE
            .fill(BG_CARD)
            .rounding(12.0)
            .inner_margin(egui::Margin::symmetric(4, 4))
            .show(ui, |ui| {
                ui.horizontal(|ui| {
                    ui.spacing_mut().item_spacing.x = 4.0;

                    let tabs = [
                        ("o", "Connect", Tab::Connect),
                        (">", "Boost", Tab::Boost),
                        ("::", "Network", Tab::Network),
                        ("*", "Settings", Tab::Settings),
                    ];

                    for (icon, label, tab) in tabs {
                        let is_active = self.current_tab == tab;
                        let tab_id = format!("tab_{:?}", tab);
                        let hover_val = self.animations.get_hover_value(&tab_id);

                        // Calculate colors with hover effect
                        let (bg, text_color, _icon_color) = if is_active {
                            (ACCENT_PRIMARY, TEXT_PRIMARY, TEXT_PRIMARY)
                        } else {
                            let hover_bg = lerp_color(egui::Color32::TRANSPARENT, BG_ELEVATED, hover_val);
                            let hover_text = lerp_color(TEXT_SECONDARY, TEXT_PRIMARY, hover_val);
                            (hover_bg, hover_text, TEXT_MUTED)
                        };

                        let response = ui.add(
                            egui::Button::new(
                                egui::RichText::new(format!("{} {}", icon, label))
                                    .size(13.0)
                                    .color(text_color)
                            )
                            .fill(bg)
                            .stroke(if is_active {
                                egui::Stroke::NONE
                            } else {
                                egui::Stroke::new(0.0, egui::Color32::TRANSPARENT)
                            })
                            .rounding(10.0)
                            .min_size(egui::vec2(95.0, 38.0))
                        );

                        // Handle hover for animation
                        self.animations.animate_hover(&tab_id, response.hovered(), hover_val);

                        if response.clicked() {
                            self.current_tab = tab;
                            self.mark_dirty();
                        }
                    }
                });
            });
    }
}

// ═══════════════════════════════════════════════════════════════════════════════
//  AUTH METHODS
// ═══════════════════════════════════════════════════════════════════════════════

impl BoosterApp {
    pub(crate) fn start_login(&mut self) {
        self.auth_error = None;
        let email = self.login_email.clone();
        let password = self.login_password.clone();
        let auth_manager = Arc::clone(&self.auth_manager);
        let rt = Arc::clone(&self.runtime);
        let tx = self.auth_update_tx.clone();
        self.login_password.clear();

        std::thread::spawn(move || {
            rt.block_on(async {
                if let Ok(auth) = auth_manager.lock() {
                    match auth.sign_in(&email, &password).await {
                        Ok(()) => {
                            // Send updated state immediately to GUI
                            let new_state = auth.get_state();
                            let _ = tx.send(new_state);
                            log::info!("Login completed, notified GUI");
                        }
                        Err(e) => {
                            log::error!("Sign in failed: {}", e);
                            let _ = tx.send(AuthState::Error(e.to_string()));
                        }
                    }
                }
            });
        });
    }

    pub(crate) fn start_google_login(&mut self) {
        self.auth_error = None;
        if let Ok(auth) = self.auth_manager.lock() {
            if let Err(e) = auth.start_google_sign_in() {
                self.auth_error = Some(e.to_string());
            }
        }
    }

    pub(crate) fn cancel_google_login(&mut self) {
        if let Ok(auth) = self.auth_manager.lock() {
            auth.cancel_oauth();
        }
        self.auth_error = None;
    }

    /// Process OAuth callback from deep link
    /// Called when the app is launched with swifttunnel://callback?token=xxx&state=xxx
    pub fn process_oauth_callback(&mut self, token: &str, state: &str) {
        log::info!("Processing OAuth callback");
        self.auth_error = None;

        let auth_manager = Arc::clone(&self.auth_manager);
        let rt = Arc::clone(&self.runtime);
        let token = token.to_string();
        let state = state.to_string();
        let tx = self.auth_update_tx.clone();

        std::thread::spawn(move || {
            rt.block_on(async {
                if let Ok(auth) = auth_manager.lock() {
                    match auth.complete_oauth_callback(&token, &state).await {
                        Ok(()) => {
                            // Send updated state immediately to GUI
                            let new_state = auth.get_state();
                            let _ = tx.send(new_state);
                            log::info!("OAuth callback completed, notified GUI");
                        }
                        Err(e) => {
                            log::error!("OAuth callback failed: {}", e);
                            let _ = tx.send(AuthState::Error(e.to_string()));
                        }
                    }
                }
            });
        });
    }

    pub(crate) fn logout(&mut self) {
        if let Ok(auth) = self.auth_manager.lock() {
            let _ = auth.logout();
        }
        self.auth_state = AuthState::LoggedOut;
        self.user_info = None;
        self.auth_error = None;
        self.login_email.clear();
        self.login_password.clear();
        self.set_status("Signed out", STATUS_CONNECTED);
    }
}

// ═══════════════════════════════════════════════════════════════════════════════
//  VPN METHODS
// ═══════════════════════════════════════════════════════════════════════════════

impl BoosterApp {
    pub(crate) fn connect_vpn(&mut self) {
        // Set instant feedback - show connecting animation immediately
        // This avoids the 500ms delay before VPN state polling catches up
        self.connecting_initiated = Some(std::time::Instant::now());

        // Check if running as administrator - required for ETW and WFP
        // If not admin, we need to relaunch elevated to avoid split tunnel bypass
        if !is_administrator() {
            log::info!("Not running as administrator, need to elevate for reliable split tunnel");
            self.set_status("Requesting admin access...", STATUS_WARNING);

            // Check if at least one game preset is selected before elevating
            if self.selected_game_presets.is_empty() {
                self.set_status("Please select at least one game", STATUS_WARNING);
                self.connecting_initiated = None;
                return;
            }

            // Get apps from selected game presets for pending connection
            let apps: Vec<String> = get_apps_for_preset_set(&self.selected_game_presets)
                .iter()
                .map(|s| s.to_string())
                .collect();

            // Determine which server to use
            let server = if let Some(forced_server) = self.forced_servers.get(&self.selected_region) {
                forced_server.clone()
            } else if let Ok(latencies) = self.region_latencies.try_lock() {
                latencies.get(&self.selected_region)
                    .map(|(id, _)| id.clone())
                    .unwrap_or_else(|| self.selected_server.clone())
            } else {
                self.selected_server.clone()
            };

            // Save pending connection for elevated process
            let pending = PendingConnection {
                region: self.selected_region.clone(),
                server,
                apps,
                routing_mode: match self.routing_mode {
                    crate::settings::RoutingMode::V1 => 0,
                    crate::settings::RoutingMode::V2 => 1,
                },
                timestamp: std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .map(|d| d.as_secs())
                    .unwrap_or(0),
            };

            if let Err(e) = save_pending_connection(&pending) {
                log::error!("Failed to save pending connection: {}", e);
                self.set_status("Failed to prepare for elevation", STATUS_ERROR);
                self.connecting_initiated = None;
                return;
            }

            // Attempt to relaunch elevated
            match relaunch_elevated() {
                Ok(()) => {
                    log::info!("Elevated process launched, exiting current instance");
                    // Exit the current non-elevated process
                    // The elevated process will auto-connect using pending connection
                    std::process::exit(0);
                }
                Err(e) => {
                    log::error!("Failed to elevate: {}", e);
                    // UAC was probably cancelled - show message and continue as non-admin
                    self.set_status("Admin access required for reliable VPN", STATUS_ERROR);
                    self.connecting_initiated = None;
                    // Delete the pending connection file since we're not elevating
                    let _ = std::fs::remove_file(pending_connection_path());
                    return;
                }
            }
        }

        // We're running as administrator - proceed with connection
        log::info!("Running as administrator, proceeding with VPN connection");

        // Refresh token silently before connecting (handles expired sessions)
        let auth_manager = Arc::clone(&self.auth_manager);
        let rt = Arc::clone(&self.runtime);

        // Try to refresh token if needed
        let access_token = {
            let refresh_result = rt.block_on(async {
                if let Ok(auth) = auth_manager.lock() {
                    // This will refresh if expired/expiring
                    auth.get_access_token().await
                } else {
                    Err(crate::auth::types::AuthError::ApiError("Lock failed".to_string()))
                }
            });

            match refresh_result {
                Ok(token) => token,
                Err(e) => {
                    log::warn!("Token refresh failed: {}, trying with existing token", e);
                    // Fall back to existing token from session
                    if let AuthState::LoggedIn(session) = &self.auth_state {
                        session.access_token.clone()
                    } else {
                        self.set_status("Please sign in first", STATUS_ERROR);
                        self.connecting_initiated = None;
                        return;
                    }
                }
            }
        };

        // Check if at least one game preset is selected
        if self.selected_game_presets.is_empty() {
            self.set_status("Please select at least one game", STATUS_WARNING);
            self.connecting_initiated = None;
            return;
        }

        // Determine which server to use:
        // 1. If user has forced a specific server for this region, use that
        // 2. Otherwise, use the best server based on latency measurements
        // 3. Fall back to selected_server if no latency data exists
        let region = if let Some(forced_server) = self.forced_servers.get(&self.selected_region) {
            log::info!(
                "Using forced server '{}' for region '{}' (user override)",
                forced_server, self.selected_region
            );
            forced_server.clone()
        } else if let Ok(latencies) = self.region_latencies.try_lock() {
            if let Some((best_server_id, latency)) = latencies.get(&self.selected_region) {
                log::info!(
                    "Using best server '{}' ({}ms) for region '{}'",
                    best_server_id, latency, self.selected_region
                );
                best_server_id.clone()
            } else {
                log::info!(
                    "No latency data for region '{}', using default server '{}'",
                    self.selected_region, self.selected_server
                );
                self.selected_server.clone()
            }
        } else {
            log::warn!("Could not acquire latencies lock, using default server");
            self.selected_server.clone()
        };

        // Get apps from selected game presets
        let apps = get_apps_for_preset_set(&self.selected_game_presets);
        log::info!("Connecting to server '{}' with split tunnel apps: {:?}", region, apps);

        let vpn = Arc::clone(&self.vpn_connection);
        let rt = Arc::clone(&self.runtime);
        let routing_mode = self.routing_mode;

        // Clear previously tunneled set when starting a new connection
        self.previously_tunneled.clear();

        std::thread::spawn(move || {
            rt.block_on(async {
                if let Ok(mut connection) = vpn.lock() {
                    if let Err(e) = connection.connect(&access_token, &region, apps, routing_mode).await {
                        log::error!("VPN connection failed: {}", e);
                    }
                }
            });
        });
    }

    pub(crate) fn disconnect_vpn(&mut self) {
        let vpn = Arc::clone(&self.vpn_connection);
        let rt = Arc::clone(&self.runtime);

        std::thread::spawn(move || {
            rt.block_on(async {
                if let Ok(mut connection) = vpn.lock() {
                    if let Err(e) = connection.disconnect().await {
                        log::error!("VPN disconnect failed: {}", e);
                    }
                }
            });
        });
    }

    /// Disconnect VPN synchronously (blocks until complete)
    /// Used when quitting the app to ensure proper cleanup
    /// Includes a 3-second timeout to prevent hanging on quit
    pub(crate) fn disconnect_vpn_sync(&mut self) {
        if !self.vpn_state.is_connected() && !self.vpn_state.is_connecting() {
            return;
        }

        log::info!("Disconnecting VPN before quit...");

        let vpn = Arc::clone(&self.vpn_connection);
        let rt = Arc::clone(&self.runtime);

        // Use timeout to prevent hanging on quit - max 3 seconds
        let disconnect_result = rt.block_on(async {
            tokio::time::timeout(std::time::Duration::from_secs(3), async {
                if let Ok(mut connection) = vpn.lock() {
                    connection.disconnect().await
                } else {
                    Err(crate::vpn::VpnError::Connection("Failed to acquire VPN lock".to_string()))
                }
            }).await
        });

        match disconnect_result {
            Ok(Ok(_)) => log::info!("VPN disconnected successfully before quit"),
            Ok(Err(e)) => log::warn!("VPN disconnect failed: {} - forcing quit anyway", e),
            Err(_) => log::warn!("VPN disconnect timed out after 3s - forcing quit anyway"),
        }

        // Brief cleanup delay
        std::thread::sleep(std::time::Duration::from_millis(200));
    }

    pub(crate) fn retry_load_servers(&mut self) {
        if let Ok(mut list) = self.dynamic_server_list.lock() {
            *list = DynamicServerList::new_empty();
        }
        self.servers_loading = true;
        self.server_list_source = ServerListSource::Loading;

        let server_list_clone = Arc::clone(&self.dynamic_server_list);
        let latencies_clone = Arc::clone(&self.region_latencies);
        let finding_clone = Arc::clone(&self.finding_best_server);
        let rt = Arc::clone(&self.runtime);

        std::thread::spawn(move || {
            rt.block_on(async {
                match load_server_list().await {
                    Ok((servers, regions, source)) => {
                        log::info!("Server list reloaded from {}", source);
                        if let Ok(mut list) = server_list_clone.lock() {
                            list.update(servers.clone(), regions.clone(), source);
                        }

                        // Re-measure latencies
                        finding_clone.store(true, Ordering::SeqCst);
                        for region in &regions {
                            let server_ips: Vec<(String, String)> = region.servers.iter()
                                .filter_map(|server_id| {
                                    servers.iter()
                                        .find(|s| &s.region == server_id)
                                        .map(|s| (server_id.clone(), s.ip.clone()))
                                })
                                .collect();

                            log::info!("Re-pinging region '{}' with {} servers", region.id, server_ips.len());

                            if let Some((best_server_id, latency)) = ping_region_async(&server_ips).await {
                                if let Ok(mut lat) = latencies_clone.lock() {
                                    lat.insert(region.id.clone(), (best_server_id.clone(), latency));
                                    log::info!("Region {} best server: {} ({}ms)", region.id, best_server_id, latency);
                                } else {
                                    log::error!("Region '{}' failed to store latency - mutex poisoned", region.id);
                                }
                            } else {
                                log::warn!("Region '{}' re-ping failed - no servers responded", region.id);
                            }
                        }
                        finding_clone.store(false, Ordering::SeqCst);
                    }
                    Err(e) => {
                        log::error!("Failed to reload server list: {}", e);
                        if let Ok(mut list) = server_list_clone.lock() {
                            *list = DynamicServerList::new_error(e);
                        }
                    }
                }
            });
        });
    }
}

// ═══════════════════════════════════════════════════════════════════════════════
//  OPTIMIZATION METHODS
// ═══════════════════════════════════════════════════════════════════════════════

impl BoosterApp {
    pub(crate) fn toggle_optimizations(&mut self) {
        if self.state.optimizations_active {
            // Disabling optimizations - restore original Roblox settings
            match self.roblox_optimizer.restore_settings() {
                Ok(_) => {
                    self.state.optimizations_active = false;
                    self.set_status("Optimizations disabled - Roblox settings restored", STATUS_WARNING);
                    log::info!("Optimizations disabled, Roblox settings restored from backup");
                }
                Err(e) => {
                    // Still disable even if restore fails (file might be missing)
                    self.state.optimizations_active = false;
                    log::warn!("Could not restore Roblox settings: {}", e);
                    self.set_status("Optimizations disabled (backup not found)", STATUS_WARNING);
                }
            }
        } else {
            // Enabling optimizations - apply Roblox settings
            match self.roblox_optimizer.apply_optimizations(&self.state.config.roblox_settings) {
                Ok(_) => {
                    self.state.optimizations_active = true;
                    self.set_status("Optimizations enabled!", STATUS_CONNECTED);
                }
                Err(e) => {
                    self.set_status(&format!("Error: {}", e), STATUS_ERROR);
                }
            }
        }
        self.mark_dirty();
    }

    pub(crate) fn apply_profile_preset(&mut self) {
        match self.selected_profile {
            OptimizationProfile::LowEnd => {
                self.state.config.roblox_settings.graphics_quality = GraphicsQuality::Level1;
                self.state.config.roblox_settings.target_fps = 60;
                self.state.config.system_optimization.set_high_priority = true;
                self.state.config.system_optimization.power_plan = PowerPlan::HighPerformance;
            }
            OptimizationProfile::Balanced => {
                self.state.config.roblox_settings.graphics_quality = GraphicsQuality::Level5;
                self.state.config.roblox_settings.target_fps = 144;
                self.state.config.system_optimization.set_high_priority = true;
                self.state.config.system_optimization.power_plan = PowerPlan::HighPerformance;
            }
            OptimizationProfile::HighEnd => {
                self.state.config.roblox_settings.graphics_quality = GraphicsQuality::Level10;
                self.state.config.roblox_settings.target_fps = 240;
                self.state.config.system_optimization.set_high_priority = false;
                self.state.config.system_optimization.power_plan = PowerPlan::HighPerformance;
            }
            OptimizationProfile::Custom => {}
        }
        self.state.config.profile = self.selected_profile;
    }
}

// ═══════════════════════════════════════════════════════════════════════════════
//  AUTO-UPDATER METHODS
// ═══════════════════════════════════════════════════════════════════════════════

impl BoosterApp {
    /// Render the update banner at the top of the Connect tab
    pub(crate) fn render_update_banner(&mut self, ui: &mut egui::Ui) {
        let state = match self.update_state.lock() {
            Ok(s) => s.clone(),
            Err(_) => return,
        };

        // Don't show banner for Idle, UpToDate, or Checking states
        match &state {
            UpdateState::Idle | UpdateState::UpToDate | UpdateState::Checking => return,
            UpdateState::Failed(msg) => {
                // Show error banner briefly, then hide
                egui::Frame::NONE
                    .fill(STATUS_ERROR.gamma_multiply(0.15))
                    .stroke(egui::Stroke::new(1.0, STATUS_ERROR.gamma_multiply(0.3)))
                    .rounding(8.0)
                    .inner_margin(12)
                    .show(ui, |ui| {
                        ui.horizontal(|ui| {
                            ui.label(egui::RichText::new("!").size(14.0).color(STATUS_ERROR));
                            ui.add_space(8.0);
                            ui.label(egui::RichText::new(format!("Update failed: {}", msg))
                                .size(13.0).color(TEXT_PRIMARY));
                        });
                    });
            }
            _ => {
                egui::Frame::NONE
                    .fill(ACCENT_PRIMARY.gamma_multiply(0.15))
                    .stroke(egui::Stroke::new(1.0, ACCENT_PRIMARY.gamma_multiply(0.3)))
                    .rounding(8.0)
                    .inner_margin(12)
                    .show(ui, |ui| {
                        match &state {
                            UpdateState::Available(info) => {
                                // Check if this version was dismissed
                                if self.update_settings.dismissed_version.as_ref() == Some(&info.version) {
                                    return;
                                }
                                ui.horizontal(|ui| {
                                    ui.label(egui::RichText::new("+").size(14.0).color(ACCENT_PRIMARY));
                                    ui.add_space(8.0);
                                    ui.label(egui::RichText::new(format!("Update v{} available", info.version))
                                        .size(13.0).color(TEXT_PRIMARY).strong());
                                    ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                                        if ui.add(egui::Button::new(
                                            egui::RichText::new("x").size(12.0).color(TEXT_MUTED)
                                        ).fill(egui::Color32::TRANSPARENT).stroke(egui::Stroke::NONE)).clicked() {
                                            self.dismiss_update(&info.version.clone());
                                        }
                                        ui.add_space(8.0);
                                        if ui.add(egui::Button::new(
                                            egui::RichText::new("Download").size(11.0).color(TEXT_PRIMARY)
                                        ).fill(ACCENT_PRIMARY).rounding(4.0)).clicked() {
                                            self.start_update_download(info.clone());
                                        }
                                    });
                                });
                            }
                            UpdateState::Downloading { info, progress, downloaded, total } => {
                                ui.horizontal(|ui| {
                                    ui.spinner();
                                    ui.add_space(8.0);
                                    let downloaded_mb = *downloaded as f64 / (1024.0 * 1024.0);
                                    let total_mb = *total as f64 / (1024.0 * 1024.0);
                                    ui.label(egui::RichText::new(format!(
                                        "Downloading v{}... {:.1}/{:.1} MB ({:.0}%)",
                                        info.version, downloaded_mb, total_mb, progress * 100.0
                                    )).size(13.0).color(TEXT_PRIMARY));
                                });
                            }
                            UpdateState::Verifying(info) => {
                                ui.horizontal(|ui| {
                                    ui.spinner();
                                    ui.add_space(8.0);
                                    ui.label(egui::RichText::new(format!("Verifying v{}...", info.version))
                                        .size(13.0).color(TEXT_PRIMARY));
                                });
                            }
                            UpdateState::ReadyToInstall { info, .. } => {
                                ui.horizontal(|ui| {
                                    ui.label(egui::RichText::new("+").size(14.0).color(STATUS_CONNECTED));
                                    ui.add_space(8.0);
                                    ui.label(egui::RichText::new(format!("v{} ready to install", info.version))
                                        .size(13.0).color(TEXT_PRIMARY).strong());
                                    ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                                        if ui.add(egui::Button::new(
                                            egui::RichText::new("Install Now").size(11.0).color(TEXT_PRIMARY)
                                        ).fill(STATUS_CONNECTED).rounding(4.0)).clicked() {
                                            self.trigger_update_install();
                                        }
                                    });
                                });
                            }
                            UpdateState::Installing => {
                                ui.horizontal(|ui| {
                                    ui.spinner();
                                    ui.add_space(8.0);
                                    ui.label(egui::RichText::new("Installing update... App will restart.")
                                        .size(13.0).color(TEXT_PRIMARY));
                                });
                            }
                            _ => {}
                        }
                    });
            }
        }

        ui.add_space(12.0);
    }

    /// Start checking for updates in the background
    pub(crate) fn start_update_check(&mut self) {
        // Set state to Checking
        if let Ok(mut state) = self.update_state.lock() {
            *state = UpdateState::Checking;
        }

        let update_state = Arc::clone(&self.update_state);
        let rt = Arc::clone(&self.runtime);

        std::thread::spawn(move || {
            rt.block_on(async {
                let checker = match UpdateChecker::new() {
                    Some(c) => c,
                    None => {
                        log::error!("Update checker failed to initialize - version parsing issue");
                        if let Ok(mut state) = update_state.lock() {
                            *state = UpdateState::Failed("Version parsing error".to_string());
                        }
                        return;
                    }
                };
                match checker.check_for_update().await {
                    Ok(Some(info)) => {
                        log::info!("Update available: v{}", info.version);
                        if let Ok(mut state) = update_state.lock() {
                            *state = UpdateState::Available(info);
                        }
                    }
                    Ok(None) => {
                        log::info!("Already on latest version");
                        if let Ok(mut state) = update_state.lock() {
                            *state = UpdateState::UpToDate;
                        }
                    }
                    Err(e) => {
                        log::error!("Update check failed: {}", e);
                        if let Ok(mut state) = update_state.lock() {
                            *state = UpdateState::Failed(e);
                        }
                    }
                }
            });
        });
    }

    /// Start downloading an update in the background
    fn start_update_download(&mut self, info: UpdateInfo) {
        let update_state = Arc::clone(&self.update_state);
        let rt = Arc::clone(&self.runtime);

        // Set initial downloading state
        if let Ok(mut state) = update_state.lock() {
            *state = UpdateState::Downloading {
                info: info.clone(),
                progress: 0.0,
                downloaded: 0,
                total: info.size,
            };
        }

        std::thread::spawn(move || {
            rt.block_on(async {
                // Generate filename from URL
                let filename = info.download_url
                    .split('/')
                    .last()
                    .unwrap_or("SwiftTunnel-update.msi")
                    .to_string();

                // Progress callback to update state
                let progress_state = Arc::clone(&update_state);
                let info_clone = info.clone();
                let on_progress: Box<dyn Fn(u64, u64) + Send + Sync> = Box::new(move |downloaded, total| {
                    let progress = if total > 0 { downloaded as f32 / total as f32 } else { 0.0 };
                    if let Ok(mut state) = progress_state.lock() {
                        *state = UpdateState::Downloading {
                            info: info_clone.clone(),
                            progress,
                            downloaded,
                            total,
                        };
                    }
                });

                // Download the MSI
                match download_update(&info.download_url, &filename, Some(on_progress)).await {
                    Ok(msi_path) => {
                        log::info!("Download complete: {}", msi_path.display());

                        // Set verifying state
                        if let Ok(mut state) = update_state.lock() {
                            *state = UpdateState::Verifying(info.clone());
                        }

                        // Verify checksum if available
                        let verified = if let Some(ref checksum_url) = info.checksum_url {
                            match download_checksum(checksum_url).await {
                                Ok(expected) => {
                                    match verify_checksum(&msi_path, &expected).await {
                                        Ok(true) => true,
                                        Ok(false) => {
                                            log::error!("Checksum verification failed!");
                                            // Delete the bad file
                                            let _ = tokio::fs::remove_file(&msi_path).await;
                                            if let Ok(mut state) = update_state.lock() {
                                                *state = UpdateState::Failed("Checksum verification failed. Download corrupted.".to_string());
                                            }
                                            return;
                                        }
                                        Err(e) => {
                                            log::error!("Checksum error: {}", e);
                                            // Continue anyway if we can't verify
                                            true
                                        }
                                    }
                                }
                                Err(e) => {
                                    log::warn!("Could not download checksum: {}", e);
                                    // Continue anyway if no checksum available
                                    true
                                }
                            }
                        } else {
                            log::warn!("No checksum file available, skipping verification");
                            true
                        };

                        if verified {
                            if let Ok(mut state) = update_state.lock() {
                                *state = UpdateState::ReadyToInstall {
                                    info: info.clone(),
                                    msi_path,
                                };
                            }
                        }
                    }
                    Err(e) => {
                        log::error!("Download failed: {}", e);
                        if let Ok(mut state) = update_state.lock() {
                            *state = UpdateState::Failed(e);
                        }
                    }
                }
            });
        });
    }

    /// Trigger the update installation
    fn trigger_update_install(&mut self) {
        let msi_path = match self.update_state.lock() {
            Ok(state) => {
                if let UpdateState::ReadyToInstall { msi_path, .. } = &*state {
                    msi_path.clone()
                } else {
                    return;
                }
            }
            Err(_) => return,
        };

        // Set installing state
        if let Ok(mut state) = self.update_state.lock() {
            *state = UpdateState::Installing;
        }

        // Disconnect VPN before exiting for update
        self.disconnect_vpn_sync();

        // Run installation
        match install_update(&msi_path) {
            Ok(()) => {
                log::info!("Update installer launched, exiting app...");
                // Exit the app to allow installer to run
                std::process::exit(0);
            }
            Err(e) => {
                log::error!("Failed to start installer: {}", e);
                if let Ok(mut state) = self.update_state.lock() {
                    *state = UpdateState::Failed(e);
                }
            }
        }
    }

    /// Dismiss the update banner for a specific version
    fn dismiss_update(&mut self, version: &str) {
        self.update_settings.dismissed_version = Some(version.to_string());
        self.mark_dirty();
    }

    /// Update server with current latency setting
    pub(crate) fn update_server_latency(&mut self) {
        log::info!("update_server_latency() called, latency_ms={}", self.artificial_latency_ms);

        // Need config ID and access token
        let config_id = match &self.current_config_id {
            Some(id) if !id.is_empty() => {
                log::info!("Using config ID: {}", id);
                id.clone()
            }
            Some(_) => {
                log::warn!("Cannot update latency: config ID is empty");
                return;
            }
            None => {
                log::warn!("Cannot update latency: no config ID");
                return;
            }
        };

        let access_token = match &self.auth_state {
            AuthState::LoggedIn(session) => session.access_token.clone(),
            _ => {
                log::warn!("Cannot update latency: not logged in");
                return;
            }
        };

        let latency_ms = self.artificial_latency_ms;
        let rt = Arc::clone(&self.runtime);

        self.updating_latency = true;

        // Spawn async task to update latency
        log::info!("Spawning latency update task: config_id={}, latency_ms={}", config_id, latency_ms);
        std::thread::spawn(move || {
            rt.block_on(async {
                log::info!("Calling update_latency API...");
                match crate::vpn::update_latency(&access_token, &config_id, latency_ms).await {
                    Ok(server_applied) => {
                        if server_applied {
                            log::info!("Latency +{}ms applied to server successfully", latency_ms);
                        } else {
                            log::info!("Latency +{}ms saved, will apply on reconnect", latency_ms);
                        }
                    }
                    Err(e) => {
                        log::error!("Failed to update latency: {}", e);
                    }
                }
            });
        });

        // Note: updating_latency flag will be cleared on next state check
        // For now, just set it false after a short delay
        self.updating_latency = false;
    }
}
