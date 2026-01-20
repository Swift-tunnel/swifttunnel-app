use crate::auth::{AuthManager, AuthState, UserInfo};
use crate::hidden_command;
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
use crate::vpn::{ConnectionState, VpnConnection, DynamicServerList, DynamicGamingRegion, load_server_list, ServerListSource, GamePreset, get_apps_for_preset_set};
use eframe::egui;
use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::sync::atomic::{AtomicBool, Ordering};

// ═══════════════════════════════════════════════════════════════════════════════
//  SWIFTTUNNEL DESIGN SYSTEM v5
//  Deep Blue - Dark theme with blue/cyan accents + modern glass effects
//  Enhanced visual hierarchy with gradients and micro-animations
// ═══════════════════════════════════════════════════════════════════════════════

// Base backgrounds - refined for better depth
const BG_DARKEST: egui::Color32 = egui::Color32::from_rgb(6, 9, 18);        // Deeper blue-black
const BG_CARD: egui::Color32 = egui::Color32::from_rgb(12, 17, 28);         // Subtle card bg
const BG_ELEVATED: egui::Color32 = egui::Color32::from_rgb(20, 26, 40);     // Elevated surfaces
const BG_HOVER: egui::Color32 = egui::Color32::from_rgb(28, 36, 52);        // Hover state
const BG_INPUT: egui::Color32 = egui::Color32::from_rgb(14, 20, 32);        // Input field background

// Gradient accent colors - for modern visual depth
const GRADIENT_START: egui::Color32 = egui::Color32::from_rgb(59, 130, 246);   // Blue
const GRADIENT_END: egui::Color32 = egui::Color32::from_rgb(139, 92, 246);     // Purple/violet
const GRADIENT_CYAN_START: egui::Color32 = egui::Color32::from_rgb(34, 211, 238); // Cyan
const GRADIENT_CYAN_END: egui::Color32 = egui::Color32::from_rgb(52, 211, 153);   // Emerald

// Primary accents
const ACCENT_PRIMARY: egui::Color32 = egui::Color32::from_rgb(59, 130, 246);   // Blue accent (#3b82f6)
const ACCENT_SECONDARY: egui::Color32 = egui::Color32::from_rgb(139, 92, 246); // Violet (#8b5cf6)
const ACCENT_CYAN: egui::Color32 = egui::Color32::from_rgb(34, 211, 238);      // Cyan for highlights (#22d3ee)

// Status colors - more vibrant
const STATUS_CONNECTED: egui::Color32 = egui::Color32::from_rgb(52, 211, 153);   // Emerald
const STATUS_CONNECTED_GLOW: egui::Color32 = egui::Color32::from_rgb(110, 231, 183); // Brighter for glow
const STATUS_WARNING: egui::Color32 = egui::Color32::from_rgb(251, 191, 36);
const STATUS_ERROR: egui::Color32 = egui::Color32::from_rgb(248, 113, 113);
const STATUS_INACTIVE: egui::Color32 = egui::Color32::from_rgb(75, 85, 99);     // Slate-600

// Text hierarchy - improved contrast
const TEXT_PRIMARY: egui::Color32 = egui::Color32::from_rgb(248, 250, 252);     // Near white
const TEXT_SECONDARY: egui::Color32 = egui::Color32::from_rgb(148, 163, 184);   // slate-400
const TEXT_MUTED: egui::Color32 = egui::Color32::from_rgb(100, 116, 139);       // slate-500
const TEXT_DIMMED: egui::Color32 = egui::Color32::from_rgb(71, 85, 105);        // slate-600

// Latency color thresholds
const LATENCY_EXCELLENT: egui::Color32 = egui::Color32::from_rgb(52, 211, 153);  // < 30ms
const LATENCY_GOOD: egui::Color32 = egui::Color32::from_rgb(163, 230, 53);       // < 60ms (lime)
const LATENCY_FAIR: egui::Color32 = egui::Color32::from_rgb(251, 191, 36);       // < 100ms (yellow)
const LATENCY_POOR: egui::Color32 = egui::Color32::from_rgb(251, 146, 60);       // < 150ms (orange)
const LATENCY_BAD: egui::Color32 = egui::Color32::from_rgb(248, 113, 113);       // >= 150ms (red)

// ═══════════════════════════════════════════════════════════════════════════════
//  ANIMATION SYSTEM
// ═══════════════════════════════════════════════════════════════════════════════

const TOGGLE_ANIMATION_DURATION: f32 = 0.15;   // 150ms for toggle switches
const PULSE_ANIMATION_DURATION: f32 = 2.0;      // 2s breathing cycle for connected pulse
const HOVER_ANIMATION_DURATION: f32 = 0.1;      // 100ms for hover effects
const SHIMMER_ANIMATION_DURATION: f32 = 1.5;    // 1.5s for skeleton shimmer
const CARD_TRANSITION_DURATION: f32 = 0.2;      // 200ms for card state changes
const BUTTON_PRESS_DURATION: f32 = 0.08;        // 80ms for button press feedback

/// Ease-out-cubic interpolation for smooth animations
fn ease_out_cubic(t: f32) -> f32 {
    let t = t.clamp(0.0, 1.0);
    1.0 - (1.0 - t).powi(3)
}

/// Ease-in-out for shimmer effects
fn ease_in_out_sine(t: f32) -> f32 {
    let t = t.clamp(0.0, 1.0);
    -(((t * std::f32::consts::PI).cos() - 1.0) / 2.0)
}

/// Interpolate between two colors
fn lerp_color(from: egui::Color32, to: egui::Color32, t: f32) -> egui::Color32 {
    let t = t.clamp(0.0, 1.0);
    egui::Color32::from_rgba_unmultiplied(
        (from.r() as f32 + (to.r() as f32 - from.r() as f32) * t) as u8,
        (from.g() as f32 + (to.g() as f32 - from.g() as f32) * t) as u8,
        (from.b() as f32 + (to.b() as f32 - from.b() as f32) * t) as u8,
        (from.a() as f32 + (to.a() as f32 - from.a() as f32) * t) as u8,
    )
}

/// Get latency color based on ms value
fn latency_color(ms: u32) -> egui::Color32 {
    if ms < 30 { LATENCY_EXCELLENT }
    else if ms < 60 { LATENCY_GOOD }
    else if ms < 100 { LATENCY_FAIR }
    else if ms < 150 { LATENCY_POOR }
    else { LATENCY_BAD }
}

/// Calculate latency bar fill percentage (0.0 - 1.0)
fn latency_fill_percent(ms: u32) -> f32 {
    // Inverted: lower latency = more fill
    // 0ms = 100%, 200ms+ = 10%
    let normalized = (ms as f32 / 200.0).min(1.0);
    1.0 - (normalized * 0.9) // Range: 1.0 to 0.1
}

/// Animation state for a single value
#[derive(Clone)]
struct Animation {
    start_time: std::time::Instant,
    duration: f32,
    from: f32,
    to: f32,
}

impl Animation {
    fn new(from: f32, to: f32, duration: f32) -> Self {
        Self {
            start_time: std::time::Instant::now(),
            duration,
            from,
            to,
        }
    }

    fn current_value(&self) -> f32 {
        let elapsed = self.start_time.elapsed().as_secs_f32();
        let t = (elapsed / self.duration).min(1.0);
        let eased = ease_out_cubic(t);
        self.from + (self.to - self.from) * eased
    }

    fn is_complete(&self) -> bool {
        self.start_time.elapsed().as_secs_f32() >= self.duration
    }
}

/// Animation manager for all UI animations
#[derive(Default)]
struct AnimationManager {
    /// Toggle switch animations (key = toggle ID)
    toggle_animations: HashMap<String, Animation>,
    /// Hover state animations for cards (key = card ID)
    hover_animations: HashMap<String, Animation>,
}

impl AnimationManager {
    fn animate_toggle(&mut self, id: &str, target: bool, current: f32) {
        let target_val = if target { 1.0 } else { 0.0 };
        // Only start a new animation if target changed
        if let Some(existing) = self.toggle_animations.get(id) {
            if (existing.to - target_val).abs() < 0.01 {
                return; // Already animating to this target
            }
        }
        self.toggle_animations.insert(
            id.to_string(),
            Animation::new(current, target_val, TOGGLE_ANIMATION_DURATION)
        );
    }

    fn get_toggle_value(&self, id: &str, fallback: bool) -> f32 {
        if let Some(anim) = self.toggle_animations.get(id) {
            anim.current_value()
        } else {
            if fallback { 1.0 } else { 0.0 }
        }
    }

    fn animate_hover(&mut self, id: &str, is_hovered: bool, current: f32) {
        let target_val = if is_hovered { 1.0 } else { 0.0 };
        if let Some(existing) = self.hover_animations.get(id) {
            if (existing.to - target_val).abs() < 0.01 {
                return;
            }
        }
        self.hover_animations.insert(
            id.to_string(),
            Animation::new(current, target_val, HOVER_ANIMATION_DURATION)
        );
    }

    fn get_hover_value(&self, id: &str) -> f32 {
        if let Some(anim) = self.hover_animations.get(id) {
            anim.current_value()
        } else {
            0.0
        }
    }

    fn has_active_animations(&self) -> bool {
        self.toggle_animations.values().any(|a| !a.is_complete()) ||
        self.hover_animations.values().any(|a| !a.is_complete())
    }

    fn cleanup_completed(&mut self) {
        self.toggle_animations.retain(|_, a| !a.is_complete());
        self.hover_animations.retain(|_, a| !a.is_complete());
    }
}

/// VPN connection progress step
#[derive(Clone, Copy, PartialEq, Eq)]
enum ConnectionStep {
    Idle,
    Fetching,
    Adapter,
    Tunnel,
    Routing,
    Connected,
}

impl ConnectionStep {
    fn from_state(state: &ConnectionState) -> Self {
        match state {
            ConnectionState::Disconnected => ConnectionStep::Idle,
            ConnectionState::FetchingConfig => ConnectionStep::Fetching,
            ConnectionState::CreatingAdapter => ConnectionStep::Adapter,
            ConnectionState::Connecting => ConnectionStep::Tunnel,
            ConnectionState::ConfiguringSplitTunnel => ConnectionStep::Routing,
            ConnectionState::Connected { .. } => ConnectionStep::Connected,
            ConnectionState::Disconnecting => ConnectionStep::Idle,
            ConnectionState::Error(_) => ConnectionStep::Idle,
        }
    }

    fn step_index(&self) -> usize {
        match self {
            ConnectionStep::Idle => 0,
            ConnectionStep::Fetching => 1,
            ConnectionStep::Adapter => 2,
            ConnectionStep::Tunnel => 3,
            ConnectionStep::Routing => 4,
            ConnectionStep::Connected => 5,
        }
    }

    fn label(&self) -> &'static str {
        match self {
            ConnectionStep::Idle => "Ready",
            ConnectionStep::Fetching => "Fetching",
            ConnectionStep::Adapter => "Adapter",
            ConnectionStep::Tunnel => "Tunnel",
            ConnectionStep::Routing => "Routing",
            ConnectionStep::Connected => "Done",
        }
    }
}

#[derive(PartialEq, Clone, Copy, Debug)]
enum Tab { Connect, Boost, Network, Settings }

#[derive(PartialEq, Clone, Copy)]
enum SettingsSection { General, Performance, Account }

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
    region_latencies: Arc<Mutex<HashMap<String, Option<u32>>>>,
    finding_best_server: Arc<AtomicBool>,
    /// Selected game presets for split tunneling (multi-select)
    selected_game_presets: std::collections::HashSet<GamePreset>,

    // Performance: reuse tokio runtime
    runtime: Arc<tokio::runtime::Runtime>,
    // Track if we need continuous updates
    needs_repaint: bool,
    last_vpn_check: std::time::Instant,

    // Performance: cached values to avoid per-frame mutex locks
    cached_latencies: HashMap<String, Option<u32>>,
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
    // Flag to force quit (bypass minimize-to-tray)
    force_quit: bool,

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
                            
                            if let Some(best_latency) = ping_region_async(&server_ips).await {
                                if let Ok(mut lat) = latencies_clone.lock() {
                                    lat.insert(region.id.clone(), Some(best_latency));
                                    log::info!("Region {} best latency: {}ms", region.id, best_latency);
                                }
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
            // Force quit flag (bypass minimize-to-tray)
            force_quit: false,

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
        style.visuals.widgets.inactive.rounding = egui::Rounding::same(8.0);

        style.visuals.widgets.hovered.bg_fill = BG_HOVER;
        style.visuals.widgets.hovered.fg_stroke = egui::Stroke::new(1.0, TEXT_PRIMARY);
        style.visuals.widgets.hovered.rounding = egui::Rounding::same(8.0);

        style.visuals.widgets.active.bg_fill = ACCENT_PRIMARY;
        style.visuals.widgets.active.fg_stroke = egui::Stroke::new(1.0, TEXT_PRIMARY);
        style.visuals.widgets.active.rounding = egui::Rounding::same(8.0);

        style.visuals.widgets.noninteractive.fg_stroke = egui::Stroke::new(1.0, TEXT_PRIMARY);
        style.visuals.selection.bg_fill = ACCENT_PRIMARY.gamma_multiply(0.3);

        style.spacing.item_spacing = egui::vec2(12.0, 10.0);
        style.spacing.button_padding = egui::vec2(20.0, 10.0);
        style.spacing.window_margin = egui::Margin::same(20.0);

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
        };

        let _ = save_settings(&settings);
        self.settings_dirty = false;
        self.last_save_time = std::time::Instant::now();
    }

    fn set_status(&mut self, msg: &str, color: egui::Color32) {
        self.status_message = Some((msg.to_string(), color, std::time::Instant::now()));
    }
}

/// Async ping function that doesn't block the main thread
async fn ping_region_async(servers: &[(String, String)]) -> Option<u32> {
    use crate::hidden_command;

    let mut best_latency: Option<u32> = None;

    for (server_id, server_ip) in servers {
        let mut total = 0u32;
        let mut count = 0u32;

        // Do 2 pings per server (faster than 3)
        for _ in 0..2 {
            let output = tokio::task::spawn_blocking({
                let ip = server_ip.clone();
                move || {
                    hidden_command("ping")
                        .args(["-n", "1", "-w", "500", &ip])
                        .output()
                        .ok()
                }
            }).await.ok().flatten();
            
            if let Some(output) = output {
                let stdout = String::from_utf8_lossy(&output.stdout);
                if let Some(ms) = parse_ping_output(&stdout) {
                    total += ms;
                    count += 1;
                }
            }
            
            // Small delay between pings
            tokio::time::sleep(tokio::time::Duration::from_millis(50)).await;
        }
        
        if count > 0 {
            let avg = total / count;
            if best_latency.is_none() || avg < best_latency.unwrap() {
                best_latency = Some(avg);
            }
        }
    }
    
    best_latency
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

        // PERFORMANCE FIX: Only request continuous repaint when actually needed
        let is_loading = self.servers_loading || self.finding_best_server.load(Ordering::Relaxed);
        let is_vpn_transitioning = self.vpn_state.is_connecting() || matches!(self.vpn_state, ConnectionState::Disconnecting);
        let is_logging_in = matches!(self.auth_state, AuthState::LoggingIn);
        let is_awaiting_oauth_here = matches!(self.auth_state, AuthState::AwaitingOAuthCallback(_));
        let is_updating = self.update_state.lock().map(|s| s.is_downloading()).unwrap_or(false);
        let has_animations = self.animations.has_active_animations();
        let is_connected = self.vpn_state.is_connected();  // For pulse animation
        let is_network_testing = self.network_analyzer_state.stability.running || self.network_analyzer_state.speed.running;

        if is_loading || is_vpn_transitioning || is_logging_in || is_awaiting_oauth_here || is_updating || has_animations || is_network_testing {
            // Fast repaint for animations (60 FPS target)
            ctx.request_repaint_after(std::time::Duration::from_millis(16));
        } else if is_connected {
            // Slow repaint for pulse animation (10 FPS is enough for breathing effect)
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
            if let Ok(vpn) = self.vpn_connection.try_lock() {
                // Get state directly - the state() method is fast
                let new_state = self.runtime.block_on(vpn.state());

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
                                format!("🎮 Tunneling: {}", process),
                                std::time::Instant::now(),
                            ));
                            self.previously_tunneled.insert(process.clone());
                        }
                    }
                }

                // Clear previously tunneled when disconnecting
                if new_state == ConnectionState::Disconnected {
                    self.previously_tunneled.clear();
                }

                self.vpn_state = new_state;
            }
            // Mark dirty outside the lock scope to avoid borrow conflict
            if should_mark_dirty {
                self.mark_dirty();
            }

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

        let is_logged_in = matches!(self.auth_state, AuthState::LoggedIn(_));
        let is_logging_in = matches!(self.auth_state, AuthState::LoggingIn);
        let is_awaiting_oauth = matches!(self.auth_state, AuthState::AwaitingOAuthCallback(_));

        egui::CentralPanel::default()
            .frame(egui::Frame::none().fill(BG_DARKEST))
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
    }
}

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
                        egui::Frame::none()
                            .fill(STATUS_CONNECTED.gamma_multiply(0.9 * alpha))
                            .rounding(8.0)
                            .inner_margin(egui::Margin::symmetric(16.0, 10.0))
                            .shadow(egui::epaint::Shadow {
                                offset: egui::vec2(0.0, 2.0),
                                blur: 8.0,
                                spread: 0.0,
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

        // Draw gradient background effect
        let gradient_start = ACCENT_PRIMARY.gamma_multiply(0.06);
        let gradient_end = ACCENT_SECONDARY.gamma_multiply(0.03);

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

                // Modern logo with gradient effect
                let logo_size = 36.0;
                let (rect, _) = ui.allocate_exact_size(egui::vec2(logo_size, logo_size), egui::Sense::hover());
                let center = rect.center();

                // Animated gradient ring
                let elapsed = self.app_start_time.elapsed().as_secs_f32();
                let rotation = elapsed * 0.5;

                // Outer ring with gradient-like effect
                let ring_color_1 = lerp_color(ACCENT_PRIMARY, ACCENT_CYAN, ((rotation).sin() + 1.0) / 2.0);
                let ring_color_2 = lerp_color(ACCENT_CYAN, ACCENT_SECONDARY, ((rotation + 1.0).sin() + 1.0) / 2.0);

                // Background circle
                ui.painter().circle_filled(center, logo_size * 0.42, BG_ELEVATED);

                // Gradient-like arc segments
                for i in 0..8 {
                    let angle_start = (i as f32 / 8.0) * std::f32::consts::TAU + rotation;
                    let color = lerp_color(ring_color_1, ring_color_2, i as f32 / 8.0);
                    let alpha = 0.6 + (((angle_start * 2.0).sin() + 1.0) / 2.0) * 0.4;

                    for j in 0..3 {
                        let angle = angle_start + j as f32 * 0.05;
                        let x = center.x + angle.cos() * (logo_size * 0.35);
                        let y = center.y + angle.sin() * (logo_size * 0.35);
                        ui.painter().circle_filled(egui::pos2(x, y), 2.0, color.gamma_multiply(alpha));
                    }
                }

                // Inner stylized "S" with wave effect
                let wave_color = ACCENT_CYAN;
                for i in 0..3 {
                    let offset = (i as f32 - 1.0) * 4.0;
                    let start = egui::pos2(center.x - 8.0, center.y + offset);
                    let end = egui::pos2(center.x + 8.0, center.y + offset);
                    let control1 = egui::pos2(center.x - 3.0, center.y + offset - 4.0);
                    let control2 = egui::pos2(center.x + 3.0, center.y + offset + 4.0);

                    let points = [start, control1, control2, end];
                    let alpha = 0.6 + (i as f32 * 0.2);
                    let stroke = egui::Stroke::new(2.0, wave_color.gamma_multiply(alpha));
                    ui.painter().add(egui::Shape::CubicBezier(egui::epaint::CubicBezierShape::from_points_stroke(
                        points,
                        false,
                        egui::Color32::TRANSPARENT,
                        stroke,
                    )));
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
                        egui::Frame::none()
                            .fill(ACCENT_PRIMARY.gamma_multiply(0.15))
                            .stroke(egui::Stroke::new(1.0, ACCENT_PRIMARY.gamma_multiply(0.3)))
                            .rounding(12.0)
                            .inner_margin(egui::Margin::symmetric(10.0, 4.0))
                            .show(ui, |ui| {
                                ui.horizontal(|ui| {
                                    ui.spacing_mut().item_spacing.x = 4.0;
                                    ui.label(egui::RichText::new("⚡").size(10.0));
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

                    egui::Frame::none()
                        .fill(badge_bg)
                        .stroke(egui::Stroke::new(1.0, badge_border))
                        .rounding(14.0)
                        .inner_margin(egui::Margin::symmetric(12.0, 6.0))
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

    /// Render VPN connection progress steps
    fn render_connection_progress_steps(&self, ui: &mut egui::Ui) {
        let current_step = ConnectionStep::from_state(&self.vpn_state);
        let current_idx = current_step.step_index();

        // Steps: Fetching (1), Adapter (2), Tunnel (3), Routing (4)
        let steps = [
            (1, "Config"),
            (2, "Adapter"),
            (3, "Tunnel"),
            (4, "Route"),
        ];

        ui.horizontal(|ui| {
            ui.spacing_mut().item_spacing.x = 0.0;
            let available = ui.available_width();
            let step_width = available / (steps.len() as f32);

            for (idx, label) in steps {
                let is_complete = current_idx > idx;
                let is_current = current_idx == idx;

                ui.allocate_ui(egui::vec2(step_width, 32.0), |ui| {
                    ui.vertical_centered(|ui| {
                        // Draw step dot
                        let dot_size = 10.0;
                        let (rect, _) = ui.allocate_exact_size(egui::vec2(dot_size, dot_size), egui::Sense::hover());

                        let dot_color = if is_complete {
                            STATUS_CONNECTED
                        } else if is_current {
                            STATUS_WARNING
                        } else {
                            BG_ELEVATED
                        };

                        // Current step has a pulsing effect
                        if is_current {
                            let elapsed = self.app_start_time.elapsed().as_secs_f32();
                            let pulse = ((elapsed * std::f32::consts::PI * 2.0).sin() + 1.0) / 2.0;
                            let glow_radius = 5.0 + pulse * 2.0;
                            ui.painter().circle_filled(rect.center(), glow_radius, dot_color.gamma_multiply(0.3));
                        }
                        ui.painter().circle_filled(rect.center(), 4.0, dot_color);

                        // Step label
                        let label_color = if is_complete || is_current { TEXT_PRIMARY } else { TEXT_MUTED };
                        ui.label(egui::RichText::new(label).size(10.0).color(label_color));
                    });
                });
            }
        });
    }

    fn render_nav_tabs(&mut self, ui: &mut egui::Ui) {
        // Tab container with subtle background
        egui::Frame::none()
            .fill(BG_CARD)
            .rounding(12.0)
            .inner_margin(egui::Margin::symmetric(4.0, 4.0))
            .show(ui, |ui| {
                ui.horizontal(|ui| {
                    ui.spacing_mut().item_spacing.x = 4.0;

                    let tabs = [
                        ("🌐", "Connect", Tab::Connect),
                        ("⚡", "Boost", Tab::Boost),
                        ("📶", "Network", Tab::Network),
                        ("⚙", "Settings", Tab::Settings),
                    ];

                    for (icon, label, tab) in tabs {
                        let is_active = self.current_tab == tab;
                        let tab_id = format!("tab_{:?}", tab);
                        let hover_val = self.animations.get_hover_value(&tab_id);

                        // Calculate colors with hover effect
                        let (bg, text_color, icon_color) = if is_active {
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

    fn render_connect_tab(&mut self, ui: &mut egui::Ui) {
        // Show update banner if available
        self.render_update_banner(ui);

        let is_logged_in = matches!(self.auth_state, AuthState::LoggedIn(_));

        if !is_logged_in {
            self.render_login_prompt(ui);
            return;
        }

        self.render_connection_status(ui);
        ui.add_space(16.0);
        self.render_game_preset_selector(ui);
        ui.add_space(16.0);
        self.render_region_selector(ui);
        ui.add_space(16.0);
        self.render_quick_info(ui);
    }

    /// Render game preset selector cards
    fn render_game_preset_selector(&mut self, ui: &mut egui::Ui) {
        egui::Frame::none()
            .fill(BG_CARD)
            .stroke(egui::Stroke::new(1.0, BG_ELEVATED))
            .rounding(12.0)
            .inner_margin(16.0)
            .show(ui, |ui| {
                ui.set_min_width(ui.available_width());

                // Section header
                ui.horizontal(|ui| {
                    ui.label(egui::RichText::new("🎮").size(16.0));
                    ui.label(egui::RichText::new("Game Selection").size(14.0).color(TEXT_PRIMARY).strong());
                    ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                        let count = self.selected_game_presets.len();
                        if count > 0 {
                            ui.label(egui::RichText::new(format!("{} selected", count))
                                .size(11.0).color(ACCENT_PRIMARY));
                        }
                    });
                });

                ui.add_space(12.0);

                // Game preset cards in a horizontal row
                ui.horizontal(|ui| {
                    ui.spacing_mut().item_spacing = egui::vec2(10.0, 0.0);

                    // Calculate card width based on available space (3 cards per row)
                    let card_width = (ui.available_width() - 20.0) / 3.0;

                    for preset in GamePreset::all() {
                        let is_selected = self.selected_game_presets.contains(preset);
                        let is_connected = self.vpn_state.is_connected();

                        let card_bg = if is_selected {
                            ACCENT_PRIMARY.gamma_multiply(0.15)
                        } else {
                            BG_ELEVATED
                        };
                        let card_border = if is_selected {
                            egui::Stroke::new(2.0, ACCENT_PRIMARY)
                        } else {
                            egui::Stroke::new(1.0, BG_HOVER)
                        };

                        let response = egui::Frame::none()
                            .fill(card_bg)
                            .stroke(card_border)
                            .rounding(8.0)
                            .inner_margin(egui::Margin::symmetric(8.0, 12.0))
                            .show(ui, |ui| {
                                ui.set_min_width(card_width);
                                ui.set_max_width(card_width);

                                ui.vertical_centered(|ui| {
                                    // Game icon
                                    ui.label(egui::RichText::new(preset.icon()).size(24.0));
                                    ui.add_space(4.0);

                                    // Game name
                                    let name_color = if is_selected { TEXT_PRIMARY } else { TEXT_SECONDARY };
                                    ui.label(egui::RichText::new(preset.display_name())
                                        .size(13.0).color(name_color).strong());

                                    // Selection indicator
                                    if is_selected {
                                        ui.add_space(2.0);
                                        ui.label(egui::RichText::new("✓").size(10.0).color(ACCENT_PRIMARY));
                                    }
                                });
                            })
                            .response;

                        // Handle click (only when not connected)
                        if response.interact(egui::Sense::click()).clicked() && !is_connected {
                            if is_selected {
                                self.selected_game_presets.remove(preset);
                            } else {
                                self.selected_game_presets.insert(*preset);
                            }
                            self.mark_dirty();
                        }

                        // Change cursor on hover (only when not connected)
                        if !is_connected {
                            response.on_hover_cursor(egui::CursorIcon::PointingHand);
                        }
                    }
                });

                // Warning if no game selected
                if self.selected_game_presets.is_empty() {
                    ui.add_space(8.0);
                    ui.horizontal(|ui| {
                        ui.label(egui::RichText::new("⚠").size(12.0).color(STATUS_WARNING));
                        ui.label(egui::RichText::new("Select at least one game to enable split tunneling")
                            .size(11.0).color(STATUS_WARNING));
                    });
                }
            });
    }

    fn render_login_prompt(&mut self, ui: &mut egui::Ui) {
        let mut go_settings = false;

        egui::Frame::none()
            .fill(BG_CARD).stroke(egui::Stroke::new(1.0, BG_ELEVATED))
            .rounding(12.0).inner_margin(20.0)
            .show(ui, |ui| {
                ui.set_min_width(ui.available_width());
                ui.vertical_centered(|ui| {
                    ui.add_space(32.0);
                    let (rect, _) = ui.allocate_exact_size(egui::vec2(64.0, 64.0), egui::Sense::hover());
                    ui.painter().circle_filled(rect.center(), 32.0, ACCENT_PRIMARY.gamma_multiply(0.2));
                    ui.painter().circle_stroke(rect.center(), 32.0, egui::Stroke::new(2.0, ACCENT_PRIMARY));

                    ui.add_space(20.0);
                    ui.label(egui::RichText::new("Sign In Required").size(20.0).color(TEXT_PRIMARY).strong());
                    ui.add_space(8.0);
                    ui.label(egui::RichText::new("Connect to gaming servers and reduce your ping").size(14.0).color(TEXT_SECONDARY));
                    ui.add_space(24.0);

                    if ui.add(
                        egui::Button::new(egui::RichText::new("Go to Account Settings").size(14.0).color(TEXT_PRIMARY))
                            .fill(ACCENT_PRIMARY).rounding(8.0).min_size(egui::vec2(200.0, 44.0))
                    ).clicked() {
                        go_settings = true;
                    }
                    ui.add_space(32.0);
                });
            });

        if go_settings {
            self.current_tab = Tab::Settings;
            self.settings_section = SettingsSection::Account;
        }
    }

    fn render_connection_status(&mut self, ui: &mut egui::Ui) {
        let (status_text, status_icon, status_color, detail_text, show_connected_info) = match &self.vpn_state {
            ConnectionState::Disconnected => ("Disconnected", "○", STATUS_INACTIVE, "Ready to connect".to_string(), false),
            ConnectionState::FetchingConfig => ("Connecting", "◐", STATUS_WARNING, "Fetching config...".to_string(), false),
            ConnectionState::CreatingAdapter => ("Connecting", "◑", STATUS_WARNING, "Creating adapter...".to_string(), false),
            ConnectionState::Connecting => ("Connecting", "◒", STATUS_WARNING, "Establishing tunnel...".to_string(), false),
            ConnectionState::ConfiguringSplitTunnel => ("Connecting", "◓", STATUS_WARNING, "Configuring routing...".to_string(), false),
            ConnectionState::Connected { server_region, .. } => {
                let name = if let Ok(list) = self.dynamic_server_list.lock() {
                    list.get_server(server_region)
                        .map(|s| s.name.clone())
                        .unwrap_or_else(|| server_region.clone())
                } else {
                    server_region.clone()
                };
                ("Protected", "●", STATUS_CONNECTED, name, true)
            }
            ConnectionState::Disconnecting => ("Disconnecting", "◌", STATUS_WARNING, "Please wait...".to_string(), false),
            ConnectionState::Error(msg) => {
                // Format user-friendly VPN error messages
                let user_friendly = if msg.contains("Administrator privileges required") {
                    "Admin access required. Restart as Administrator.".to_string()
                } else if msg.contains("wintun.dll not found") {
                    "Driver not found. Please reinstall SwiftTunnel.".to_string()
                } else if msg.contains("401") || msg.contains("Unauthorized") {
                    "Session expired. Sign out and sign in again.".to_string()
                } else if msg.contains("404") {
                    "Server unavailable. Try a different region.".to_string()
                } else if msg.contains("timeout") || msg.contains("Timeout") {
                    "Connection timed out. Check your internet.".to_string()
                } else if msg.contains("Network error") || msg.contains("network") {
                    "Network error. Check your connection.".to_string()
                } else if msg.contains("handshake") || msg.contains("Handshake") {
                    "Secure connection failed. Try again.".to_string()
                } else {
                    msg.clone()
                };
                ("Error", "✕", STATUS_ERROR, user_friendly, false)
            }
        };

        let is_connected = self.vpn_state.is_connected();
        let is_connecting = self.vpn_state.is_connecting();
        let is_error = matches!(&self.vpn_state, ConnectionState::Error(_));

        let (assigned_ip, uptime_str, split_tunnel_active, tunneled_processes) = if let ConnectionState::Connected {
            assigned_ip, since, split_tunnel_active, tunneled_processes, ..
        } = &self.vpn_state {
            let uptime = since.elapsed();
            let h = uptime.as_secs() / 3600;
            let m = (uptime.as_secs() % 3600) / 60;
            let s = uptime.as_secs() % 60;
            (assigned_ip.clone(), format!("{:02}:{:02}:{:02}", h, m, s), *split_tunnel_active, tunneled_processes.clone())
        } else {
            (String::new(), String::new(), false, Vec::new())
        };

        let mut do_connect = false;
        let mut do_disconnect = false;

        // Dynamic card styling based on state
        let (card_bg, card_border, border_width) = if is_connected {
            // Connected: subtle green tint with glow
            (lerp_color(BG_CARD, STATUS_CONNECTED, 0.05),
             STATUS_CONNECTED.gamma_multiply(0.4),
             1.5)
        } else if is_error {
            // Error: subtle red tint
            (lerp_color(BG_CARD, STATUS_ERROR, 0.03),
             STATUS_ERROR.gamma_multiply(0.3),
             1.0)
        } else {
            (BG_CARD, BG_ELEVATED, 1.0)
        };

        egui::Frame::none()
            .fill(card_bg)
            .stroke(egui::Stroke::new(border_width, card_border))
            .rounding(16.0)
            .inner_margin(egui::Margin::symmetric(20.0, 18.0))
            .show(ui, |ui| {
                ui.set_min_width(ui.available_width());

                ui.horizontal(|ui| {
                    // Status indicator with animation
                    let indicator_size = 48.0;
                    let (indicator_rect, _) = ui.allocate_exact_size(egui::vec2(indicator_size, indicator_size), egui::Sense::hover());
                    let center = indicator_rect.center();

                    if is_connected {
                        // Animated breathing glow for connected state
                        let elapsed = self.app_start_time.elapsed().as_secs_f32();
                        let pulse = ((elapsed * std::f32::consts::PI / PULSE_ANIMATION_DURATION).sin() + 1.0) / 2.0;

                        // Outer glow rings
                        for i in 0..3 {
                            let ring_pulse = ((pulse + i as f32 * 0.2) % 1.0);
                            let radius = 18.0 + ring_pulse * 8.0;
                            let alpha = 0.15 * (1.0 - ring_pulse);
                            ui.painter().circle_filled(center, radius, STATUS_CONNECTED_GLOW.gamma_multiply(alpha));
                        }

                        // Main circle
                        ui.painter().circle_filled(center, 16.0, STATUS_CONNECTED);
                        // Inner highlight
                        ui.painter().circle_filled(center, 8.0, STATUS_CONNECTED_GLOW.gamma_multiply(0.5));
                        // Shield icon
                        ui.painter().text(center, egui::Align2::CENTER_CENTER,
                            "✓", egui::FontId::proportional(14.0), egui::Color32::WHITE);
                    } else if is_connecting {
                        // Spinning animation for connecting
                        let elapsed = self.app_start_time.elapsed().as_secs_f32();

                        // Rotating dots
                        for i in 0..3 {
                            let angle = elapsed * 3.0 + (i as f32 * std::f32::consts::TAU / 3.0);
                            let radius = 14.0;
                            let dot_pos = egui::pos2(
                                center.x + angle.cos() * radius,
                                center.y + angle.sin() * radius
                            );
                            let dot_alpha = 0.3 + (1.0 - (i as f32 / 3.0)) * 0.7;
                            ui.painter().circle_filled(dot_pos, 4.0 - i as f32 * 0.5, STATUS_WARNING.gamma_multiply(dot_alpha));
                        }

                        // Center dot
                        ui.painter().circle_filled(center, 6.0, STATUS_WARNING.gamma_multiply(0.3));
                    } else if is_error {
                        // Error state
                        ui.painter().circle_filled(center, 16.0, STATUS_ERROR.gamma_multiply(0.2));
                        ui.painter().circle_stroke(center, 16.0, egui::Stroke::new(2.0, STATUS_ERROR));
                        ui.painter().text(center, egui::Align2::CENTER_CENTER,
                            "!", egui::FontId::proportional(18.0), STATUS_ERROR);
                    } else {
                        // Disconnected state
                        ui.painter().circle_filled(center, 16.0, BG_ELEVATED);
                        ui.painter().circle_stroke(center, 16.0, egui::Stroke::new(1.5, STATUS_INACTIVE));
                    }

                    ui.add_space(14.0);

                    ui.vertical(|ui| {
                        // Status text with icon
                        ui.horizontal(|ui| {
                            ui.label(egui::RichText::new(status_text)
                                .size(20.0)
                                .color(status_color)
                                .strong());
                        });
                        ui.add_space(2.0);
                        ui.label(egui::RichText::new(&detail_text)
                            .size(13.0)
                            .color(TEXT_SECONDARY));
                    });

                    ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                        let (btn_text, btn_icon, btn_color) = if is_connected {
                            ("Disconnect", "⏻", STATUS_ERROR)
                        } else if is_connecting {
                            ("Cancel", "✕", STATUS_WARNING)
                        } else {
                            ("Connect", "→", ACCENT_PRIMARY)
                        };

                        // Button with icon
                        let btn_response = ui.add(
                            egui::Button::new(egui::RichText::new(format!("{}  {}", btn_text, btn_icon))
                                .size(14.0)
                                .color(TEXT_PRIMARY)
                                .strong())
                                .fill(btn_color)
                                .rounding(10.0)
                                .min_size(egui::vec2(130.0, 46.0))
                        );

                        if btn_response.clicked() {
                            if is_connected || is_connecting {
                                do_disconnect = true;
                            } else {
                                do_connect = true;
                            }
                        }
                    });
                });

                // VPN Connection Progress Steps (shown during connecting states)
                if is_connecting {
                    ui.add_space(18.0);
                    self.render_connection_progress_steps(ui);
                }

                if show_connected_info {
                    ui.add_space(16.0);

                    // Subtle divider
                    let divider_rect = ui.allocate_exact_size(egui::vec2(ui.available_width(), 1.0), egui::Sense::hover()).0;
                    ui.painter().rect_filled(divider_rect, 0.0, BG_ELEVATED);

                    ui.add_space(14.0);

                    // Info badges in a row
                    ui.horizontal(|ui| {
                        ui.spacing_mut().item_spacing.x = 12.0;

                        // IP Address badge
                        egui::Frame::none()
                            .fill(BG_ELEVATED)
                            .rounding(8.0)
                            .inner_margin(egui::Margin::symmetric(12.0, 8.0))
                            .show(ui, |ui| {
                                ui.horizontal(|ui| {
                                    ui.spacing_mut().item_spacing.x = 6.0;
                                    ui.label(egui::RichText::new("🌐").size(12.0));
                                    ui.vertical(|ui| {
                                        ui.spacing_mut().item_spacing.y = 1.0;
                                        ui.label(egui::RichText::new("IP Address").size(10.0).color(TEXT_MUTED));
                                        ui.label(egui::RichText::new(&assigned_ip).size(12.0).color(TEXT_PRIMARY).strong());
                                    });
                                });
                            });

                        // Uptime badge
                        egui::Frame::none()
                            .fill(BG_ELEVATED)
                            .rounding(8.0)
                            .inner_margin(egui::Margin::symmetric(12.0, 8.0))
                            .show(ui, |ui| {
                                ui.horizontal(|ui| {
                                    ui.spacing_mut().item_spacing.x = 6.0;
                                    ui.label(egui::RichText::new("⏱").size(12.0));
                                    ui.vertical(|ui| {
                                        ui.spacing_mut().item_spacing.y = 1.0;
                                        ui.label(egui::RichText::new("Uptime").size(10.0).color(TEXT_MUTED));
                                        ui.label(egui::RichText::new(&uptime_str).size(12.0).color(TEXT_PRIMARY).strong());
                                    });
                                });
                            });

                        // Split tunnel badge (if active)
                        if split_tunnel_active {
                            let (tunnel_icon, tunnel_text, tunnel_color) = if tunneled_processes.is_empty() {
                                ("⏳", "Waiting...", STATUS_WARNING)
                            } else {
                                ("✓", &tunneled_processes.join(", ") as &str, STATUS_CONNECTED)
                            };

                            egui::Frame::none()
                                .fill(tunnel_color.gamma_multiply(0.1))
                                .stroke(egui::Stroke::new(1.0, tunnel_color.gamma_multiply(0.3)))
                                .rounding(8.0)
                                .inner_margin(egui::Margin::symmetric(12.0, 8.0))
                                .show(ui, |ui| {
                                    ui.horizontal(|ui| {
                                        ui.spacing_mut().item_spacing.x = 6.0;
                                        ui.label(egui::RichText::new(tunnel_icon).size(12.0).color(tunnel_color));
                                        ui.vertical(|ui| {
                                            ui.spacing_mut().item_spacing.y = 1.0;
                                            ui.label(egui::RichText::new("Split Tunnel").size(10.0).color(TEXT_MUTED));
                                            ui.label(egui::RichText::new(tunnel_text).size(11.0).color(tunnel_color));
                                        });
                                    });
                                });
                        }
                    });
                }
            });

        if do_connect { self.connect_vpn(); }
        if do_disconnect { self.disconnect_vpn(); }
    }

    fn render_region_selector(&mut self, ui: &mut egui::Ui) {
        let mut clicked_region: Option<String> = None;
        let is_finding = self.finding_best_server.load(Ordering::Relaxed);

        // PERFORMANCE: Use cached values instead of locking mutexes every frame
        let regions = &self.cached_regions;
        let is_loading = self.servers_loading;
        let error_msg: Option<String> = if let Ok(list) = self.dynamic_server_list.try_lock() {
            list.error_message().map(|s| s.to_string())
        } else {
            None
        };
        let latencies = &self.cached_latencies;

        // Section header with enhanced styling
        ui.horizontal(|ui| {
            // Globe icon for regions
            ui.label(egui::RichText::new("🌐").size(14.0));
            ui.add_space(4.0);
            ui.label(egui::RichText::new("SELECT REGION").size(11.0).color(TEXT_SECONDARY).strong());

            ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                if is_loading {
                    // Animated loading indicator
                    let elapsed = self.app_start_time.elapsed().as_secs_f32();
                    let pulse = ((elapsed * 3.0).sin() + 1.0) / 2.0;
                    let color = lerp_color(ACCENT_PRIMARY, ACCENT_CYAN, pulse);
                    ui.label(egui::RichText::new("●").size(8.0).color(color));
                    ui.add_space(4.0);
                    ui.label(egui::RichText::new("Loading...").size(11.0).color(ACCENT_PRIMARY));
                } else if is_finding {
                    let elapsed = self.app_start_time.elapsed().as_secs_f32();
                    let pulse = ((elapsed * 3.0).sin() + 1.0) / 2.0;
                    let color = lerp_color(ACCENT_CYAN, STATUS_CONNECTED, pulse);
                    ui.label(egui::RichText::new("●").size(8.0).color(color));
                    ui.add_space(4.0);
                    ui.label(egui::RichText::new("Measuring...").size(11.0).color(ACCENT_CYAN));
                } else {
                    // Server count badge
                    egui::Frame::none()
                        .fill(BG_ELEVATED)
                        .rounding(8.0)
                        .inner_margin(egui::Margin::symmetric(8.0, 3.0))
                        .show(ui, |ui| {
                            ui.label(egui::RichText::new(format!("{} regions", regions.len()))
                                .size(10.0)
                                .color(TEXT_MUTED));
                        });
                }
            });
        });
        ui.add_space(14.0);

        // Show skeleton loading or error state if no regions
        if regions.is_empty() {
            if is_loading {
                // Skeleton loading cards with shimmer effect
                self.render_skeleton_region_cards(ui);
            } else if let Some(err) = &error_msg {
                // Error state with retry
                egui::Frame::none()
                    .fill(STATUS_ERROR.gamma_multiply(0.08))
                    .stroke(egui::Stroke::new(1.0, STATUS_ERROR.gamma_multiply(0.3)))
                    .rounding(12.0)
                    .inner_margin(egui::Margin::symmetric(24.0, 20.0))
                    .show(ui, |ui| {
                        ui.set_min_width(ui.available_width());
                        ui.vertical_centered(|ui| {
                            ui.label(egui::RichText::new("⚠").size(32.0).color(STATUS_ERROR));
                            ui.add_space(12.0);
                            ui.label(egui::RichText::new("Failed to load servers")
                                .size(15.0)
                                .color(TEXT_PRIMARY)
                                .strong());
                            ui.add_space(6.0);
                            ui.label(egui::RichText::new(err)
                                .size(12.0)
                                .color(TEXT_SECONDARY));
                            ui.add_space(16.0);
                            if ui.add(
                                egui::Button::new(egui::RichText::new("↻  Retry").size(13.0).color(TEXT_PRIMARY))
                                    .fill(ACCENT_PRIMARY)
                                    .rounding(8.0)
                                    .min_size(egui::vec2(100.0, 36.0))
                            ).clicked() {
                                self.retry_load_servers();
                            }
                        });
                    });
            } else {
                // Empty state
                egui::Frame::none()
                    .fill(BG_CARD)
                    .rounding(12.0)
                    .inner_margin(egui::Margin::symmetric(24.0, 30.0))
                    .show(ui, |ui| {
                        ui.set_min_width(ui.available_width());
                        ui.vertical_centered(|ui| {
                            ui.label(egui::RichText::new("No servers available")
                                .size(14.0)
                                .color(TEXT_MUTED));
                        });
                    });
            }
            return;
        }

        // Calculate grid dimensions - 2 columns with better spacing
        let available_width = ui.available_width();
        let card_spacing = 12.0;
        let card_width = (available_width - card_spacing) / 2.0;

        // Create 2-column grid with enhanced cards
        let mut region_iter = regions.iter().peekable();
        while region_iter.peek().is_some() {
            ui.horizontal(|ui| {
                ui.spacing_mut().item_spacing.x = card_spacing;

                for _ in 0..2 {
                    if let Some(region) = region_iter.next() {
                        let is_selected = self.selected_region == region.id;
                        let latency = latencies.get(&region.id).and_then(|l| *l);
                        let card_id = format!("region_{}", region.id);

                        // Get hover animation value
                        let hover_val = self.animations.get_hover_value(&card_id);

                        // Calculate colors based on state
                        let (bg, border_color, border_width) = if is_selected {
                            // Selected: gradient-like effect with glow
                            (lerp_color(ACCENT_PRIMARY.gamma_multiply(0.12), ACCENT_PRIMARY.gamma_multiply(0.18), hover_val),
                             ACCENT_PRIMARY,
                             2.0)
                        } else {
                            // Hover effect: subtle lift
                            let hover_bg = lerp_color(BG_CARD, BG_ELEVATED, hover_val * 0.5);
                            let hover_border = lerp_color(BG_ELEVATED, ACCENT_PRIMARY.gamma_multiply(0.4), hover_val);
                            (hover_bg, hover_border, 1.0 + hover_val * 0.5)
                        };

                        let response = egui::Frame::none()
                            .fill(bg)
                            .stroke(egui::Stroke::new(border_width, border_color))
                            .rounding(14.0)
                            .inner_margin(egui::Margin::symmetric(14.0, 14.0))
                            .show(ui, |ui| {
                                ui.set_width(card_width - 28.0);
                                ui.set_min_height(85.0);

                                ui.vertical(|ui| {
                                    // Top row: Country code + badges + latency
                                    ui.horizontal(|ui| {
                                        // Country code badge with icon
                                        egui::Frame::none()
                                            .fill(if is_selected { ACCENT_PRIMARY } else { BG_ELEVATED })
                                            .rounding(6.0)
                                            .inner_margin(egui::Margin::symmetric(10.0, 5.0))
                                            .show(ui, |ui| {
                                                ui.horizontal(|ui| {
                                                    ui.spacing_mut().item_spacing.x = 4.0;
                                                    // Flag emoji based on country code
                                                    let flag = match region.country_code.as_str() {
                                                        "SG" => "🇸🇬",
                                                        "JP" => "🇯🇵",
                                                        "IN" => "🇮🇳",
                                                        "AU" => "🇦🇺",
                                                        "DE" => "🇩🇪",
                                                        "FR" => "🇫🇷",
                                                        "US" => "🇺🇸",
                                                        "BR" => "🇧🇷",
                                                        _ => "🌍",
                                                    };
                                                    ui.label(egui::RichText::new(flag).size(12.0));
                                                    ui.label(egui::RichText::new(&region.country_code)
                                                        .size(11.0)
                                                        .color(if is_selected { egui::Color32::WHITE } else { TEXT_SECONDARY })
                                                        .strong());
                                                });
                                            });

                                        // "LAST" badge
                                        let is_last_used = self.last_connected_region.as_ref().map(|r| r == &region.id).unwrap_or(false);
                                        if is_last_used && !is_selected {
                                            ui.add_space(4.0);
                                            egui::Frame::none()
                                                .fill(ACCENT_CYAN.gamma_multiply(0.12))
                                                .stroke(egui::Stroke::new(1.0, ACCENT_CYAN.gamma_multiply(0.3)))
                                                .rounding(6.0)
                                                .inner_margin(egui::Margin::symmetric(6.0, 3.0))
                                                .show(ui, |ui| {
                                                    ui.label(egui::RichText::new("★ LAST")
                                                        .size(9.0)
                                                        .color(ACCENT_CYAN));
                                                });
                                        }

                                        // Latency display on right
                                        ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                                            if let Some(ms) = latency {
                                                let lat_color = latency_color(ms);
                                                // Latency with colored indicator
                                                ui.horizontal(|ui| {
                                                    ui.spacing_mut().item_spacing.x = 4.0;
                                                    ui.label(egui::RichText::new(format!("{}ms", ms))
                                                        .size(12.0)
                                                        .color(lat_color)
                                                        .strong());
                                                    // Small quality indicator dot
                                                    let (dot_rect, _) = ui.allocate_exact_size(egui::vec2(6.0, 6.0), egui::Sense::hover());
                                                    ui.painter().circle_filled(dot_rect.center(), 3.0, lat_color);
                                                });
                                            } else if is_finding {
                                                // Animated measuring indicator
                                                let elapsed = self.app_start_time.elapsed().as_secs_f32();
                                                let dots = match ((elapsed * 2.0) as i32) % 4 {
                                                    0 => ".",
                                                    1 => "..",
                                                    2 => "...",
                                                    _ => "",
                                                };
                                                ui.label(egui::RichText::new(format!("ping{}", dots))
                                                    .size(11.0)
                                                    .color(TEXT_DIMMED));
                                            }
                                        });
                                    });

                                    ui.add_space(10.0);

                                    // Region name
                                    ui.label(egui::RichText::new(&region.name)
                                        .size(15.0)
                                        .color(if is_selected { TEXT_PRIMARY } else { TEXT_PRIMARY })
                                        .strong());

                                    ui.add_space(2.0);

                                    // Description
                                    ui.label(egui::RichText::new(&region.description)
                                        .size(11.0)
                                        .color(TEXT_MUTED));

                                    // Latency bar (visual indicator)
                                    if let Some(ms) = latency {
                                        ui.add_space(8.0);
                                        let bar_height = 3.0;
                                        let bar_width = card_width - 56.0;
                                        let (bar_rect, _) = ui.allocate_exact_size(egui::vec2(bar_width, bar_height), egui::Sense::hover());

                                        // Background bar
                                        ui.painter().rect_filled(bar_rect, 2.0, BG_ELEVATED);

                                        // Filled portion based on latency (inverted: lower = more fill)
                                        let fill_percent = latency_fill_percent(ms);
                                        let fill_width = bar_width * fill_percent;
                                        let fill_rect = egui::Rect::from_min_size(
                                            bar_rect.min,
                                            egui::vec2(fill_width, bar_height)
                                        );
                                        ui.painter().rect_filled(fill_rect, 2.0, latency_color(ms));
                                    }
                                });
                            });

                        // Handle hover for animation
                        let is_hovered = response.response.hovered();
                        self.animations.animate_hover(&card_id, is_hovered, hover_val);

                        if response.response.interact(egui::Sense::click()).clicked() {
                            clicked_region = Some(region.id.clone());
                        }
                    }
                }
            });
            ui.add_space(10.0);
        }

        // Handle click - just select the region, don't re-ping
        if let Some(region_id) = clicked_region {
            self.select_region(&region_id);
        }
    }

    /// Render skeleton loading cards with shimmer effect
    fn render_skeleton_region_cards(&self, ui: &mut egui::Ui) {
        let available_width = ui.available_width();
        let card_spacing = 12.0;
        let card_width = (available_width - card_spacing) / 2.0;

        // Shimmer animation progress
        let elapsed = self.app_start_time.elapsed().as_secs_f32();
        let shimmer_progress = (elapsed / SHIMMER_ANIMATION_DURATION).fract();

        // Render 4 skeleton cards (2 rows)
        for row in 0..2 {
            ui.horizontal(|ui| {
                ui.spacing_mut().item_spacing.x = card_spacing;

                for col in 0..2 {
                    let card_offset = (row * 2 + col) as f32 * 0.1;
                    let local_shimmer = ((shimmer_progress + card_offset) % 1.0);

                    egui::Frame::none()
                        .fill(BG_CARD)
                        .stroke(egui::Stroke::new(1.0, BG_ELEVATED))
                        .rounding(14.0)
                        .inner_margin(egui::Margin::symmetric(14.0, 14.0))
                        .show(ui, |ui| {
                            ui.set_width(card_width - 28.0);
                            ui.set_min_height(85.0);

                            ui.vertical(|ui| {
                                // Skeleton badge
                                let badge_rect = ui.allocate_exact_size(egui::vec2(60.0, 22.0), egui::Sense::hover()).0;
                                self.render_skeleton_rect(ui.painter(), badge_rect, 6.0, local_shimmer);

                                ui.add_space(10.0);

                                // Skeleton title
                                let title_rect = ui.allocate_exact_size(egui::vec2(card_width * 0.6, 16.0), egui::Sense::hover()).0;
                                self.render_skeleton_rect(ui.painter(), title_rect, 4.0, local_shimmer + 0.05);

                                ui.add_space(6.0);

                                // Skeleton description
                                let desc_rect = ui.allocate_exact_size(egui::vec2(card_width * 0.8, 12.0), egui::Sense::hover()).0;
                                self.render_skeleton_rect(ui.painter(), desc_rect, 4.0, local_shimmer + 0.1);

                                ui.add_space(8.0);

                                // Skeleton latency bar
                                let bar_rect = ui.allocate_exact_size(egui::vec2(card_width - 56.0, 3.0), egui::Sense::hover()).0;
                                self.render_skeleton_rect(ui.painter(), bar_rect, 2.0, local_shimmer + 0.15);
                            });
                        });
                }
            });
            ui.add_space(10.0);
        }
    }

    /// Render a single skeleton rectangle with shimmer effect
    fn render_skeleton_rect(&self, painter: &egui::Painter, rect: egui::Rect, rounding: f32, shimmer_offset: f32) {
        // Base skeleton color
        let base_color = BG_ELEVATED;

        // Shimmer highlight that moves across
        let shimmer_width = rect.width() * 0.4;
        let shimmer_x = rect.left() - shimmer_width + (rect.width() + shimmer_width * 2.0) * ease_in_out_sine(shimmer_offset % 1.0);

        // Draw base
        painter.rect_filled(rect, rounding, base_color);

        // Draw shimmer highlight (clipped to rect)
        let shimmer_rect = egui::Rect::from_min_max(
            egui::pos2(shimmer_x.max(rect.left()), rect.top()),
            egui::pos2((shimmer_x + shimmer_width).min(rect.right()), rect.bottom())
        );

        if shimmer_rect.width() > 0.0 {
            // Gradient-like effect using multiple rectangles
            let highlight_color = BG_HOVER;
            painter.rect_filled(shimmer_rect, rounding, highlight_color);
        }
    }

    /// Select a region - no longer pings, just selects the first server
    fn select_region(&mut self, region_id: &str) {
        self.selected_region = region_id.to_string();

        // Get first server from the region
        if let Ok(list) = self.dynamic_server_list.lock() {
            if let Some(region) = list.get_region(region_id) {
                if let Some(first_server) = region.servers.first() {
                    self.selected_server = first_server.clone();
                }
            }
        }

        self.mark_dirty();
    }

    fn render_quick_info(&self, ui: &mut egui::Ui) {
        egui::Frame::none()
            .fill(BG_CARD).stroke(egui::Stroke::new(1.0, BG_ELEVATED))
            .rounding(12.0).inner_margin(20.0)
            .show(ui, |ui| {
                ui.set_min_width(ui.available_width());
                ui.label(egui::RichText::new("System Info").size(14.0).color(TEXT_PRIMARY).strong());
                ui.add_space(12.0);

                if let Some(info) = &self.system_info {
                    ui.horizontal(|ui| {
                        ui.label(egui::RichText::new("CPU").size(12.0).color(TEXT_MUTED));
                        ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                            ui.label(egui::RichText::new(format!("{} cores", info.cpu_count)).size(12.0).color(TEXT_PRIMARY));
                        });
                    });
                    ui.add_space(6.0);
                    ui.horizontal(|ui| {
                        ui.label(egui::RichText::new("Memory").size(12.0).color(TEXT_MUTED));
                        ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                            ui.label(egui::RichText::new(format!("{:.1} GB", info.total_memory as f64 / 1024.0)).size(12.0).color(TEXT_PRIMARY));
                        });
                    });
                } else {
                    ui.label(egui::RichText::new("Loading...").size(12.0).color(TEXT_MUTED));
                }
            });
    }

    fn render_boost_tab(&mut self, ui: &mut egui::Ui) {
        // Clear old restore point status
        if let Some((_, _, time)) = &self.restore_point_status {
            if time.elapsed() > std::time::Duration::from_secs(5) {
                self.restore_point_status = None;
            }
        }

        // ─────────────────────────────────────────────────────────────
        // STATUS HEADER WITH ENABLE/DISABLE
        // ─────────────────────────────────────────────────────────────
        let (status_text, status_color) = if self.state.optimizations_active {
            ("Optimizations Active", STATUS_CONNECTED)
        } else {
            ("Optimizations Inactive", STATUS_INACTIVE)
        };

        let profile_str = format!("{:?}", self.selected_profile);
        let opt_active = self.state.optimizations_active;
        let mut toggle_opt = false;

        egui::Frame::none()
            .fill(BG_CARD).stroke(egui::Stroke::new(1.0, BG_ELEVATED))
            .rounding(12.0).inner_margin(20.0)
            .show(ui, |ui| {
                ui.set_min_width(ui.available_width());

                ui.horizontal(|ui| {
                    let (rect, _) = ui.allocate_exact_size(egui::vec2(12.0, 12.0), egui::Sense::hover());
                    ui.painter().circle_filled(rect.center(), 6.0, status_color);
                    ui.add_space(8.0);

                    ui.vertical(|ui| {
                        ui.label(egui::RichText::new(status_text).size(16.0).color(status_color).strong());
                        ui.label(egui::RichText::new(format!("Profile: {}", profile_str)).size(12.0).color(TEXT_SECONDARY));
                    });

                    ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                        let (btn_text, btn_color) = if opt_active { ("Disable", STATUS_ERROR) } else { ("Enable", ACCENT_PRIMARY) };
                        if ui.add(
                            egui::Button::new(egui::RichText::new(btn_text).size(14.0).color(TEXT_PRIMARY))
                                .fill(btn_color).rounding(8.0).min_size(egui::vec2(100.0, 40.0))
                        ).clicked() {
                            toggle_opt = true;
                        }
                    });
                });
            });

        if toggle_opt {
            self.toggle_optimizations();
        }

        // ─────────────────────────────────────────────────────────────
        // PROFILE SELECTION
        // ─────────────────────────────────────────────────────────────
        ui.add_space(16.0);
        ui.label(egui::RichText::new("QUICK PRESET").size(12.0).color(TEXT_MUTED).strong());
        ui.add_space(12.0);

        let mut new_profile = None;
        let available_width = ui.available_width();
        let gap = 12.0;
        let card_width = ((available_width - gap * 2.0) / 3.0).max(100.0);

        ui.horizontal(|ui| {
            ui.spacing_mut().item_spacing.x = gap;

            for (title, desc, icon, profile, profile_info) in [
                ("Performance", "Maximum FPS", "⚡", OptimizationProfile::LowEnd, &profile_info::PERFORMANCE),
                ("Balanced", "FPS + Quality", "⚖", OptimizationProfile::Balanced, &profile_info::BALANCED),
                ("Quality", "Best Visuals", "✨", OptimizationProfile::HighEnd, &profile_info::QUALITY),
            ] {
                let is_selected = self.selected_profile == profile;
                let card_id = format!("profile_{}", title);

                // Get hover animation value
                let hover_val = self.animations.get_hover_value(&card_id);

                // Calculate colors with hover effect
                let (bg, border, text_color) = if is_selected {
                    (ACCENT_PRIMARY.gamma_multiply(0.15), ACCENT_PRIMARY, ACCENT_PRIMARY)
                } else {
                    // Blend towards hover state
                    let hover_brightness = 1.0 + hover_val * 0.15;
                    let bg = egui::Color32::from_rgb(
                        (BG_CARD.r() as f32 * hover_brightness).min(255.0) as u8,
                        (BG_CARD.g() as f32 * hover_brightness).min(255.0) as u8,
                        (BG_CARD.b() as f32 * hover_brightness).min(255.0) as u8,
                    );
                    (bg, BG_ELEVATED, TEXT_PRIMARY)
                };

                let response = egui::Frame::none()
                    .fill(bg)
                    .stroke(egui::Stroke::new(if is_selected { 2.0 } else { 1.0 }, border))
                    .rounding(12.0)
                    .inner_margin(egui::Margin::symmetric(12.0, 16.0))
                    .show(ui, |ui| {
                        ui.set_width(card_width - 24.0);
                        ui.vertical_centered(|ui| {
                            ui.label(egui::RichText::new(icon).size(24.0).color(if is_selected { ACCENT_PRIMARY } else { TEXT_MUTED }));
                            ui.add_space(8.0);
                            ui.label(egui::RichText::new(title).size(14.0).color(text_color).strong());
                            ui.add_space(4.0);
                            ui.label(egui::RichText::new(desc).size(11.0).color(TEXT_SECONDARY));
                        });
                    });

                // Handle hover for animation
                let is_hovered = response.response.hovered();
                self.animations.animate_hover(&card_id, is_hovered, hover_val);

                // Show tooltip on hover
                if is_hovered {
                    let tooltip_id = ui.id().with(&card_id);
                    egui::show_tooltip_at_pointer(ui.ctx(), egui::LayerId::new(egui::Order::Tooltip, tooltip_id), tooltip_id, |ui| {
                        ui.set_max_width(250.0);
                        ui.label(egui::RichText::new(profile_info.name).size(13.0).color(TEXT_PRIMARY).strong());
                        ui.add_space(4.0);
                        ui.label(egui::RichText::new(profile_info.description).size(11.0).color(TEXT_SECONDARY));
                        ui.add_space(8.0);
                        ui.label(egui::RichText::new(profile_info.settings_summary).size(10.0).color(TEXT_MUTED));
                        ui.add_space(6.0);
                        ui.horizontal(|ui| {
                            egui::Frame::none()
                                .fill(ACCENT_PRIMARY.gamma_multiply(0.15))
                                .rounding(4.0)
                                .inner_margin(egui::Margin::symmetric(6.0, 2.0))
                                .show(ui, |ui| {
                                    ui.label(egui::RichText::new(profile_info.fps_target).size(10.0).color(ACCENT_PRIMARY));
                                });
                            ui.add_space(4.0);
                            ui.label(egui::RichText::new(format!("Best for: {}", profile_info.best_for)).size(10.0).color(TEXT_MUTED));
                        });
                    });
                }

                if response.response.interact(egui::Sense::click()).clicked() {
                    new_profile = Some(profile);
                }
            }
        });

        if let Some(profile) = new_profile {
            self.selected_profile = profile;
            self.apply_profile_preset();
            self.mark_dirty();
        }

        // ─────────────────────────────────────────────────────────────
        // ROBLOX FPS SETTINGS
        // ─────────────────────────────────────────────────────────────
        ui.add_space(16.0);

        let current_fps = self.state.config.roblox_settings.target_fps;
        let is_uncapped = current_fps >= 9999;
        let fps_display = if is_uncapped { "Uncapped".to_string() } else { format!("{}", current_fps) };

        egui::Frame::none()
            .fill(BG_CARD).stroke(egui::Stroke::new(1.0, BG_ELEVATED))
            .rounding(12.0).inner_margin(20.0)
            .show(ui, |ui| {
                ui.set_min_width(ui.available_width());
                ui.label(egui::RichText::new("Roblox FPS Settings").size(14.0).color(TEXT_PRIMARY).strong());
                ui.add_space(12.0);

                ui.horizontal(|ui| {
                    ui.label(egui::RichText::new("Target FPS").size(13.0).color(TEXT_SECONDARY));
                    ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                        ui.label(egui::RichText::new(&fps_display).size(14.0).color(ACCENT_PRIMARY).strong());
                    });
                });

                ui.add_space(8.0);
                if !is_uncapped {
                    if ui.add(egui::Slider::new(&mut self.state.config.roblox_settings.target_fps, 30..=360).show_value(false)).changed() {
                        self.mark_dirty();
                    }
                } else {
                    ui.add_enabled(false, egui::Slider::new(&mut 360u32.clone(), 30..=360).show_value(false));
                }

                ui.add_space(12.0);
                ui.horizontal(|ui| {
                    for fps in [60, 120, 144, 240] {
                        let is_sel = current_fps == fps;
                        let (bg, text) = if is_sel { (ACCENT_PRIMARY, TEXT_PRIMARY) } else { (BG_ELEVATED, TEXT_SECONDARY) };
                        if ui.add(
                            egui::Button::new(egui::RichText::new(format!("{}", fps)).size(11.0).color(text))
                                .fill(bg).rounding(4.0).min_size(egui::vec2(44.0, 28.0))
                        ).clicked() {
                            self.state.config.roblox_settings.target_fps = fps;
                            self.mark_dirty();
                        }
                    }
                    let (bg, text) = if is_uncapped { (ACCENT_PRIMARY, TEXT_PRIMARY) } else { (BG_ELEVATED, TEXT_SECONDARY) };
                    if ui.add(
                        egui::Button::new(egui::RichText::new("Max").size(11.0).color(text))
                            .fill(bg).rounding(4.0).min_size(egui::vec2(44.0, 28.0))
                    ).clicked() {
                        self.state.config.roblox_settings.target_fps = 9999;
                        self.mark_dirty();
                    }
                });

                ui.add_space(8.0);
                ui.label(egui::RichText::new("FPS settings are protected from Roblox overwriting them").size(10.0).color(STATUS_CONNECTED));

                // ─────────────────────────────────────────────────────────────
                // GRAPHICS QUALITY SLIDER
                // ─────────────────────────────────────────────────────────────
                ui.add_space(16.0);
                ui.separator();
                ui.add_space(12.0);

                let current_quality = self.state.config.roblox_settings.graphics_quality.to_level();
                let quality_display = if current_quality == 0 { "Auto".to_string() } else { format!("Level {}", current_quality) };

                ui.horizontal(|ui| {
                    ui.label(egui::RichText::new("Graphics Quality").size(13.0).color(TEXT_SECONDARY));
                    ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                        ui.label(egui::RichText::new(&quality_display).size(14.0).color(ACCENT_CYAN).strong());
                    });
                });

                ui.add_space(8.0);

                // Slider for graphics quality (1-10)
                let mut quality_level = current_quality.max(1) as i32; // Ensure min of 1 for slider
                if ui.add(egui::Slider::new(&mut quality_level, 1..=10).show_value(false)).changed() {
                    self.state.config.roblox_settings.graphics_quality = GraphicsQuality::from_level(quality_level);
                    // Switch to Custom profile when manually changing graphics
                    if self.selected_profile != OptimizationProfile::Custom {
                        self.selected_profile = OptimizationProfile::Custom;
                    }
                    self.mark_dirty();
                }

                ui.add_space(12.0);

                // Quick preset buttons for common quality levels
                ui.horizontal(|ui| {
                    for (label, level) in [("1", 1), ("3", 3), ("5", 5), ("7", 7), ("10", 10)] {
                        let is_sel = current_quality == level;
                        let (bg, text) = if is_sel { (ACCENT_CYAN, TEXT_PRIMARY) } else { (BG_ELEVATED, TEXT_SECONDARY) };
                        if ui.add(
                            egui::Button::new(egui::RichText::new(label).size(11.0).color(text))
                                .fill(bg).rounding(4.0).min_size(egui::vec2(36.0, 28.0))
                        ).clicked() {
                            self.state.config.roblox_settings.graphics_quality = GraphicsQuality::from_level(level);
                            if self.selected_profile != OptimizationProfile::Custom {
                                self.selected_profile = OptimizationProfile::Custom;
                            }
                            self.mark_dirty();
                        }
                    }
                });

                ui.add_space(8.0);
                ui.horizontal(|ui| {
                    ui.label(egui::RichText::new("💡").size(10.0));
                    ui.label(egui::RichText::new("Lower = better FPS, Higher = better visuals").size(10.0).color(TEXT_MUTED));
                });
            });

        // ─────────────────────────────────────────────────────────────
        // SYSTEM BOOSTS (Tier 1)
        // ─────────────────────────────────────────────────────────────
        ui.add_space(16.0);

        egui::Frame::none()
            .fill(BG_CARD).stroke(egui::Stroke::new(1.0, BG_ELEVATED))
            .rounding(12.0).inner_margin(20.0)
            .show(ui, |ui| {
                ui.set_min_width(ui.available_width());
                ui.horizontal(|ui| {
                    ui.label(egui::RichText::new("System Boosts").size(14.0).color(TEXT_PRIMARY).strong());
                    ui.add_space(8.0);

                    // Tier 1 badge with tooltip
                    let tier_badge = egui::Frame::none()
                        .fill(STATUS_CONNECTED.gamma_multiply(0.15))
                        .rounding(4.0)
                        .inner_margin(egui::Margin::symmetric(6.0, 2.0))
                        .show(ui, |ui| {
                            ui.label(egui::RichText::new("TIER 1 - SAFE").size(10.0).color(STATUS_CONNECTED));
                        });
                    if tier_badge.response.hovered() {
                        let tooltip_id = ui.id().with("tier1_tip");
                        egui::show_tooltip_at_pointer(ui.ctx(), egui::LayerId::new(egui::Order::Tooltip, tooltip_id), tooltip_id, |ui| {
                            ui.set_max_width(280.0);
                            ui.label(egui::RichText::new(tier_info::TIER_1_TITLE).size(12.0).color(TEXT_PRIMARY).strong());
                            ui.add_space(4.0);
                            ui.label(egui::RichText::new(tier_info::TIER_1_DESC).size(11.0).color(TEXT_SECONDARY));
                        });
                    }
                });
                ui.add_space(4.0);
                ui.label(egui::RichText::new("Safe optimizations with no side effects").size(11.0).color(TEXT_MUTED));
                ui.add_space(12.0);

                self.render_toggle_row_with_info(ui, &boost_info::HIGH_PRIORITY,
                    self.state.config.system_optimization.set_high_priority, |app| {
                    app.state.config.system_optimization.set_high_priority = !app.state.config.system_optimization.set_high_priority;
                });
                ui.add_space(10.0);

                self.render_toggle_row_with_info(ui, &boost_info::TIMER_RESOLUTION,
                    self.state.config.system_optimization.timer_resolution_1ms, |app| {
                    app.state.config.system_optimization.timer_resolution_1ms = !app.state.config.system_optimization.timer_resolution_1ms;
                });
                ui.add_space(10.0);

                self.render_toggle_row_with_info(ui, &boost_info::MMCSS,
                    self.state.config.system_optimization.mmcss_gaming_profile, |app| {
                    app.state.config.system_optimization.mmcss_gaming_profile = !app.state.config.system_optimization.mmcss_gaming_profile;
                });
                ui.add_space(10.0);

                self.render_toggle_row_with_info(ui, &boost_info::GAME_MODE,
                    self.state.config.system_optimization.game_mode_enabled, |app| {
                    app.state.config.system_optimization.game_mode_enabled = !app.state.config.system_optimization.game_mode_enabled;
                });
            });

        // ─────────────────────────────────────────────────────────────
        // NETWORK BOOSTS (Tier 1)
        // ─────────────────────────────────────────────────────────────
        ui.add_space(16.0);

        egui::Frame::none()
            .fill(BG_CARD).stroke(egui::Stroke::new(1.0, BG_ELEVATED))
            .rounding(12.0).inner_margin(20.0)
            .show(ui, |ui| {
                ui.set_min_width(ui.available_width());
                ui.horizontal(|ui| {
                    ui.label(egui::RichText::new("Network Boosts").size(14.0).color(TEXT_PRIMARY).strong());
                    ui.add_space(8.0);

                    // Tier 1 badge with tooltip
                    let tier_badge = egui::Frame::none()
                        .fill(STATUS_CONNECTED.gamma_multiply(0.15))
                        .rounding(4.0)
                        .inner_margin(egui::Margin::symmetric(6.0, 2.0))
                        .show(ui, |ui| {
                            ui.label(egui::RichText::new("TIER 1 - SAFE").size(10.0).color(STATUS_CONNECTED));
                        });
                    if tier_badge.response.hovered() {
                        let tooltip_id = ui.id().with("tier1_net_tip");
                        egui::show_tooltip_at_pointer(ui.ctx(), egui::LayerId::new(egui::Order::Tooltip, tooltip_id), tooltip_id, |ui| {
                            ui.set_max_width(280.0);
                            ui.label(egui::RichText::new(tier_info::TIER_1_TITLE).size(12.0).color(TEXT_PRIMARY).strong());
                            ui.add_space(4.0);
                            ui.label(egui::RichText::new(tier_info::TIER_1_DESC).size(11.0).color(TEXT_SECONDARY));
                        });
                    }
                });
                ui.add_space(4.0);
                ui.label(egui::RichText::new("Lower latency for online games").size(11.0).color(TEXT_MUTED));
                ui.add_space(12.0);

                self.render_toggle_row_with_info(ui, &boost_info::DISABLE_NAGLE,
                    self.state.config.network_settings.disable_nagle, |app| {
                    app.state.config.network_settings.disable_nagle = !app.state.config.network_settings.disable_nagle;
                });
                ui.add_space(10.0);

                self.render_toggle_row_with_info(ui, &boost_info::NETWORK_THROTTLING,
                    self.state.config.network_settings.disable_network_throttling, |app| {
                    app.state.config.network_settings.disable_network_throttling = !app.state.config.network_settings.disable_network_throttling;
                });
                ui.add_space(10.0);

                self.render_toggle_row_with_info(ui, &boost_info::OPTIMIZE_MTU,
                    self.state.config.network_settings.optimize_mtu, |app| {
                    app.state.config.network_settings.optimize_mtu = !app.state.config.network_settings.optimize_mtu;
                });
            });

        // ─────────────────────────────────────────────────────────────
        // SYSTEM PROTECTION
        // ─────────────────────────────────────────────────────────────
        ui.add_space(16.0);

        let mut create_restore_point = false;
        let mut open_restore = false;

        egui::Frame::none()
            .fill(BG_CARD).stroke(egui::Stroke::new(1.0, BG_ELEVATED))
            .rounding(12.0).inner_margin(20.0)
            .show(ui, |ui| {
                ui.set_min_width(ui.available_width());
                ui.label(egui::RichText::new("System Protection").size(14.0).color(TEXT_PRIMARY).strong());
                ui.add_space(4.0);
                ui.label(egui::RichText::new("Create restore points before making changes").size(11.0).color(TEXT_MUTED));
                ui.add_space(16.0);

                ui.horizontal(|ui| {
                    if ui.add(
                        egui::Button::new(egui::RichText::new("📋 Create Restore Point").size(13.0).color(TEXT_PRIMARY))
                            .fill(ACCENT_PRIMARY).rounding(8.0).min_size(egui::vec2(180.0, 38.0))
                    ).clicked() {
                        create_restore_point = true;
                    }

                    ui.add_space(12.0);

                    if ui.add(
                        egui::Button::new(egui::RichText::new("🔄 Open System Restore").size(13.0).color(TEXT_PRIMARY))
                            .fill(BG_ELEVATED).rounding(8.0).min_size(egui::vec2(180.0, 38.0))
                    ).clicked() {
                        open_restore = true;
                    }
                });

                if let Some((msg, color, _)) = &self.restore_point_status {
                    ui.add_space(12.0);
                    ui.label(egui::RichText::new(msg).size(12.0).color(*color));
                }
            });

        if create_restore_point {
            match SystemOptimizer::create_restore_point("SwiftTunnel - Before PC Boosts") {
                Ok(desc) => {
                    self.restore_point_status = Some((
                        format!("✓ Restore point created: {}", desc),
                        STATUS_CONNECTED,
                        std::time::Instant::now()
                    ));
                }
                Err(e) => {
                    self.restore_point_status = Some((
                        format!("✗ Failed: {}", e),
                        STATUS_ERROR,
                        std::time::Instant::now()
                    ));
                }
            }
        }

        if open_restore {
            if let Err(e) = SystemOptimizer::open_system_restore() {
                self.restore_point_status = Some((
                    format!("✗ Failed to open: {}", e),
                    STATUS_ERROR,
                    std::time::Instant::now()
                ));
            }
        }

        // Show status message if any
        if let Some((msg, color, _)) = &self.status_message {
            ui.add_space(16.0);
            ui.label(egui::RichText::new(msg).size(13.0).color(*color));
        }
    }

    fn render_settings_tab(&mut self, ui: &mut egui::Ui) {
        ui.horizontal(|ui| {
            for (label, section) in [("General", SettingsSection::General), ("Performance", SettingsSection::Performance), ("Account", SettingsSection::Account)] {
                let is_active = self.settings_section == section;
                let (bg, text) = if is_active { (BG_ELEVATED, TEXT_PRIMARY) } else { (egui::Color32::TRANSPARENT, TEXT_SECONDARY) };

                if ui.add(
                    egui::Button::new(egui::RichText::new(label).size(13.0).color(text))
                        .fill(bg).rounding(6.0).min_size(egui::vec2(80.0, 32.0))
                ).clicked() {
                    self.settings_section = section;
                }
                ui.add_space(8.0);
            }
        });

        ui.add_space(20.0);

        match self.settings_section {
            SettingsSection::General => self.render_general_settings(ui),
            SettingsSection::Performance => self.render_performance_settings(ui),
            SettingsSection::Account => self.render_account_settings(ui),
        }
    }

    fn render_general_settings(&mut self, ui: &mut egui::Ui) {
        // About section
        egui::Frame::none()
            .fill(BG_CARD).stroke(egui::Stroke::new(1.0, BG_ELEVATED))
            .rounding(12.0).inner_margin(20.0)
            .show(ui, |ui| {
                ui.set_min_width(ui.available_width());
                ui.label(egui::RichText::new("About").size(14.0).color(TEXT_PRIMARY).strong());
                ui.add_space(12.0);
                ui.label(egui::RichText::new(format!("SwiftTunnel v{}", env!("CARGO_PKG_VERSION"))).size(13.0).color(TEXT_PRIMARY));
                ui.label(egui::RichText::new("Game Booster & PC Optimization Suite").size(12.0).color(TEXT_SECONDARY));
                ui.add_space(8.0);
                ui.label(egui::RichText::new("Optimized for Roblox and other games").size(11.0).color(TEXT_MUTED));
            });

        ui.add_space(16.0);

        // Updates section
        let mut check_now = false;
        let mut toggle_auto_check = false;
        let current_auto_check = self.update_settings.auto_check;

        egui::Frame::none()
            .fill(BG_CARD).stroke(egui::Stroke::new(1.0, BG_ELEVATED))
            .rounding(12.0).inner_margin(20.0)
            .show(ui, |ui| {
                ui.set_min_width(ui.available_width());
                ui.label(egui::RichText::new("Updates").size(14.0).color(TEXT_PRIMARY).strong());
                ui.add_space(12.0);

                // Current version and check button
                ui.horizontal(|ui| {
                    ui.label(egui::RichText::new(format!("Current version: {}", env!("CARGO_PKG_VERSION"))).size(12.0).color(TEXT_SECONDARY));

                    ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                        // Check for updates button
                        let update_state = self.update_state.lock().map(|s| s.clone()).unwrap_or(UpdateState::Idle);
                        let is_checking = matches!(update_state, UpdateState::Checking);

                        if is_checking {
                            ui.horizontal(|ui| {
                                ui.spinner();
                                ui.add_space(4.0);
                                ui.label(egui::RichText::new("Checking...").size(11.0).color(TEXT_SECONDARY));
                            });
                        } else {
                            if ui.add(
                                egui::Button::new(egui::RichText::new("Check for Updates").size(11.0).color(TEXT_PRIMARY))
                                    .fill(ACCENT_PRIMARY).rounding(6.0)
                            ).clicked() {
                                check_now = true;
                            }
                        }
                    });
                });

                ui.add_space(12.0);

                // Show update status
                let update_state = self.update_state.lock().map(|s| s.clone()).unwrap_or(UpdateState::Idle);
                match &update_state {
                    UpdateState::UpToDate => {
                        ui.horizontal(|ui| {
                            ui.label(egui::RichText::new("✓").size(12.0).color(STATUS_CONNECTED));
                            ui.add_space(4.0);
                            ui.label(egui::RichText::new("You're on the latest version").size(12.0).color(STATUS_CONNECTED));
                        });
                    }
                    UpdateState::Available(info) => {
                        ui.horizontal(|ui| {
                            ui.label(egui::RichText::new("🔄").size(12.0));
                            ui.add_space(4.0);
                            ui.label(egui::RichText::new(format!("Update v{} available", info.version)).size(12.0).color(ACCENT_PRIMARY));
                        });
                    }
                    UpdateState::Failed(msg) => {
                        ui.horizontal(|ui| {
                            ui.label(egui::RichText::new("⚠").size(12.0).color(STATUS_ERROR));
                            ui.add_space(4.0);
                            ui.label(egui::RichText::new(msg).size(12.0).color(STATUS_ERROR));
                        });
                    }
                    _ => {}
                }

                ui.add_space(12.0);

                // Auto-check toggle
                ui.horizontal(|ui| {
                    ui.vertical(|ui| {
                        ui.label(egui::RichText::new("Check for updates on startup").size(12.0).color(TEXT_PRIMARY));
                        ui.label(egui::RichText::new("Automatically check for new versions when the app starts").size(10.0).color(TEXT_MUTED));
                    });
                    ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                        let size = egui::vec2(44.0, 24.0);
                        let (rect, response) = ui.allocate_exact_size(size, egui::Sense::click());
                        if response.clicked() {
                            toggle_auto_check = true;
                        }
                        let bg = if current_auto_check { ACCENT_PRIMARY } else { BG_ELEVATED };
                        let knob_x = if current_auto_check { rect.right() - 12.0 } else { rect.left() + 12.0 };
                        ui.painter().rect_filled(rect, 12.0, bg);
                        ui.painter().circle_filled(egui::pos2(knob_x, rect.center().y), 8.0, TEXT_PRIMARY);
                    });
                });
            });

        ui.add_space(16.0);

        // System Tray section
        let mut toggle_minimize_to_tray = false;
        let current_minimize_to_tray = self.minimize_to_tray;

        egui::Frame::none()
            .fill(BG_CARD).stroke(egui::Stroke::new(1.0, BG_ELEVATED))
            .rounding(12.0).inner_margin(20.0)
            .show(ui, |ui| {
                ui.set_min_width(ui.available_width());
                ui.label(egui::RichText::new("System Tray").size(14.0).color(TEXT_PRIMARY).strong());
                ui.add_space(12.0);

                // Minimize to tray toggle
                ui.horizontal(|ui| {
                    ui.vertical(|ui| {
                        ui.label(egui::RichText::new("Minimize to tray on close").size(12.0).color(TEXT_PRIMARY));
                        ui.label(egui::RichText::new("Keep SwiftTunnel running in the background when you close the window").size(10.0).color(TEXT_MUTED));
                    });
                    ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                        let size = egui::vec2(44.0, 24.0);
                        let (rect, response) = ui.allocate_exact_size(size, egui::Sense::click());
                        if response.clicked() {
                            toggle_minimize_to_tray = true;
                        }
                        let bg = if current_minimize_to_tray { ACCENT_PRIMARY } else { BG_ELEVATED };
                        let knob_x = if current_minimize_to_tray { rect.right() - 12.0 } else { rect.left() + 12.0 };
                        ui.painter().rect_filled(rect, 12.0, bg);
                        ui.painter().circle_filled(egui::pos2(knob_x, rect.center().y), 8.0, TEXT_PRIMARY);
                    });
                });

                ui.add_space(8.0);
                ui.label(egui::RichText::new("Tip: Click the tray icon to show the window. Right-click for more options.").size(10.0).color(TEXT_MUTED).italics());
            });

        // Handle actions after UI rendering
        if check_now {
            self.start_update_check();
        }
        if toggle_auto_check {
            self.update_settings.auto_check = !self.update_settings.auto_check;
            self.mark_dirty();
        }
        if toggle_minimize_to_tray {
            self.minimize_to_tray = !self.minimize_to_tray;
            // Also update the tray's setting
            if let Some(ref tray) = self.system_tray {
                tray.set_minimize_to_tray(self.minimize_to_tray);
            }
            self.mark_dirty();
        }
    }

    fn render_performance_settings(&mut self, ui: &mut egui::Ui) {
        // Performance settings are now in the Boost tab
        // This section shows a summary and link to Boost tab

        egui::Frame::none()
            .fill(BG_CARD).stroke(egui::Stroke::new(1.0, BG_ELEVATED))
            .rounding(12.0).inner_margin(20.0)
            .show(ui, |ui| {
                ui.set_min_width(ui.available_width());
                ui.label(egui::RichText::new("Performance Boosts").size(14.0).color(TEXT_PRIMARY).strong());
                ui.add_space(8.0);
                ui.label(egui::RichText::new("All boost settings are now on the Boost tab for easier access.").size(12.0).color(TEXT_SECONDARY));
                ui.add_space(16.0);

                // Current status summary
                let fps_val = self.state.config.roblox_settings.target_fps;
                let fps = if fps_val >= 9999 { "Uncapped".to_string() } else { fps_val.to_string() };
                let system_boosts = [
                    self.state.config.system_optimization.set_high_priority,
                    self.state.config.system_optimization.timer_resolution_1ms,
                    self.state.config.system_optimization.mmcss_gaming_profile,
                    self.state.config.system_optimization.game_mode_enabled,
                ].iter().filter(|&&x| x).count();
                let network_boosts = [
                    self.state.config.network_settings.disable_nagle,
                    self.state.config.network_settings.disable_network_throttling,
                    self.state.config.network_settings.optimize_mtu,
                ].iter().filter(|&&x| x).count();

                ui.horizontal(|ui| {
                    ui.label(egui::RichText::new("FPS Target:").size(12.0).color(TEXT_SECONDARY));
                    ui.label(egui::RichText::new(&fps).size(12.0).color(ACCENT_PRIMARY));
                });
                ui.horizontal(|ui| {
                    ui.label(egui::RichText::new("System Boosts:").size(12.0).color(TEXT_SECONDARY));
                    ui.label(egui::RichText::new(format!("{}/4 enabled", system_boosts)).size(12.0).color(ACCENT_PRIMARY));
                });
                ui.horizontal(|ui| {
                    ui.label(egui::RichText::new("Network Boosts:").size(12.0).color(TEXT_SECONDARY));
                    ui.label(egui::RichText::new(format!("{}/3 enabled", network_boosts)).size(12.0).color(ACCENT_PRIMARY));
                });

                ui.add_space(16.0);

                let mut go_to_boost = false;
                if ui.add(
                    egui::Button::new(egui::RichText::new("⚡ Go to Boost Tab").size(13.0).color(TEXT_PRIMARY))
                        .fill(ACCENT_PRIMARY).rounding(8.0).min_size(egui::vec2(150.0, 36.0))
                ).clicked() {
                    go_to_boost = true;
                }

                if go_to_boost {
                    self.current_tab = Tab::Boost;
                }
            });
    }

    /// Helper function to render a toggle row with label and description
    /// Render toggle row with smooth animation
    fn render_toggle_row(&mut self, ui: &mut egui::Ui, label: &str, description: &str, value: bool, on_toggle: fn(&mut Self)) {
        let toggle_id = label.to_string();
        self.render_animated_toggle_row(ui, &toggle_id, label, description, value, on_toggle, None);
    }

    /// Render toggle row with expandable info panel
    fn render_toggle_row_with_info(&mut self, ui: &mut egui::Ui, info: &BoostInfo, value: bool, on_toggle: fn(&mut Self)) {
        let toggle_id = info.id.to_string();
        self.render_animated_toggle_row(
            ui,
            &toggle_id,
            info.title,
            info.short_desc,
            value,
            on_toggle,
            Some(info)
        );
    }

    /// Core animated toggle row renderer
    fn render_animated_toggle_row(
        &mut self,
        ui: &mut egui::Ui,
        toggle_id: &str,
        label: &str,
        description: &str,
        value: bool,
        on_toggle: fn(&mut Self),
        info: Option<&BoostInfo>
    ) {
        let mut should_toggle = false;
        let mut toggle_info_panel = false;
        let is_expanded = self.expanded_boost_info.contains(toggle_id);

        ui.vertical(|ui| {
            ui.horizontal(|ui| {
                ui.vertical(|ui| {
                    ui.horizontal(|ui| {
                        ui.label(egui::RichText::new(label).size(13.0).color(TEXT_PRIMARY));

                        // Info button (?) if we have boost info
                        if info.is_some() {
                            let info_btn = ui.add(
                                egui::Button::new(egui::RichText::new("?").size(10.0).color(TEXT_MUTED))
                                    .fill(if is_expanded { BG_HOVER } else { BG_ELEVATED })
                                    .rounding(8.0)
                                    .min_size(egui::vec2(18.0, 18.0))
                            );
                            if info_btn.clicked() {
                                toggle_info_panel = true;
                            }
                            if info_btn.hovered() {
                                let tooltip_id = ui.id().with("tip");
                                egui::show_tooltip_at_pointer(ui.ctx(), egui::LayerId::new(egui::Order::Tooltip, tooltip_id), tooltip_id, |ui| {
                                    ui.label(egui::RichText::new("Click for more details").size(11.0).color(TEXT_SECONDARY));
                                });
                            }
                        }
                    });
                    ui.label(egui::RichText::new(description).size(11.0).color(TEXT_MUTED));
                });

                ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                    // Animated toggle switch
                    let size = egui::vec2(44.0, 24.0);
                    let (rect, response) = ui.allocate_exact_size(size, egui::Sense::click());

                    if response.clicked() {
                        should_toggle = true;
                        // Start animation
                        let current = self.animations.get_toggle_value(toggle_id, value);
                        self.animations.animate_toggle(toggle_id, !value, current);
                    }

                    // Get animated value
                    let anim_value = self.animations.get_toggle_value(toggle_id, value);

                    // Interpolate background color (BG_ELEVATED -> ACCENT_PRIMARY)
                    let bg = egui::Color32::from_rgb(
                        (BG_ELEVATED.r() as f32 + (ACCENT_PRIMARY.r() as f32 - BG_ELEVATED.r() as f32) * anim_value) as u8,
                        (BG_ELEVATED.g() as f32 + (ACCENT_PRIMARY.g() as f32 - BG_ELEVATED.g() as f32) * anim_value) as u8,
                        (BG_ELEVATED.b() as f32 + (ACCENT_PRIMARY.b() as f32 - BG_ELEVATED.b() as f32) * anim_value) as u8,
                    );

                    // Interpolate knob position
                    let knob_x = rect.left() + 12.0 + (rect.width() - 24.0) * anim_value;

                    ui.painter().rect_filled(rect, 12.0, bg);
                    ui.painter().circle_filled(egui::pos2(knob_x, rect.center().y), 8.0, TEXT_PRIMARY);
                });
            });

            // Expanded info panel
            if is_expanded {
                if let Some(boost_info) = info {
                    ui.add_space(8.0);
                    egui::Frame::none()
                        .fill(BG_ELEVATED.gamma_multiply(0.7))
                        .rounding(8.0)
                        .inner_margin(12.0)
                        .show(ui, |ui| {
                            ui.set_min_width(ui.available_width());

                            // Full description
                            ui.label(egui::RichText::new(boost_info.long_desc).size(11.0).color(TEXT_SECONDARY));
                            ui.add_space(8.0);

                            // Impact & risk in a row
                            ui.horizontal(|ui| {
                                // Impact badge
                                egui::Frame::none()
                                    .fill(STATUS_CONNECTED.gamma_multiply(0.15))
                                    .rounding(4.0)
                                    .inner_margin(egui::Margin::symmetric(6.0, 3.0))
                                    .show(ui, |ui| {
                                        ui.label(egui::RichText::new(boost_info.impact).size(10.0).color(STATUS_CONNECTED));
                                    });

                                // Risk level badge
                                let risk_color = match boost_info.risk_level {
                                    RiskLevel::Safe => STATUS_CONNECTED,
                                    RiskLevel::LowRisk => STATUS_WARNING,
                                    RiskLevel::MediumRisk => STATUS_ERROR,
                                };
                                egui::Frame::none()
                                    .fill(risk_color.gamma_multiply(0.15))
                                    .rounding(4.0)
                                    .inner_margin(egui::Margin::symmetric(6.0, 3.0))
                                    .show(ui, |ui| {
                                        ui.label(egui::RichText::new(boost_info.risk_level.label()).size(10.0).color(risk_color));
                                    });

                                // Admin required warning
                                if boost_info.requires_admin {
                                    egui::Frame::none()
                                        .fill(STATUS_WARNING.gamma_multiply(0.15))
                                        .rounding(4.0)
                                        .inner_margin(egui::Margin::symmetric(6.0, 3.0))
                                        .show(ui, |ui| {
                                            ui.label(egui::RichText::new("⚡ Admin").size(10.0).color(STATUS_WARNING));
                                        });
                                }
                            });
                        });
                }
            }
        });

        // Handle toggle outside the closure
        if should_toggle {
            on_toggle(self);
            self.mark_dirty();
        }
        if toggle_info_panel {
            if is_expanded {
                self.expanded_boost_info.remove(toggle_id);
            } else {
                self.expanded_boost_info.insert(toggle_id.to_string());
            }
            self.mark_dirty();
        }
    }

    fn render_account_settings(&mut self, ui: &mut egui::Ui) {
        match &self.auth_state {
            AuthState::LoggedOut | AuthState::Error(_) => self.render_login_form(ui),
            AuthState::LoggingIn => self.render_login_pending(ui),
            AuthState::AwaitingOAuthCallback(_) => self.render_awaiting_oauth_callback(ui),
            AuthState::LoggedIn(_) => self.render_logged_in(ui),
        }
    }

    fn render_login_form(&mut self, ui: &mut egui::Ui) {
        let can_login = !self.login_email.is_empty() && !self.login_password.is_empty();
        let mut do_login = false;
        let mut open_signup = false;

        egui::Frame::none()
            .fill(BG_CARD).stroke(egui::Stroke::new(1.0, BG_ELEVATED))
            .rounding(12.0).inner_margin(20.0)
            .show(ui, |ui| {
                ui.set_min_width(ui.available_width());
                ui.label(egui::RichText::new("Sign In").size(16.0).color(TEXT_PRIMARY).strong());
                ui.add_space(16.0);

                ui.label(egui::RichText::new("Email").size(12.0).color(TEXT_SECONDARY));
                ui.add_space(4.0);
                ui.add(egui::TextEdit::singleline(&mut self.login_email).hint_text("you@example.com").desired_width(f32::INFINITY));

                ui.add_space(12.0);
                ui.label(egui::RichText::new("Password").size(12.0).color(TEXT_SECONDARY));
                ui.add_space(4.0);
                ui.add(egui::TextEdit::singleline(&mut self.login_password).hint_text("********").password(true).desired_width(f32::INFINITY));

                ui.add_space(20.0);
                let btn_color = if can_login { ACCENT_PRIMARY } else { BG_ELEVATED };
                if ui.add(
                    egui::Button::new(egui::RichText::new("Sign In").size(14.0).color(TEXT_PRIMARY))
                        .fill(btn_color).rounding(8.0).min_size(egui::vec2(f32::INFINITY, 44.0))
                ).clicked() && can_login {
                    do_login = true;
                }

                ui.add_space(12.0);
                ui.horizontal(|ui| {
                    ui.label(egui::RichText::new("No account?").size(12.0).color(TEXT_SECONDARY));
                    if ui.add(egui::Label::new(egui::RichText::new("Sign up").size(12.0).color(ACCENT_PRIMARY).underline()).sense(egui::Sense::click())).clicked() {
                        open_signup = true;
                    }
                });
            });

        if do_login { self.start_login(); }
        if open_signup { let _ = open::that("https://swifttunnel.net/signup"); }

        if let Some(error) = &self.auth_error.clone() {
            ui.add_space(12.0);
            egui::Frame::none()
                .fill(STATUS_ERROR.gamma_multiply(0.15)).rounding(8.0).inner_margin(12.0)
                .show(ui, |ui| {
                    ui.label(egui::RichText::new(error).size(12.0).color(STATUS_ERROR));
                });
        }
    }

    fn render_full_login_screen(&mut self, ui: &mut egui::Ui) {
        let can_login = !self.login_email.is_empty() && !self.login_password.is_empty();
        let mut do_login = false;
        let mut open_signup = false;
        let mut open_forgot_password = false;

        let available = ui.available_size();
        let card_max_width: f32 = 420.0;

        // Center the login content vertically and horizontally
        ui.vertical_centered(|ui| {
            // Vertical centering
            let card_estimated_height = 520.0;
            let top_space = ((available.y - card_estimated_height) / 2.0).max(20.0);
            ui.add_space(top_space);

            // Constrain content width
            ui.allocate_ui_with_layout(
                egui::vec2(card_max_width.min(available.x - 48.0), available.y),
                egui::Layout::top_down(egui::Align::LEFT),
                |ui| {
                    // ─────────────────────────────────────────────────────────────
                    // HEADER: Logo + SwiftTunnel text
                    // ─────────────────────────────────────────────────────────────
                    ui.horizontal(|ui| {
                        // Draw wave/tunnel logo icon
                        let logo_size = 32.0;
                        let (rect, _) = ui.allocate_exact_size(egui::vec2(logo_size, logo_size), egui::Sense::hover());
                        let center = rect.center();

                        // Draw stylized wave/tunnel shape
                        let wave_color = ACCENT_CYAN;
                        ui.painter().circle_filled(center, logo_size * 0.45, wave_color.gamma_multiply(0.2));

                        // Draw curved lines for wave effect
                        for i in 0..3 {
                            let offset = (i as f32 - 1.0) * 5.0;
                            let start = egui::pos2(center.x - 8.0, center.y + offset);
                            let end = egui::pos2(center.x + 8.0, center.y + offset);
                            let control1 = egui::pos2(center.x - 4.0, center.y + offset - 4.0);
                            let control2 = egui::pos2(center.x + 4.0, center.y + offset + 4.0);

                            let points = [start, control1, control2, end];
                            let stroke = egui::Stroke::new(2.0, wave_color);
                            ui.painter().add(egui::Shape::CubicBezier(egui::epaint::CubicBezierShape::from_points_stroke(
                                points,
                                false,
                                egui::Color32::TRANSPARENT,
                                stroke,
                            )));
                        }

                        ui.add_space(8.0);
                        ui.label(egui::RichText::new("SwiftTunnel")
                            .size(22.0)
                            .color(TEXT_PRIMARY)
                            .strong());
                    });

                    ui.add_space(40.0);

                    // ─────────────────────────────────────────────────────────────
                    // WELCOME SECTION
                    // ─────────────────────────────────────────────────────────────
                    ui.horizontal(|ui| {
                        // Sparkle icon (✦)
                        ui.label(egui::RichText::new("✦")
                            .size(14.0)
                            .color(ACCENT_CYAN));
                        ui.add_space(4.0);
                        ui.label(egui::RichText::new("Welcome back")
                            .size(14.0)
                            .color(ACCENT_CYAN));
                    });

                    ui.add_space(8.0);
                    ui.label(egui::RichText::new("Sign in to your account")
                        .size(28.0)
                        .color(TEXT_PRIMARY)
                        .strong());

                    ui.add_space(8.0);
                    ui.label(egui::RichText::new("Enter your credentials to access your dashboard")
                        .size(14.0)
                        .color(TEXT_SECONDARY));

                    ui.add_space(32.0);

                    // ─────────────────────────────────────────────────────────────
                    // EMAIL FIELD
                    // ─────────────────────────────────────────────────────────────
                    ui.label(egui::RichText::new("Email address")
                        .size(14.0)
                        .color(TEXT_PRIMARY));
                    ui.add_space(8.0);

                    // Custom input field with icon
                    egui::Frame::none()
                        .fill(BG_INPUT)
                        .stroke(egui::Stroke::new(1.0, BG_ELEVATED))
                        .rounding(10.0)
                        .inner_margin(egui::Margin::symmetric(16.0, 14.0))
                        .show(ui, |ui| {
                            ui.set_min_width(ui.available_width());
                            ui.horizontal(|ui| {
                                // Mail icon
                                ui.label(egui::RichText::new("✉")
                                    .size(16.0)
                                    .color(TEXT_MUTED));
                                ui.add_space(12.0);

                                // Email input
                                let email_edit = egui::TextEdit::singleline(&mut self.login_email)
                                    .hint_text(egui::RichText::new("your.email@example.com").color(TEXT_MUTED))
                                    .desired_width(f32::INFINITY)
                                    .frame(false)
                                    .text_color(TEXT_PRIMARY);
                                ui.add(email_edit);
                            });
                        });

                    ui.add_space(20.0);

                    // ─────────────────────────────────────────────────────────────
                    // PASSWORD FIELD
                    // ─────────────────────────────────────────────────────────────
                    ui.horizontal(|ui| {
                        ui.label(egui::RichText::new("Password")
                            .size(14.0)
                            .color(TEXT_PRIMARY));

                        ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                            if ui.add(
                                egui::Label::new(
                                    egui::RichText::new("Forgot password?")
                                        .size(14.0)
                                        .color(ACCENT_PRIMARY)
                                ).sense(egui::Sense::click())
                            ).clicked() {
                                open_forgot_password = true;
                            }
                        });
                    });
                    ui.add_space(8.0);

                    // Custom password field with icon
                    egui::Frame::none()
                        .fill(BG_INPUT)
                        .stroke(egui::Stroke::new(1.0, BG_ELEVATED))
                        .rounding(10.0)
                        .inner_margin(egui::Margin::symmetric(16.0, 14.0))
                        .show(ui, |ui| {
                            ui.set_min_width(ui.available_width());
                            ui.horizontal(|ui| {
                                // Lock icon
                                ui.label(egui::RichText::new("🔒")
                                    .size(16.0)
                                    .color(TEXT_MUTED));
                                ui.add_space(12.0);

                                // Password input
                                let password_edit = egui::TextEdit::singleline(&mut self.login_password)
                                    .hint_text(egui::RichText::new("Enter your password").color(TEXT_MUTED))
                                    .password(true)
                                    .desired_width(f32::INFINITY)
                                    .frame(false)
                                    .text_color(TEXT_PRIMARY);
                                ui.add(password_edit);
                            });
                        });

                    ui.add_space(28.0);

                    // ─────────────────────────────────────────────────────────────
                    // SIGN IN BUTTON
                    // ─────────────────────────────────────────────────────────────
                    let btn_color = if can_login { ACCENT_PRIMARY } else { ACCENT_PRIMARY.gamma_multiply(0.5) };

                    let response = ui.add_sized(
                        egui::vec2(ui.available_width(), 52.0),
                        egui::Button::new(
                            egui::RichText::new("Sign in   →")
                                .size(16.0)
                                .color(egui::Color32::WHITE)
                                .strong()
                        )
                        .fill(btn_color)
                        .rounding(10.0)
                    );

                    if response.clicked() && can_login {
                        do_login = true;
                    }

                    ui.add_space(20.0);

                    // ─────────────────────────────────────────────────────────────
                    // DIVIDER
                    // ─────────────────────────────────────────────────────────────
                    ui.horizontal(|ui| {
                        let available_width = ui.available_width();
                        let line_width = (available_width - 120.0) / 2.0;

                        ui.add_sized(
                            egui::vec2(line_width, 1.0),
                            egui::Separator::default().horizontal()
                        );
                        ui.add_space(8.0);
                        ui.label(egui::RichText::new("or continue with")
                            .size(12.0)
                            .color(TEXT_MUTED));
                        ui.add_space(8.0);
                        ui.add_sized(
                            egui::vec2(line_width, 1.0),
                            egui::Separator::default().horizontal()
                        );
                    });

                    ui.add_space(20.0);

                    // ─────────────────────────────────────────────────────────────
                    // GOOGLE SIGN IN BUTTON
                    // ─────────────────────────────────────────────────────────────
                    let google_response = ui.add_sized(
                        egui::vec2(ui.available_width(), 48.0),
                        egui::Button::new(
                            egui::RichText::new("🔵  Sign in with Google")
                                .size(15.0)
                                .color(TEXT_PRIMARY)
                        )
                        .fill(BG_ELEVATED)
                        .stroke(egui::Stroke::new(1.0, BG_HOVER))
                        .rounding(10.0)
                    );

                    if google_response.clicked() {
                        self.start_google_login();
                    }

                    ui.add_space(24.0);

                    // ─────────────────────────────────────────────────────────────
                    // SIGN UP LINK
                    // ─────────────────────────────────────────────────────────────
                    ui.vertical_centered(|ui| {
                        ui.horizontal(|ui| {
                            ui.label(egui::RichText::new("Don't have an account?")
                                .size(14.0)
                                .color(TEXT_SECONDARY));
                            ui.add_space(4.0);
                            if ui.add(
                                egui::Label::new(
                                    egui::RichText::new("Sign up")
                                        .size(14.0)
                                        .color(ACCENT_PRIMARY)
                                ).sense(egui::Sense::click())
                            ).clicked() {
                                open_signup = true;
                            }
                        });
                    });

                    // ─────────────────────────────────────────────────────────────
                    // ERROR MESSAGE
                    // ─────────────────────────────────────────────────────────────
                    if let Some(error) = &self.auth_error.clone() {
                        ui.add_space(20.0);
                        egui::Frame::none()
                            .fill(STATUS_ERROR.gamma_multiply(0.15))
                            .stroke(egui::Stroke::new(1.0, STATUS_ERROR.gamma_multiply(0.3)))
                            .rounding(10.0)
                            .inner_margin(16.0)
                            .show(ui, |ui| {
                                ui.set_min_width(ui.available_width());
                                ui.horizontal(|ui| {
                                    ui.label(egui::RichText::new("⚠")
                                        .size(14.0)
                                        .color(STATUS_ERROR));
                                    ui.add_space(8.0);
                                    ui.label(egui::RichText::new(error)
                                        .size(13.0)
                                        .color(STATUS_ERROR));
                                });
                            });
                    }
                }
            );
        });

        if do_login { self.start_login(); }
        if open_signup { let _ = open::that("https://swifttunnel.net/signup"); }
        if open_forgot_password { let _ = open::that("https://swifttunnel.net/forgot-password"); }
    }

    fn render_login_pending(&self, ui: &mut egui::Ui) {
        let available = ui.available_size();
        let is_large_screen = available.x > 800.0 && available.y > 600.0;
        let card_max_width: f32 = if is_large_screen { 400.0 } else { 320.0 };

        ui.vertical_centered(|ui| {
            // Center vertically
            let top_space = ((available.y - 200.0) / 2.0 - 60.0).max(40.0);
            ui.add_space(top_space);

            ui.allocate_ui_with_layout(
                egui::vec2(card_max_width.min(available.x - 40.0), available.y),
                egui::Layout::top_down(egui::Align::Center),
                |ui| {
                    egui::Frame::none()
                        .fill(BG_CARD)
                        .stroke(egui::Stroke::new(1.0, BG_ELEVATED))
                        .rounding(16.0)
                        .inner_margin(40.0)
                        .show(ui, |ui| {
                            ui.set_min_width(ui.available_width());
                            ui.vertical_centered(|ui| {
                                ui.add_space(20.0);
                                ui.spinner();
                                ui.add_space(20.0);
                                ui.label(egui::RichText::new("Signing in...")
                                    .size(18.0)
                                    .color(TEXT_PRIMARY)
                                    .strong());
                                ui.add_space(8.0);
                                ui.label(egui::RichText::new("Please wait...")
                                    .size(14.0)
                                    .color(TEXT_SECONDARY));
                                ui.add_space(20.0);
                            });
                        });
                }
            );
        });
    }

    fn render_awaiting_oauth_callback(&mut self, ui: &mut egui::Ui) {
        let available = ui.available_size();
        let card_max_width: f32 = 420.0;
        let mut do_cancel = false;

        ui.vertical_centered(|ui| {
            // Center vertically
            let top_space = ((available.y - 300.0) / 2.0).max(40.0);
            ui.add_space(top_space);

            ui.allocate_ui_with_layout(
                egui::vec2(card_max_width.min(available.x - 40.0), available.y),
                egui::Layout::top_down(egui::Align::Center),
                |ui| {
                    egui::Frame::none()
                        .fill(BG_CARD)
                        .stroke(egui::Stroke::new(1.0, BG_ELEVATED))
                        .rounding(16.0)
                        .inner_margin(40.0)
                        .show(ui, |ui| {
                            ui.set_min_width(ui.available_width());
                            ui.vertical_centered(|ui| {
                                // Browser icon
                                ui.label(egui::RichText::new("🌐")
                                    .size(48.0));

                                ui.add_space(20.0);

                                ui.label(egui::RichText::new("Complete sign in")
                                    .size(22.0)
                                    .color(TEXT_PRIMARY)
                                    .strong());

                                ui.add_space(12.0);

                                ui.label(egui::RichText::new("A browser window has opened.")
                                    .size(14.0)
                                    .color(TEXT_SECONDARY));
                                ui.add_space(4.0);
                                ui.label(egui::RichText::new("Please sign in with Google to continue.")
                                    .size(14.0)
                                    .color(TEXT_SECONDARY));

                                ui.add_space(24.0);

                                // Spinner
                                ui.spinner();

                                ui.add_space(8.0);

                                ui.label(egui::RichText::new("Waiting for authentication...")
                                    .size(13.0)
                                    .color(TEXT_MUTED));

                                ui.add_space(32.0);

                                // Cancel button
                                if ui.add(
                                    egui::Button::new(
                                        egui::RichText::new("Cancel")
                                            .size(14.0)
                                            .color(TEXT_SECONDARY)
                                    )
                                    .fill(egui::Color32::TRANSPARENT)
                                    .stroke(egui::Stroke::new(1.0, BG_HOVER))
                                    .rounding(8.0)
                                    .min_size(egui::vec2(100.0, 36.0))
                                ).clicked() {
                                    do_cancel = true;
                                }
                            });
                        });
                }
            );
        });

        if do_cancel {
            self.cancel_google_login();
        }
    }

    fn render_logged_in(&mut self, ui: &mut egui::Ui) {
        let user_email = self.user_info.as_ref().map(|u| u.email.clone());
        let user_initial = user_email.as_ref()
            .and_then(|e| e.chars().next())
            .map(|c| c.to_uppercase().to_string())
            .unwrap_or_else(|| "U".to_string());

        let mut do_logout = false;

        egui::Frame::none()
            .fill(BG_CARD).stroke(egui::Stroke::new(1.0, BG_ELEVATED))
            .rounding(12.0).inner_margin(20.0)
            .show(ui, |ui| {
                ui.set_min_width(ui.available_width());

                ui.horizontal(|ui| {
                    let (rect, _) = ui.allocate_exact_size(egui::vec2(48.0, 48.0), egui::Sense::hover());
                    ui.painter().circle_filled(rect.center(), 24.0, ACCENT_PRIMARY.gamma_multiply(0.3));
                    ui.painter().text(rect.center(), egui::Align2::CENTER_CENTER, &user_initial, egui::FontId::proportional(20.0), ACCENT_PRIMARY);

                    ui.add_space(12.0);
                    ui.vertical(|ui| {
                        if let Some(email) = &user_email {
                            ui.label(egui::RichText::new(email).size(14.0).color(TEXT_PRIMARY).strong());
                        }
                        ui.label(egui::RichText::new("Signed in").size(12.0).color(STATUS_CONNECTED));
                    });

                    ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                        if ui.add(
                            egui::Button::new(egui::RichText::new("Sign Out").size(12.0).color(TEXT_PRIMARY))
                                .fill(BG_ELEVATED).rounding(6.0)
                        ).clicked() {
                            do_logout = true;
                        }
                    });
                });
            });

        if do_logout { self.logout(); }

        ui.add_space(16.0);

        egui::Frame::none()
            .fill(BG_CARD).stroke(egui::Stroke::new(1.0, BG_ELEVATED))
            .rounding(12.0).inner_margin(20.0)
            .show(ui, |ui| {
                ui.set_min_width(ui.available_width());
                ui.label(egui::RichText::new("Subscription").size(14.0).color(TEXT_PRIMARY).strong());
                ui.add_space(12.0);

                for (label, value) in [("Plan", "Free"), ("Status", "Active")] {
                    ui.horizontal(|ui| {
                        ui.label(egui::RichText::new(label).size(13.0).color(TEXT_SECONDARY));
                        ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                            ui.label(egui::RichText::new(value).size(13.0).color(TEXT_PRIMARY));
                        });
                    });
                    ui.add_space(6.0);
                }
            });
    }

    // ═══════════════════════════════════════════════════════════════════════════════
    //  ACTIONS
    // ═══════════════════════════════════════════════════════════════════════════════

    fn connect_vpn(&mut self) {
        let access_token = if let AuthState::LoggedIn(session) = &self.auth_state {
            session.access_token.clone()
        } else {
            self.set_status("Please sign in first", STATUS_ERROR);
            return;
        };

        // Check if at least one game preset is selected
        if self.selected_game_presets.is_empty() {
            self.set_status("Please select at least one game", STATUS_WARNING);
            return;
        }

        let region = self.selected_server.clone();
        // Get apps from selected game presets
        let apps = get_apps_for_preset_set(&self.selected_game_presets);
        log::info!("Connecting with split tunnel apps: {:?}", apps);

        let vpn = Arc::clone(&self.vpn_connection);
        let rt = Arc::clone(&self.runtime);

        // Clear previously tunneled set when starting a new connection
        self.previously_tunneled.clear();

        std::thread::spawn(move || {
            rt.block_on(async {
                if let Ok(mut connection) = vpn.lock() {
                    if let Err(e) = connection.connect(&access_token, &region, apps).await {
                        log::error!("VPN connection failed: {}", e);
                    }
                }
            });
        });
    }

    fn disconnect_vpn(&mut self) {
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
    fn disconnect_vpn_sync(&mut self) {
        if !self.vpn_state.is_connected() && !self.vpn_state.is_connecting() {
            return;
        }

        log::info!("Disconnecting VPN before quit...");

        let vpn = Arc::clone(&self.vpn_connection);
        let rt = Arc::clone(&self.runtime);

        // Block on the disconnect to ensure cleanup completes
        rt.block_on(async {
            if let Ok(mut connection) = vpn.lock() {
                if let Err(e) = connection.disconnect().await {
                    log::error!("VPN disconnect on quit failed: {}", e);
                } else {
                    log::info!("VPN disconnected successfully before quit");
                }
            }
        });

        // Give a moment for adapter cleanup
        std::thread::sleep(std::time::Duration::from_millis(500));
    }

    fn retry_load_servers(&mut self) {
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
                            
                            if let Some(best_latency) = ping_region_async(&server_ips).await {
                                if let Ok(mut lat) = latencies_clone.lock() {
                                    lat.insert(region.id.clone(), Some(best_latency));
                                }
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

    fn start_login(&mut self) {
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

    fn start_google_login(&mut self) {
        self.auth_error = None;
        if let Ok(auth) = self.auth_manager.lock() {
            if let Err(e) = auth.start_google_sign_in() {
                self.auth_error = Some(e.to_string());
            }
        }
    }

    fn cancel_google_login(&mut self) {
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

    fn logout(&mut self) {
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

    fn toggle_optimizations(&mut self) {
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

    fn apply_profile_preset(&mut self) {
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

    // ═══════════════════════════════════════════════════════════════════════════════
    //  AUTO-UPDATER METHODS
    // ═══════════════════════════════════════════════════════════════════════════════

    /// Render the update banner at the top of the Connect tab
    fn render_update_banner(&mut self, ui: &mut egui::Ui) {
        let state = match self.update_state.lock() {
            Ok(s) => s.clone(),
            Err(_) => return,
        };

        // Don't show banner for Idle, UpToDate, or Checking states
        match &state {
            UpdateState::Idle | UpdateState::UpToDate | UpdateState::Checking => return,
            UpdateState::Failed(msg) => {
                // Show error banner briefly, then hide
                egui::Frame::none()
                    .fill(STATUS_ERROR.gamma_multiply(0.15))
                    .stroke(egui::Stroke::new(1.0, STATUS_ERROR.gamma_multiply(0.3)))
                    .rounding(8.0)
                    .inner_margin(12.0)
                    .show(ui, |ui| {
                        ui.horizontal(|ui| {
                            ui.label(egui::RichText::new("⚠").size(14.0).color(STATUS_ERROR));
                            ui.add_space(8.0);
                            ui.label(egui::RichText::new(format!("Update failed: {}", msg))
                                .size(12.0).color(STATUS_ERROR));
                            ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                                if ui.add(egui::Button::new(
                                    egui::RichText::new("Retry").size(11.0).color(TEXT_PRIMARY)
                                ).fill(STATUS_ERROR.gamma_multiply(0.3)).rounding(4.0)).clicked() {
                                    self.start_update_check();
                                }
                            });
                        });
                    });
                ui.add_space(12.0);
                return;
            }
            _ => {}
        }

        // Get update info for banner
        let info = match state.get_info() {
            Some(i) => i.clone(),
            None => return,
        };

        // Don't show if user dismissed this version
        if let Some(ref dismissed) = self.update_settings.dismissed_version {
            if dismissed == &info.version {
                return;
            }
        }

        egui::Frame::none()
            .fill(ACCENT_PRIMARY.gamma_multiply(0.15))
            .stroke(egui::Stroke::new(1.0, ACCENT_PRIMARY.gamma_multiply(0.3)))
            .rounding(8.0)
            .inner_margin(12.0)
            .show(ui, |ui| {
                ui.set_min_width(ui.available_width());

                match &state {
                    UpdateState::Available(info) => {
                        ui.horizontal(|ui| {
                            ui.label(egui::RichText::new("🔄").size(14.0));
                            ui.add_space(8.0);
                            ui.label(egui::RichText::new(format!("Update v{} available!", info.version))
                                .size(13.0).color(TEXT_PRIMARY).strong());
                            ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                                if ui.add(egui::Button::new(
                                    egui::RichText::new("Download").size(11.0).color(TEXT_PRIMARY)
                                ).fill(ACCENT_PRIMARY).rounding(4.0)).clicked() {
                                    self.start_update_download(info.clone());
                                }
                                ui.add_space(8.0);
                                if ui.add(egui::Button::new(
                                    egui::RichText::new("Later").size(11.0).color(TEXT_SECONDARY)
                                ).fill(egui::Color32::TRANSPARENT).stroke(egui::Stroke::new(1.0, BG_HOVER)).rounding(4.0)).clicked() {
                                    self.dismiss_update(&info.version);
                                }
                            });
                        });
                    }
                    UpdateState::Downloading { progress, downloaded, total, .. } => {
                        ui.vertical(|ui| {
                            ui.horizontal(|ui| {
                                ui.label(egui::RichText::new("⬇").size(14.0));
                                ui.add_space(8.0);
                                ui.label(egui::RichText::new(format!(
                                    "Downloading v{}... {:.1}%",
                                    info.version, progress * 100.0
                                )).size(13.0).color(TEXT_PRIMARY));
                                ui.add_space(8.0);
                                let mb_downloaded = *downloaded as f64 / 1_000_000.0;
                                let mb_total = *total as f64 / 1_000_000.0;
                                ui.label(egui::RichText::new(format!(
                                    "({:.1} / {:.1} MB)", mb_downloaded, mb_total
                                )).size(11.0).color(TEXT_SECONDARY));
                            });
                            ui.add_space(6.0);
                            // Progress bar
                            let (rect, _) = ui.allocate_exact_size(
                                egui::vec2(ui.available_width(), 4.0),
                                egui::Sense::hover()
                            );
                            ui.painter().rect_filled(rect, 2.0, BG_ELEVATED);
                            let progress_width = rect.width() * progress;
                            let progress_rect = egui::Rect::from_min_size(
                                rect.min,
                                egui::vec2(progress_width, rect.height())
                            );
                            ui.painter().rect_filled(progress_rect, 2.0, ACCENT_PRIMARY);
                        });
                    }
                    UpdateState::Verifying(_) => {
                        ui.horizontal(|ui| {
                            ui.spinner();
                            ui.add_space(8.0);
                            ui.label(egui::RichText::new(format!("Verifying v{}...", info.version))
                                .size(13.0).color(TEXT_PRIMARY));
                        });
                    }
                    UpdateState::ReadyToInstall { info, .. } => {
                        ui.horizontal(|ui| {
                            ui.label(egui::RichText::new("✓").size(14.0).color(STATUS_CONNECTED));
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

        ui.add_space(12.0);
    }

    /// Start checking for updates in the background
    fn start_update_check(&mut self) {
        // Set state to Checking
        if let Ok(mut state) = self.update_state.lock() {
            *state = UpdateState::Checking;
        }

        let update_state = Arc::clone(&self.update_state);
        let rt = Arc::clone(&self.runtime);

        std::thread::spawn(move || {
            rt.block_on(async {
                let checker = UpdateChecker::new();
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

    // ═══════════════════════════════════════════════════════════════════════════════
    //  NETWORK ANALYZER TAB
    // ═══════════════════════════════════════════════════════════════════════════════

    /// Render the Network Analyzer tab
    fn render_network_tab(&mut self, ui: &mut egui::Ui) {
        // Show update banner if available
        self.render_update_banner(ui);

        let is_logged_in = matches!(self.auth_state, AuthState::LoggedIn(_));

        if !is_logged_in {
            self.render_login_prompt(ui);
            return;
        }

        // Tab header
        ui.horizontal(|ui| {
            ui.label(egui::RichText::new("📶 Network Analyzer")
                .size(20.0)
                .color(TEXT_PRIMARY)
                .strong());
            ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                ui.label(egui::RichText::new("Test your connection")
                    .size(12.0)
                    .color(TEXT_MUTED));
            });
        });
        ui.add_space(16.0);

        // Connection Stability Test section
        self.render_stability_section(ui);
        ui.add_space(20.0);

        // Speed Test section
        self.render_speed_test_section(ui);
    }

    /// Render the Connection Stability Test section
    fn render_stability_section(&mut self, ui: &mut egui::Ui) {
        egui::Frame::none()
            .fill(BG_CARD)
            .rounding(12.0)
            .inner_margin(egui::Margin::same(16.0))
            .show(ui, |ui| {
                // Section header
                ui.horizontal(|ui| {
                    ui.label(egui::RichText::new("🎯 Connection Stability")
                        .size(16.0)
                        .color(TEXT_PRIMARY)
                        .strong());

                    ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                        // Show quality badge if we have results
                        if let Some(ref results) = self.network_analyzer_state.stability.results {
                            let (badge_color, badge_text) = match results.quality {
                                crate::network_analyzer::ConnectionQuality::Excellent => (STATUS_CONNECTED, "Excellent"),
                                crate::network_analyzer::ConnectionQuality::Good => (LATENCY_GOOD, "Good"),
                                crate::network_analyzer::ConnectionQuality::Fair => (STATUS_WARNING, "Fair"),
                                crate::network_analyzer::ConnectionQuality::Poor => (LATENCY_POOR, "Poor"),
                                crate::network_analyzer::ConnectionQuality::Bad => (STATUS_ERROR, "Bad"),
                            };
                            egui::Frame::none()
                                .fill(badge_color.gamma_multiply(0.2))
                                .rounding(4.0)
                                .inner_margin(egui::Margin::symmetric(8.0, 4.0))
                                .show(ui, |ui| {
                                    ui.label(egui::RichText::new(badge_text)
                                        .size(11.0)
                                        .color(badge_color)
                                        .strong());
                                });
                        }
                    });
                });
                ui.add_space(12.0);

                // Ping chart
                self.render_ping_chart(ui);
                ui.add_space(12.0);

                // Stats row
                if let Some(ref results) = self.network_analyzer_state.stability.results {
                    ui.horizontal(|ui| {
                        // Avg Ping
                        self.render_stat_box(ui, "Avg Ping", &format!("{:.0}ms", results.avg_ping), latency_color(results.avg_ping as u32));
                        ui.add_space(8.0);
                        // Jitter
                        self.render_stat_box(ui, "Jitter", &format!("{:.1}ms", results.jitter), TEXT_SECONDARY);
                        ui.add_space(8.0);
                        // Packet Loss
                        let loss_color = if results.packet_loss < 1.0 { STATUS_CONNECTED } else if results.packet_loss < 5.0 { STATUS_WARNING } else { STATUS_ERROR };
                        self.render_stat_box(ui, "Loss", &format!("{:.1}%", results.packet_loss), loss_color);
                        ui.add_space(8.0);
                        // Min/Max
                        self.render_stat_box(ui, "Min/Max", &format!("{}/{}ms", results.min_ping, results.max_ping), TEXT_MUTED);
                    });
                } else if self.network_analyzer_state.stability.running {
                    ui.horizontal(|ui| {
                        ui.spinner();
                        ui.label(egui::RichText::new(format!("Testing... {:.0}%", self.network_analyzer_state.stability.progress * 100.0))
                            .size(13.0)
                            .color(TEXT_SECONDARY));
                    });
                }

                ui.add_space(12.0);

                // Start/Stop button
                let is_running = self.network_analyzer_state.stability.running;
                let button_text = if is_running { "⏹ Stop Test" } else { "▶ Start Stability Test" };
                let button_color = if is_running { STATUS_ERROR } else { ACCENT_PRIMARY };

                let button = egui::Button::new(
                    egui::RichText::new(button_text)
                        .size(14.0)
                        .color(TEXT_PRIMARY)
                )
                .fill(button_color)
                .rounding(8.0)
                .min_size(egui::vec2(ui.available_width(), 38.0));

                if ui.add(button).clicked() {
                    if is_running {
                        // TODO: Implement stop functionality
                        self.network_analyzer_state.stability.running = false;
                    } else {
                        self.start_stability_test();
                    }
                }
            });
    }

    /// Render the ping chart showing real-time ping history
    fn render_ping_chart(&self, ui: &mut egui::Ui) {
        let samples = &self.network_analyzer_state.stability.ping_samples;
        let chart_height = 120.0;
        let chart_width = ui.available_width();

        // Chart background
        let (response, painter) = ui.allocate_painter(egui::vec2(chart_width, chart_height), egui::Sense::hover());
        let rect = response.rect;

        // Draw background
        painter.rect_filled(rect, 8.0, BG_ELEVATED);

        // Draw reference lines at 50ms, 100ms, 150ms
        let max_ms = 200.0_f32;
        for ref_ms in [50.0, 100.0, 150.0] {
            let y = rect.max.y - (ref_ms / max_ms) * rect.height();
            painter.line_segment(
                [egui::pos2(rect.min.x + 4.0, y), egui::pos2(rect.max.x - 4.0, y)],
                egui::Stroke::new(1.0, BG_HOVER)
            );
            painter.text(
                egui::pos2(rect.min.x + 6.0, y - 8.0),
                egui::Align2::LEFT_BOTTOM,
                format!("{}ms", ref_ms as u32),
                egui::FontId::proportional(9.0),
                TEXT_DIMMED
            );
        }

        // Draw samples
        if samples.len() >= 2 {
            let max_samples = 60; // Show last 60 samples (30 seconds at 2 pings/sec)
            let start_idx = samples.len().saturating_sub(max_samples);
            let visible_samples = &samples[start_idx..];

            let sample_width = rect.width() / max_samples as f32;

            // Draw line connecting points
            let mut points: Vec<egui::Pos2> = Vec::new();
            for (i, sample) in visible_samples.iter().enumerate() {
                if let Some(ms) = sample {
                    let x = rect.min.x + (i as f32 * sample_width) + sample_width / 2.0;
                    let y = rect.max.y - ((*ms as f32).min(max_ms) / max_ms) * rect.height() * 0.9 - 5.0;
                    points.push(egui::pos2(x, y));
                }
            }

            // Draw line
            if points.len() >= 2 {
                for window in points.windows(2) {
                    painter.line_segment(
                        [window[0], window[1]],
                        egui::Stroke::new(2.0, ACCENT_CYAN.gamma_multiply(0.7))
                    );
                }
            }

            // Draw points
            for (i, sample) in visible_samples.iter().enumerate() {
                let x = rect.min.x + (i as f32 * sample_width) + sample_width / 2.0;

                match sample {
                    Some(ms) => {
                        let y = rect.max.y - ((*ms as f32).min(max_ms) / max_ms) * rect.height() * 0.9 - 5.0;
                        let color = latency_color(*ms);
                        painter.circle_filled(egui::pos2(x, y), 3.0, color);
                    }
                    None => {
                        // Packet loss - draw red X at bottom
                        let y = rect.max.y - 10.0;
                        painter.text(
                            egui::pos2(x, y),
                            egui::Align2::CENTER_CENTER,
                            "×",
                            egui::FontId::proportional(12.0),
                            STATUS_ERROR
                        );
                    }
                }
            }
        } else {
            // No data yet - show placeholder
            painter.text(
                rect.center(),
                egui::Align2::CENTER_CENTER,
                "Start test to see ping history",
                egui::FontId::proportional(12.0),
                TEXT_DIMMED
            );
        }
    }

    /// Render a small stat box
    fn render_stat_box(&self, ui: &mut egui::Ui, label: &str, value: &str, value_color: egui::Color32) {
        egui::Frame::none()
            .fill(BG_ELEVATED)
            .rounding(6.0)
            .inner_margin(egui::Margin::symmetric(12.0, 8.0))
            .show(ui, |ui| {
                ui.vertical(|ui| {
                    ui.label(egui::RichText::new(label).size(10.0).color(TEXT_MUTED));
                    ui.label(egui::RichText::new(value).size(14.0).color(value_color).strong());
                });
            });
    }

    /// Start the stability test
    fn start_stability_test(&mut self) {
        if self.network_analyzer_state.stability.running {
            return;
        }

        // Reset state
        self.network_analyzer_state.stability.running = true;
        self.network_analyzer_state.stability.progress = 0.0;
        self.network_analyzer_state.stability.ping_samples.clear();
        self.network_analyzer_state.stability.results = None;

        // Create new channel for this test
        let (tx, rx) = std::sync::mpsc::channel::<StabilityTestProgress>();
        self.stability_progress_rx = rx;

        // Spawn test in background
        let rt = Arc::clone(&self.runtime);
        std::thread::spawn(move || {
            let _ = rt.block_on(async {
                run_stability_test(30, tx).await
            });
        });
    }

    /// Render the Speed Test section
    fn render_speed_test_section(&mut self, ui: &mut egui::Ui) {
        egui::Frame::none()
            .fill(BG_CARD)
            .rounding(12.0)
            .inner_margin(egui::Margin::same(16.0))
            .show(ui, |ui| {
                // Section header
                ui.horizontal(|ui| {
                    ui.label(egui::RichText::new("🚀 Speed Test")
                        .size(16.0)
                        .color(TEXT_PRIMARY)
                        .strong());

                    ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                        if let Some(ref results) = self.network_analyzer_state.speed.results {
                            ui.label(egui::RichText::new(format!("via {}", results.server))
                                .size(11.0)
                                .color(TEXT_MUTED));
                        }
                    });
                });
                ui.add_space(16.0);

                // Speed gauges
                ui.horizontal(|ui| {
                    let gauge_width = (ui.available_width() - 16.0) / 2.0;

                    // Download gauge
                    ui.vertical(|ui| {
                        ui.set_width(gauge_width);
                        self.render_speed_gauge(ui, "Download", self.network_analyzer_state.speed.download_speed, ACCENT_CYAN, true);
                    });

                    ui.add_space(16.0);

                    // Upload gauge
                    ui.vertical(|ui| {
                        ui.set_width(gauge_width);
                        self.render_speed_gauge(ui, "Upload", self.network_analyzer_state.speed.upload_speed, ACCENT_SECONDARY, false);
                    });
                });

                ui.add_space(16.0);

                // Phase indicator
                if self.network_analyzer_state.speed.running {
                    let phase = &self.network_analyzer_state.speed.phase;
                    let phase_text = match phase {
                        crate::network_analyzer::SpeedTestPhase::Download => "⬇ Testing Download...",
                        crate::network_analyzer::SpeedTestPhase::Upload => "⬆ Testing Upload...",
                        _ => "Starting...",
                    };

                    ui.horizontal(|ui| {
                        ui.spinner();
                        ui.label(egui::RichText::new(phase_text)
                            .size(13.0)
                            .color(TEXT_SECONDARY));

                        // Progress bar
                        ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                            let progress = self.network_analyzer_state.speed.phase_progress;
                            let progress_rect = ui.allocate_exact_size(egui::vec2(100.0, 4.0), egui::Sense::hover()).0;
                            let painter = ui.painter();
                            painter.rect_filled(progress_rect, 2.0, BG_ELEVATED);
                            let filled_width = progress_rect.width() * progress;
                            painter.rect_filled(
                                egui::Rect::from_min_size(progress_rect.min, egui::vec2(filled_width, 4.0)),
                                2.0,
                                ACCENT_PRIMARY
                            );
                        });
                    });
                    ui.add_space(8.0);
                }

                // Start button
                let is_running = self.network_analyzer_state.speed.running;
                let button_text = if is_running { "⏹ Stop Test" } else { "▶ Start Speed Test" };
                let button_color = if is_running { STATUS_ERROR } else { GRADIENT_CYAN_START };

                let button = egui::Button::new(
                    egui::RichText::new(button_text)
                        .size(14.0)
                        .color(TEXT_PRIMARY)
                )
                .fill(button_color)
                .rounding(8.0)
                .min_size(egui::vec2(ui.available_width(), 38.0));

                if ui.add(button).clicked() {
                    if is_running {
                        // TODO: Implement stop functionality
                        self.network_analyzer_state.speed.running = false;
                        self.network_analyzer_state.speed.phase = crate::network_analyzer::SpeedTestPhase::Idle;
                    } else {
                        self.start_speed_test();
                    }
                }

                // Last test info
                if let Some(ref results) = self.network_analyzer_state.speed.results {
                    ui.add_space(8.0);
                    ui.label(egui::RichText::new(format!(
                        "Last test: {} ({})",
                        results.timestamp.format("%H:%M:%S"),
                        results.server
                    ))
                        .size(10.0)
                        .color(TEXT_DIMMED));
                }
            });
    }

    /// Render a semi-circle speed gauge
    fn render_speed_gauge(&self, ui: &mut egui::Ui, label: &str, speed: f32, color: egui::Color32, _is_download: bool) {
        let gauge_size = 140.0;
        let (response, painter) = ui.allocate_painter(egui::vec2(ui.available_width(), gauge_size), egui::Sense::hover());
        let rect = response.rect;
        let center = egui::pos2(rect.center().x, rect.max.y - 20.0);
        let radius = gauge_size * 0.4;

        // Draw background arc
        let arc_width = 12.0;
        let segments = 60;
        for i in 0..segments {
            let angle1 = std::f32::consts::PI - (i as f32 / segments as f32) * std::f32::consts::PI;
            let angle2 = std::f32::consts::PI - ((i + 1) as f32 / segments as f32) * std::f32::consts::PI;

            let p1 = center + egui::vec2(angle1.cos() * radius, -angle1.sin() * radius);
            let p2 = center + egui::vec2(angle2.cos() * radius, -angle2.sin() * radius);

            painter.line_segment([p1, p2], egui::Stroke::new(arc_width, BG_ELEVATED));
        }

        // Draw filled arc based on speed (max 1000 Mbps scale)
        let max_speed = 1000.0_f32;
        let fill_ratio = (speed / max_speed).min(1.0);
        let fill_segments = (fill_ratio * segments as f32) as usize;

        for i in 0..fill_segments {
            let angle1 = std::f32::consts::PI - (i as f32 / segments as f32) * std::f32::consts::PI;
            let angle2 = std::f32::consts::PI - ((i + 1) as f32 / segments as f32) * std::f32::consts::PI;

            let p1 = center + egui::vec2(angle1.cos() * radius, -angle1.sin() * radius);
            let p2 = center + egui::vec2(angle2.cos() * radius, -angle2.sin() * radius);

            // Gradient effect - more saturated towards the end
            let segment_ratio = i as f32 / fill_segments.max(1) as f32;
            let segment_color = lerp_color(color.gamma_multiply(0.6), color, segment_ratio);

            painter.line_segment([p1, p2], egui::Stroke::new(arc_width, segment_color));
        }

        // Draw speed value in center
        let speed_text = format_speed(speed);
        painter.text(
            center + egui::vec2(0.0, -15.0),
            egui::Align2::CENTER_CENTER,
            &speed_text,
            egui::FontId::proportional(24.0),
            TEXT_PRIMARY
        );

        // Draw label below
        painter.text(
            center + egui::vec2(0.0, 10.0),
            egui::Align2::CENTER_CENTER,
            label,
            egui::FontId::proportional(12.0),
            TEXT_SECONDARY
        );

        // Draw scale markers
        for (ratio, label) in [(0.0, "0"), (0.25, "250"), (0.5, "500"), (0.75, "750"), (1.0, "1000")] {
            let angle = std::f32::consts::PI - ratio * std::f32::consts::PI;
            let marker_pos = center + egui::vec2(angle.cos() * (radius + 20.0), -angle.sin() * (radius + 20.0));
            painter.text(
                marker_pos,
                egui::Align2::CENTER_CENTER,
                label,
                egui::FontId::proportional(8.0),
                TEXT_DIMMED
            );
        }
    }

    /// Start the speed test
    fn start_speed_test(&mut self) {
        if self.network_analyzer_state.speed.running {
            return;
        }

        // Reset state
        self.network_analyzer_state.speed.running = true;
        self.network_analyzer_state.speed.phase = crate::network_analyzer::SpeedTestPhase::Download;
        self.network_analyzer_state.speed.phase_progress = 0.0;
        self.network_analyzer_state.speed.download_speed = 0.0;
        self.network_analyzer_state.speed.upload_speed = 0.0;
        self.network_analyzer_state.speed.results = None;

        // Create new channel for this test
        let (tx, rx) = std::sync::mpsc::channel::<SpeedTestProgress>();
        self.speed_progress_rx = rx;

        // Spawn test in background
        let rt = Arc::clone(&self.runtime);
        std::thread::spawn(move || {
            let _ = rt.block_on(async {
                run_speed_test(tx).await
            });
        });
    }
}
