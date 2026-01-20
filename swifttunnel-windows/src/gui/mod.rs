//! SwiftTunnel GUI Module
//!
//! Modern UI with sidebar navigation and card layouts.

pub mod theme;
pub mod animations;
pub mod components;
pub mod sidebar;
pub mod header;
pub mod pages;

pub use theme::*;
pub use animations::*;

use eframe::egui;
use std::collections::{HashMap, HashSet};
use std::sync::{Arc, Mutex};
use std::sync::atomic::{AtomicBool, Ordering};

use crate::auth::{AuthManager, AuthState, UserInfo};
use crate::network_analyzer::{
    NetworkAnalyzerState, StabilityTestProgress, SpeedTestProgress,
    run_stability_test, run_speed_test,
};
use crate::performance_monitor::SystemInfo;
use crate::roblox_optimizer::RobloxOptimizer;
use crate::settings::{load_settings, save_settings, AppSettings, WindowState};
use crate::structs::*;
use crate::tray::SystemTray;
use crate::updater::{UpdateChecker, UpdateSettings, UpdateState};
use crate::vpn::{ConnectionState, VpnConnection, DynamicServerList, DynamicGamingRegion, load_server_list, ServerListSource, GamePreset, get_apps_for_preset_set};

use sidebar::render_sidebar;
use header::{render_header, render_auth_header, HeaderAction};
use pages::{
    home::{render_home_page, HomePageState, HomePageAction},
    games::{render_games_page, GamesPageState, GamesPageAction},
    boost::{render_boost_page, BoostPageState, BoostPageAction, BoostSetting},
    network::{render_network_page, NetworkPageState, NetworkPageAction},
    settings::{render_settings_page, SettingsPageState, SettingsPageAction, SettingsSection},
};

/// Application pages
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Page {
    Home,
    Games,
    Boost,
    Network,
    Settings,
}

impl Default for Page {
    fn default() -> Self {
        Page::Home
    }
}

impl Page {
    fn to_string(&self) -> &'static str {
        match self {
            Page::Home => "home",
            Page::Games => "games",
            Page::Boost => "boost",
            Page::Network => "network",
            Page::Settings => "settings",
        }
    }

    fn from_string(s: &str) -> Self {
        match s {
            "games" => Page::Games,
            "boost" => Page::Boost,
            "network" => Page::Network,
            "settings" => Page::Settings,
            _ => Page::Home,
        }
    }
}

/// Main application struct
pub struct BoosterApp {
    pub state: AppState,
    system_info: Option<SystemInfo>,
    selected_profile: OptimizationProfile,
    current_page: Page,
    roblox_optimizer: RobloxOptimizer,
    status_message: Option<(String, egui::Color32, std::time::Instant)>,

    // Auth
    auth_manager: Arc<Mutex<AuthManager>>,
    auth_state: AuthState,
    user_info: Option<UserInfo>,
    auth_error: Option<String>,
    login_email: String,
    login_password: String,

    // Settings
    settings_dirty: bool,
    last_save_time: std::time::Instant,
    settings_section: SettingsSection,

    // System tray
    system_tray: Option<SystemTray>,

    // VPN
    vpn_connection: Arc<Mutex<VpnConnection>>,
    vpn_state: ConnectionState,
    dynamic_server_list: Arc<Mutex<DynamicServerList>>,
    servers_loading: bool,
    server_list_source: ServerListSource,
    selected_region: String,
    selected_server: String,
    region_latencies: Arc<Mutex<HashMap<String, Option<u32>>>>,
    finding_best_server: Arc<AtomicBool>,
    selected_game_presets: HashSet<GamePreset>,

    // Performance
    runtime: Arc<tokio::runtime::Runtime>,
    needs_repaint: bool,
    last_vpn_check: std::time::Instant,
    cached_latencies: HashMap<String, Option<u32>>,
    cached_regions: Vec<DynamicGamingRegion>,
    last_cache_update: std::time::Instant,

    // Restore point status
    restore_point_status: Option<(String, egui::Color32, std::time::Instant)>,

    // Auto-updater
    update_state: Arc<Mutex<UpdateState>>,
    update_settings: UpdateSettings,
    update_check_started: bool,

    // Settings values
    minimize_to_tray: bool,

    // Auth update channel
    auth_update_tx: std::sync::mpsc::Sender<AuthState>,
    auth_update_rx: std::sync::mpsc::Receiver<AuthState>,

    // Animation system
    animations: AnimationManager,
    app_start_time: std::time::Instant,

    // UI state
    expanded_boost_info: HashSet<String>,
    last_connected_region: Option<String>,
    process_notification: Option<(String, std::time::Instant)>,
    previously_tunneled: HashSet<String>,
    force_quit: bool,

    // Network Analyzer
    network_analyzer_state: NetworkAnalyzerState,
    stability_progress_tx: std::sync::mpsc::Sender<StabilityTestProgress>,
    stability_progress_rx: std::sync::mpsc::Receiver<StabilityTestProgress>,
    speed_progress_tx: std::sync::mpsc::Sender<SpeedTestProgress>,
    speed_progress_rx: std::sync::mpsc::Receiver<SpeedTestProgress>,
    download_gauge_animation: Option<Animation>,
    upload_gauge_animation: Option<Animation>,
}

impl BoosterApp {
    pub fn new(cc: &eframe::CreationContext<'_>) -> Self {
        let saved_settings = load_settings();
        theme::configure_style(&cc.egui_ctx);

        // Create tokio runtime
        let runtime = Arc::new(
            tokio::runtime::Builder::new_multi_thread()
                .worker_threads(2)
                .enable_all()
                .build()
                .expect("Failed to create tokio runtime")
        );

        // Create channels
        let (auth_update_tx, auth_update_rx) = std::sync::mpsc::channel::<AuthState>();
        let (stability_tx, stability_rx) = std::sync::mpsc::channel::<StabilityTestProgress>();
        let (speed_tx, speed_rx) = std::sync::mpsc::channel::<SpeedTestProgress>();

        // Initialize auth manager
        let auth_manager = AuthManager::new().unwrap_or_else(|e| {
            log::error!("Critical: Failed to initialize auth manager: {}", e);
            panic!("Cannot initialize authentication: {}", e)
        });
        let auth_state = auth_manager.get_state();
        let user_info = auth_manager.get_user();

        let mut app_state = AppState::default();
        app_state.config = saved_settings.config.clone();
        app_state.optimizations_active = saved_settings.optimizations_active;

        let current_page = Page::from_string(&saved_settings.current_tab);

        // Initialize server list
        let dynamic_server_list = Arc::new(Mutex::new(DynamicServerList::new_empty()));
        let region_latencies = Arc::new(Mutex::new(HashMap::new()));
        let finding_best_server = Arc::new(AtomicBool::new(false));

        // Spawn server list fetch
        let server_list_clone = Arc::clone(&dynamic_server_list);
        let latencies_clone = Arc::clone(&region_latencies);
        let finding_clone = Arc::clone(&finding_best_server);
        let rt_clone = Arc::clone(&runtime);

        std::thread::spawn(move || {
            rt_clone.block_on(async {
                match load_server_list().await {
                    Ok((servers, regions, source)) => {
                        log::info!("Server list loaded from {}", source);
                        if let Ok(mut list) = server_list_clone.lock() {
                            list.update(servers.clone(), regions.clone(), source);
                        }

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
            current_page,
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
            cached_latencies: HashMap::new(),
            cached_regions: Vec::new(),
            last_cache_update: std::time::Instant::now(),
            restore_point_status: None,
            update_state: Arc::new(Mutex::new(UpdateState::Idle)),
            update_settings: saved_settings.update_settings.clone(),
            update_check_started: false,
            minimize_to_tray: saved_settings.minimize_to_tray,
            auth_update_tx,
            auth_update_rx,
            animations: AnimationManager::default(),
            app_start_time: std::time::Instant::now(),
            expanded_boost_info: saved_settings.expanded_boost_info.into_iter().collect(),
            last_connected_region: saved_settings.last_connected_region,
            process_notification: None,
            previously_tunneled: HashSet::new(),
            force_quit: false,
            network_analyzer_state: {
                let mut state = NetworkAnalyzerState::default();
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
            current_tab: self.current_page.to_string().to_string(),
            update_settings: self.update_settings.clone(),
            minimize_to_tray: self.minimize_to_tray,
            last_connected_region: self.last_connected_region.clone(),
            expanded_boost_info: self.expanded_boost_info.iter().cloned().collect(),
            selected_game_presets: self.selected_game_presets.iter()
                .map(|p| match p {
                    GamePreset::Roblox => "roblox",
                    GamePreset::Valorant => "valorant",
                    GamePreset::Fortnite => "fortnite",
                }.to_string())
                .collect(),
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

    // ═══════════════════════════════════════════════════════════════════════════════
    //  VPN ACTIONS
    // ═══════════════════════════════════════════════════════════════════════════════

    fn connect_vpn(&mut self) {
        let access_token = if let AuthState::LoggedIn(session) = &self.auth_state {
            session.access_token.clone()
        } else {
            self.set_status("Please sign in first", STATUS_ERROR);
            return;
        };

        if self.selected_game_presets.is_empty() {
            self.set_status("Please select at least one game", STATUS_WARNING);
            return;
        }

        let region = self.selected_server.clone();
        let apps = get_apps_for_preset_set(&self.selected_game_presets);
        log::info!("Connecting with split tunnel apps: {:?}", apps);

        let vpn = Arc::clone(&self.vpn_connection);
        let rt = Arc::clone(&self.runtime);
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

    fn disconnect_vpn_sync(&mut self) {
        if !self.vpn_state.is_connected() && !self.vpn_state.is_connecting() {
            return;
        }

        log::info!("Disconnecting VPN before quit...");
        let vpn = Arc::clone(&self.vpn_connection);
        let rt = Arc::clone(&self.runtime);

        rt.block_on(async {
            if let Ok(mut connection) = vpn.lock() {
                if let Err(e) = connection.disconnect().await {
                    log::error!("VPN disconnect on quit failed: {}", e);
                } else {
                    log::info!("VPN disconnected successfully before quit");
                }
            }
        });

        std::thread::sleep(std::time::Duration::from_millis(500));
    }

    // ═══════════════════════════════════════════════════════════════════════════════
    //  AUTH ACTIONS
    // ═══════════════════════════════════════════════════════════════════════════════

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
                            let _ = tx.send(auth.get_state());
                        }
                        Err(e) => {
                            log::error!("Login failed: {}", e);
                            let _ = tx.send(AuthState::Error(e.to_string()));
                        }
                    }
                }
            });
        });
    }

    fn start_oauth(&mut self) {
        let auth_manager = Arc::clone(&self.auth_manager);
        let tx = self.auth_update_tx.clone();

        std::thread::spawn(move || {
            if let Ok(auth) = auth_manager.lock() {
                match auth.start_google_sign_in() {
                    Ok(_state) => {
                        // Browser was opened by start_google_sign_in
                        // State is set to AwaitingOAuthCallback inside start_google_sign_in
                        let _ = tx.send(auth.get_state());
                    }
                    Err(e) => {
                        log::error!("OAuth start failed: {:?}", e);
                        let _ = tx.send(AuthState::Error(format!("{:?}", e)));
                    }
                }
            }
        });
    }

    fn logout(&mut self) {
        if let Ok(auth) = self.auth_manager.lock() {
            let _ = auth.logout();
            self.auth_state = AuthState::LoggedOut;
            self.user_info = None;
        }
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

    // ═══════════════════════════════════════════════════════════════════════════════
    //  NETWORK TEST ACTIONS
    // ═══════════════════════════════════════════════════════════════════════════════

    fn start_stability_test(&mut self) {
        if self.network_analyzer_state.stability.running {
            return;
        }

        self.network_analyzer_state.stability.running = true;
        self.network_analyzer_state.stability.progress = 0.0;
        self.network_analyzer_state.stability.ping_samples.clear();

        let tx = self.stability_progress_tx.clone();
        let rt = Arc::clone(&self.runtime);

        std::thread::spawn(move || {
            rt.block_on(async {
                let _ = run_stability_test(30, tx).await;
            });
        });
    }

    fn start_speed_test(&mut self) {
        if self.network_analyzer_state.speed.running {
            return;
        }

        self.network_analyzer_state.speed.running = true;
        self.network_analyzer_state.speed.phase = crate::network_analyzer::SpeedTestPhase::Download;
        self.network_analyzer_state.speed.phase_progress = 0.0;
        self.network_analyzer_state.speed.download_speed = 0.0;
        self.network_analyzer_state.speed.upload_speed = 0.0;

        let tx = self.speed_progress_tx.clone();
        let rt = Arc::clone(&self.runtime);

        std::thread::spawn(move || {
            rt.block_on(async {
                let _ = run_speed_test(tx).await;
            });
        });
    }

    // ═══════════════════════════════════════════════════════════════════════════════
    //  UPDATE ACTIONS
    // ═══════════════════════════════════════════════════════════════════════════════

    fn start_update_check(&mut self) {
        let state_clone = Arc::clone(&self.update_state);
        let rt = Arc::clone(&self.runtime);

        std::thread::spawn(move || {
            rt.block_on(async {
                let checker = UpdateChecker::new();
                match checker.check_for_update().await {
                    Ok(Some(info)) => {
                        log::info!("Update available: {}", info.version);
                        if let Ok(mut state) = state_clone.lock() {
                            *state = UpdateState::Available(info);
                        }
                    }
                    Ok(None) => {
                        log::info!("No updates available");
                        if let Ok(mut state) = state_clone.lock() {
                            *state = UpdateState::UpToDate;
                        }
                    }
                    Err(e) => {
                        log::error!("Update check failed: {}", e);
                        if let Ok(mut state) = state_clone.lock() {
                            *state = UpdateState::Failed(e);
                        }
                    }
                }
            });
        });
    }
}

/// Async ping function
async fn ping_region_async(servers: &[(String, String)]) -> Option<u32> {
    use crate::hidden_command;

    let mut best_latency: Option<u32> = None;

    for (_server_id, server_ip) in servers {
        let mut total = 0u32;
        let mut count = 0u32;

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
        // Clean up animations
        self.animations.cleanup_completed();

        // Handle repaint timing
        let is_loading = self.servers_loading || self.finding_best_server.load(Ordering::Relaxed);
        let is_vpn_transitioning = self.vpn_state.is_connecting() || matches!(self.vpn_state, ConnectionState::Disconnecting);
        let is_logging_in = matches!(self.auth_state, AuthState::LoggingIn);
        let has_animations = self.animations.has_active_animations();
        let is_connected = self.vpn_state.is_connected();
        let is_network_testing = self.network_analyzer_state.stability.running || self.network_analyzer_state.speed.running;

        if is_loading || is_vpn_transitioning || is_logging_in || has_animations || is_network_testing {
            ctx.request_repaint_after(std::time::Duration::from_millis(16));
        } else if is_connected {
            ctx.request_repaint_after(std::time::Duration::from_millis(100));
        }

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

        if show_window {
            ctx.send_viewport_cmd(egui::ViewportCommand::Visible(true));
            ctx.send_viewport_cmd(egui::ViewportCommand::Minimized(false));
            ctx.send_viewport_cmd(egui::ViewportCommand::Focus);
        }

        if quit && !self.force_quit {
            log::info!("Tray Quit clicked - forcing quit");
            self.force_quit = true;
            if let Some(ref tray) = self.system_tray {
                tray.shutdown();
            }
            self.disconnect_vpn_sync();
            self.settings_dirty = true;
            self.last_save_time = std::time::Instant::now() - std::time::Duration::from_secs(10);
            self.save_if_needed(ctx);
            std::process::exit(0);
        }

        // Handle close button
        let close_requested = ctx.input(|i| i.viewport().close_requested());
        if close_requested && !self.force_quit && self.minimize_to_tray && self.system_tray.is_some() {
            ctx.send_viewport_cmd(egui::ViewportCommand::CancelClose);
            ctx.send_viewport_cmd(egui::ViewportCommand::Visible(false));
        }

        // Poll auth updates
        while let Ok(new_state) = self.auth_update_rx.try_recv() {
            if let AuthState::Error(ref msg) = new_state {
                self.auth_error = Some(msg.clone());
            } else if matches!(new_state, AuthState::LoggedIn(_)) {
                self.auth_error = None;
            }
            self.auth_state = new_state;
            if let Ok(auth) = self.auth_manager.try_lock() {
                self.user_info = auth.get_user();
            }
        }

        // Poll stability test progress
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
                    self.mark_dirty();
                }
                StabilityTestProgress::Error(msg) => {
                    log::error!("Stability test error: {}", msg);
                    self.network_analyzer_state.stability.running = false;
                }
            }
        }

        // Poll speed test progress
        while let Ok(progress) = self.speed_progress_rx.try_recv() {
            match progress {
                SpeedTestProgress::DownloadStarted => {
                    self.network_analyzer_state.speed.phase = crate::network_analyzer::SpeedTestPhase::Download;
                }
                SpeedTestProgress::DownloadProgress(speed, p) => {
                    self.network_analyzer_state.speed.download_speed = speed;
                    self.network_analyzer_state.speed.phase_progress = p;
                }
                SpeedTestProgress::DownloadComplete(speed) => {
                    self.network_analyzer_state.speed.download_speed = speed;
                }
                SpeedTestProgress::UploadStarted => {
                    self.network_analyzer_state.speed.phase = crate::network_analyzer::SpeedTestPhase::Upload;
                    self.network_analyzer_state.speed.phase_progress = 0.0;
                }
                SpeedTestProgress::UploadProgress(speed, p) => {
                    self.network_analyzer_state.speed.upload_speed = speed;
                    self.network_analyzer_state.speed.phase_progress = p;
                }
                SpeedTestProgress::UploadComplete(speed) => {
                    self.network_analyzer_state.speed.upload_speed = speed;
                }
                SpeedTestProgress::Completed(results) => {
                    self.network_analyzer_state.speed.running = false;
                    self.network_analyzer_state.speed.phase = crate::network_analyzer::SpeedTestPhase::Complete;
                    self.network_analyzer_state.speed.results = Some(results);
                    self.mark_dirty();
                }
                SpeedTestProgress::Error(msg) => {
                    log::error!("Speed test error: {}", msg);
                    self.network_analyzer_state.speed.running = false;
                }
            }
        }

        // Poll VPN state
        if self.last_vpn_check.elapsed() >= std::time::Duration::from_millis(500) {
            self.last_vpn_check = std::time::Instant::now();

            // Get new VPN state (acquire lock, get state, release lock)
            let new_state = if let Ok(vpn) = self.vpn_connection.try_lock() {
                Some(self.runtime.block_on(vpn.state()))
            } else {
                None
            };

            // Process state changes after lock is released
            if let Some(new_state) = new_state {
                let mut should_mark_dirty = false;

                if !self.vpn_state.is_connected() && new_state.is_connected() {
                    if let ConnectionState::Connected { server_region, .. } = &new_state {
                        if self.last_connected_region.as_ref() != Some(server_region) {
                            self.last_connected_region = Some(server_region.clone());
                            should_mark_dirty = true;
                        }
                    }
                }

                if let ConnectionState::Connected { tunneled_processes, .. } = &new_state {
                    for process in tunneled_processes {
                        if !self.previously_tunneled.contains(process) {
                            self.process_notification = Some((
                                format!("🎮 Tunneling: {}", process),
                                std::time::Instant::now(),
                            ));
                            self.previously_tunneled.insert(process.clone());
                        }
                    }
                }

                if new_state == ConnectionState::Disconnected {
                    self.previously_tunneled.clear();
                }

                self.vpn_state = new_state;

                if should_mark_dirty {
                    self.mark_dirty();
                }
            }

            // Update caches
            if let Ok(list) = self.dynamic_server_list.try_lock() {
                self.servers_loading = matches!(list.source, ServerListSource::Loading);
                self.server_list_source = list.source.clone();
                self.cached_regions = list.regions().to_vec();
            }

            if let Ok(lat) = self.region_latencies.try_lock() {
                self.cached_latencies = lat.clone();
            }
        }

        // Auto-update check
        if !self.update_check_started && self.update_settings.auto_check {
            static START_TIME: std::sync::OnceLock<std::time::Instant> = std::sync::OnceLock::new();
            let start = START_TIME.get_or_init(std::time::Instant::now);
            if start.elapsed() >= std::time::Duration::from_secs(2) {
                self.update_check_started = true;
                self.start_update_check();
            }
        }

        self.save_if_needed(ctx);

        let is_logged_in = matches!(self.auth_state, AuthState::LoggedIn(_));

        // Main UI layout
        egui::CentralPanel::default()
            .frame(egui::Frame::none().fill(BG_SIDEBAR))
            .show(ctx, |ui| {
                if is_logged_in {
                    // Modern layout with sidebar
                    ui.horizontal(|ui| {
                        // Sidebar
                        ui.allocate_ui(egui::vec2(SIDEBAR_WIDTH, ui.available_height()), |ui| {
                            if let Some(page) = render_sidebar(
                                ui,
                                self.current_page,
                                &mut self.animations,
                                None,
                                env!("CARGO_PKG_VERSION"),
                                self.app_start_time,
                            ) {
                                self.current_page = page;
                                self.mark_dirty();
                            }
                        });

                        // Main content area
                        egui::Frame::none()
                            .fill(BG_MAIN)
                            .show(ui, |ui| {
                                ui.set_min_size(ui.available_size());

                                ui.vertical(|ui| {
                                    // Header
                                    ui.allocate_ui(egui::vec2(ui.available_width(), HEADER_HEIGHT), |ui| {
                                        let connected_region = if let ConnectionState::Connected { server_region, .. } = &self.vpn_state {
                                            Some(server_region.as_str())
                                        } else {
                                            None
                                        };
                                        let connected_latency = connected_region
                                            .and_then(|r| self.cached_latencies.get(r))
                                            .and_then(|l| *l);

                                        match render_header(
                                            ui,
                                            self.vpn_state.is_connected(),
                                            self.vpn_state.is_connecting(),
                                            connected_region,
                                            connected_latency,
                                            &mut self.animations,
                                            self.app_start_time,
                                        ) {
                                            HeaderAction::ToggleVpn => {
                                                if self.vpn_state.is_connected() {
                                                    self.disconnect_vpn();
                                                } else {
                                                    self.connect_vpn();
                                                }
                                            }
                                            HeaderAction::Minimize => {
                                                ctx.send_viewport_cmd(egui::ViewportCommand::Minimized(true));
                                            }
                                            HeaderAction::Close => {
                                                if self.minimize_to_tray && self.system_tray.is_some() {
                                                    ctx.send_viewport_cmd(egui::ViewportCommand::Visible(false));
                                                } else {
                                                    ctx.send_viewport_cmd(egui::ViewportCommand::Close);
                                                }
                                            }
                                            HeaderAction::None => {}
                                        }
                                    });

                                    // Page content with padding
                                    egui::Frame::none()
                                        .inner_margin(egui::Margin::same(CONTENT_PADDING))
                                        .show(ui, |ui| {
                                            egui::ScrollArea::vertical()
                                                .auto_shrink([false, false])
                                                .show(ui, |ui| {
                                                    self.render_current_page(ui);
                                                });
                                        });
                                });
                            });
                    });
                } else {
                    // Login screen (centered, no sidebar)
                    egui::Frame::none()
                        .fill(BG_MAIN)
                        .show(ui, |ui| {
                            self.render_login_screen(ui);
                        });
                }
            });

        // Process notification toast
        self.render_process_notification(ctx);
    }
}

impl BoosterApp {
    fn render_current_page(&mut self, ui: &mut egui::Ui) {
        match self.current_page {
            Page::Home => {
                let tunneled: Vec<String> = if let ConnectionState::Connected { tunneled_processes, .. } = &self.vpn_state {
                    tunneled_processes.clone()
                } else {
                    Vec::new()
                };

                let state = HomePageState {
                    vpn_state: &self.vpn_state,
                    regions: &self.cached_regions,
                    latencies: &self.cached_latencies,
                    selected_region: &self.selected_region,
                    last_connected_region: self.last_connected_region.as_deref(),
                    is_loading: self.servers_loading,
                    finding_best: self.finding_best_server.load(Ordering::Relaxed),
                    tunneled_processes: &tunneled,
                    app_start_time: self.app_start_time,
                };

                match render_home_page(ui, &state, &mut self.animations) {
                    HomePageAction::Connect => self.connect_vpn(),
                    HomePageAction::Disconnect => self.disconnect_vpn(),
                    HomePageAction::SelectRegion(region) => {
                        self.selected_region = region.clone();
                        self.selected_server = region;
                        self.mark_dirty();
                    }
                    HomePageAction::None => {}
                }
            }

            Page::Games => {
                let tunneled: Vec<String> = if let ConnectionState::Connected { tunneled_processes, .. } = &self.vpn_state {
                    tunneled_processes.clone()
                } else {
                    Vec::new()
                };

                let state = GamesPageState {
                    vpn_state: &self.vpn_state,
                    selected_presets: &self.selected_game_presets,
                    tunneled_processes: &tunneled,
                };

                match render_games_page(ui, &state, &mut self.animations) {
                    GamesPageAction::TogglePreset(preset) => {
                        if self.selected_game_presets.contains(&preset) {
                            self.selected_game_presets.remove(&preset);
                        } else {
                            self.selected_game_presets.insert(preset);
                        }
                        self.mark_dirty();
                    }
                    GamesPageAction::None => {}
                }
            }

            Page::Boost => {
                let state = BoostPageState {
                    config: &self.state.config,
                    selected_profile: self.selected_profile,
                    optimizations_active: self.state.optimizations_active,
                    expanded_info: &self.expanded_boost_info,
                };

                match render_boost_page(ui, &state, &mut self.animations) {
                    BoostPageAction::ToggleOptimizations => {
                        self.state.optimizations_active = !self.state.optimizations_active;
                        self.mark_dirty();
                    }
                    BoostPageAction::SelectProfile(profile) => {
                        self.selected_profile = profile;
                        self.state.config.profile = profile;
                        // Apply profile defaults
                        match profile {
                            OptimizationProfile::LowEnd => {
                                // Performance/Low-end PC mode - all optimizations enabled
                                self.state.config.system_optimization.set_high_priority = true;
                                self.state.config.system_optimization.timer_resolution_1ms = true;
                                self.state.config.system_optimization.mmcss_gaming_profile = true;
                            }
                            OptimizationProfile::Balanced => {
                                self.state.config.system_optimization.set_high_priority = true;
                                self.state.config.system_optimization.timer_resolution_1ms = true;
                                self.state.config.system_optimization.mmcss_gaming_profile = false;
                            }
                            OptimizationProfile::HighEnd => {
                                // Quality/High-end PC mode - minimal optimizations
                                self.state.config.system_optimization.set_high_priority = false;
                                self.state.config.system_optimization.timer_resolution_1ms = false;
                                self.state.config.system_optimization.mmcss_gaming_profile = false;
                            }
                            OptimizationProfile::Custom => {
                                // Don't change settings for custom profile
                            }
                        }
                        self.mark_dirty();
                    }
                    BoostPageAction::ToggleSetting(setting) => {
                        match setting {
                            BoostSetting::HighPriority => {
                                self.state.config.system_optimization.set_high_priority =
                                    !self.state.config.system_optimization.set_high_priority;
                            }
                            BoostSetting::TimerResolution => {
                                self.state.config.system_optimization.timer_resolution_1ms =
                                    !self.state.config.system_optimization.timer_resolution_1ms;
                            }
                            BoostSetting::MMCSS => {
                                self.state.config.system_optimization.mmcss_gaming_profile =
                                    !self.state.config.system_optimization.mmcss_gaming_profile;
                            }
                            BoostSetting::GameMode => {
                                self.state.config.system_optimization.game_mode_enabled =
                                    !self.state.config.system_optimization.game_mode_enabled;
                            }
                            BoostSetting::DisableNagle => {
                                self.state.config.network_settings.disable_nagle =
                                    !self.state.config.network_settings.disable_nagle;
                            }
                            BoostSetting::DisableThrottling => {
                                self.state.config.network_settings.disable_network_throttling =
                                    !self.state.config.network_settings.disable_network_throttling;
                            }
                            BoostSetting::OptimizeMTU => {
                                self.state.config.network_settings.optimize_mtu =
                                    !self.state.config.network_settings.optimize_mtu;
                            }
                        }
                        self.mark_dirty();
                    }
                    BoostPageAction::ToggleExpand(id) => {
                        if self.expanded_boost_info.contains(&id) {
                            self.expanded_boost_info.remove(&id);
                        } else {
                            self.expanded_boost_info.insert(id);
                        }
                        self.mark_dirty();
                    }
                    BoostPageAction::SetTargetFps(fps) => {
                        self.state.config.roblox_settings.target_fps = fps;
                        self.mark_dirty();
                    }
                    BoostPageAction::SetGraphicsQuality(graphics_quality) => {
                        self.state.config.roblox_settings.graphics_quality = graphics_quality;
                        self.mark_dirty();
                    }
                    BoostPageAction::None => {}
                }
            }

            Page::Network => {
                let state = NetworkPageState {
                    analyzer_state: &self.network_analyzer_state,
                    download_gauge_anim: self.download_gauge_animation.as_ref(),
                    upload_gauge_anim: self.upload_gauge_animation.as_ref(),
                    app_start_time: self.app_start_time,
                };

                match render_network_page(ui, &state, &mut self.animations) {
                    NetworkPageAction::StartStabilityTest => self.start_stability_test(),
                    NetworkPageAction::StartSpeedTest => self.start_speed_test(),
                    NetworkPageAction::None => {}
                }
            }

            Page::Settings => {
                let state = SettingsPageState {
                    minimize_to_tray: self.minimize_to_tray,
                    auto_update: self.update_settings.auto_check,
                    user_info: self.user_info.as_ref(),
                    current_section: self.settings_section,
                    version: env!("CARGO_PKG_VERSION"),
                };

                match render_settings_page(ui, &state, &mut self.animations) {
                    SettingsPageAction::ToggleMinimizeToTray => {
                        self.minimize_to_tray = !self.minimize_to_tray;
                        if let Some(ref tray) = self.system_tray {
                            tray.set_minimize_to_tray(self.minimize_to_tray);
                        }
                        self.mark_dirty();
                    }
                    SettingsPageAction::ToggleAutoUpdate => {
                        self.update_settings.auto_check = !self.update_settings.auto_check;
                        self.mark_dirty();
                    }
                    SettingsPageAction::Logout => self.logout(),
                    SettingsPageAction::CheckForUpdates => self.start_update_check(),
                    SettingsPageAction::SwitchSection(section) => {
                        self.settings_section = section;
                    }
                    SettingsPageAction::None => {}
                }
            }
        }
    }

    fn render_login_screen(&mut self, ui: &mut egui::Ui) {
        let available = ui.available_size();

        ui.vertical_centered(|ui| {
            ui.add_space((available.y - 400.0) / 2.0);

            // Logo and header
            render_auth_header(ui, self.app_start_time);

            ui.add_space(32.0);

            // Login form card
            egui::Frame::none()
                .fill(BG_CARD)
                .rounding(CARD_ROUNDING)
                .inner_margin(CONTENT_PADDING)
                .show(ui, |ui| {
                    ui.set_max_width(340.0);

                    ui.label(egui::RichText::new("Sign in to your account")
                        .size(14.0)
                        .color(TEXT_SECONDARY));

                    ui.add_space(16.0);

                    // Email input
                    ui.label(egui::RichText::new("Email").size(12.0).color(TEXT_MUTED));
                    let email_edit = egui::TextEdit::singleline(&mut self.login_email)
                        .hint_text("you@example.com")
                        .margin(egui::Margin::symmetric(12.0, 10.0));
                    ui.add(email_edit);

                    ui.add_space(12.0);

                    // Password input
                    ui.label(egui::RichText::new("Password").size(12.0).color(TEXT_MUTED));
                    let password_edit = egui::TextEdit::singleline(&mut self.login_password)
                        .password(true)
                        .hint_text("••••••••")
                        .margin(egui::Margin::symmetric(12.0, 10.0));
                    ui.add(password_edit);

                    // Error message
                    if let Some(ref error) = self.auth_error {
                        ui.add_space(8.0);
                        ui.label(egui::RichText::new(error)
                            .size(11.0)
                            .color(STATUS_ERROR));
                    }

                    ui.add_space(16.0);

                    // Sign in button
                    let can_login = !self.login_email.is_empty() && !self.login_password.is_empty();
                    let login_btn = egui::Button::new(
                        egui::RichText::new("Sign In")
                            .size(14.0)
                            .color(TEXT_PRIMARY)
                    )
                    .fill(ACCENT_PRIMARY)
                    .rounding(8.0)
                    .min_size(egui::vec2(ui.available_width(), 40.0));

                    if ui.add_enabled(can_login, login_btn).clicked() {
                        self.start_login();
                    }

                    ui.add_space(12.0);

                    // Divider
                    ui.horizontal(|ui| {
                        let line_width = (ui.available_width() - 40.0) / 2.0;
                        let (r1, _) = ui.allocate_exact_size(egui::vec2(line_width, 1.0), egui::Sense::hover());
                        ui.painter().rect_filled(r1, 0.0, BG_ELEVATED);
                        ui.label(egui::RichText::new("or").size(11.0).color(TEXT_MUTED));
                        let (r2, _) = ui.allocate_exact_size(egui::vec2(line_width, 1.0), egui::Sense::hover());
                        ui.painter().rect_filled(r2, 0.0, BG_ELEVATED);
                    });

                    ui.add_space(12.0);

                    // Google OAuth button
                    let google_btn = egui::Button::new(
                        egui::RichText::new("🔷 Continue with Google")
                            .size(13.0)
                            .color(TEXT_PRIMARY)
                    )
                    .fill(BG_ELEVATED)
                    .stroke(egui::Stroke::new(1.0, BG_HOVER))
                    .rounding(8.0)
                    .min_size(egui::vec2(ui.available_width(), 40.0));

                    if ui.add(google_btn).clicked() {
                        self.start_oauth();
                    }
                });
        });
    }

    fn render_process_notification(&mut self, ctx: &egui::Context) {
        let should_show = if let Some((_, time)) = &self.process_notification {
            time.elapsed() < std::time::Duration::from_secs(3)
        } else {
            false
        };

        if should_show {
            if let Some((msg, time)) = &self.process_notification {
                let elapsed = time.elapsed().as_secs_f32();
                let alpha = if elapsed > 2.5 {
                    1.0 - ((elapsed - 2.5) / 0.5)
                } else {
                    1.0
                };

                egui::Area::new(egui::Id::new("process_notification"))
                    .anchor(egui::Align2::CENTER_TOP, [0.0, HEADER_HEIGHT + 20.0])
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

                ctx.request_repaint();
            }
        } else if self.process_notification.is_some() {
            self.process_notification = None;
        }
    }
}
