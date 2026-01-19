use crate::auth::{AuthManager, AuthState, UserInfo};
use crate::hidden_command;
use crate::performance_monitor::SystemInfo;
use crate::roblox_optimizer::RobloxOptimizer;
use crate::settings::{load_settings, save_settings, AppSettings, WindowState};
use crate::structs::*;
use crate::system_optimizer::SystemOptimizer;
use crate::tray::SystemTray;
use crate::updater::{UpdateChecker, UpdateInfo, UpdateSettings, UpdateState, download_update, download_checksum, verify_checksum, install_update};
use crate::vpn::{ConnectionState, VpnConnection, DynamicServerList, DynamicGamingRegion, load_server_list, ServerListSource};
use crate::vpn::split_tunnel::get_default_tunnel_apps;
use eframe::egui;
use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::sync::atomic::{AtomicBool, Ordering};

// ═══════════════════════════════════════════════════════════════════════════════
//  SWIFTTUNNEL DESIGN SYSTEM v4
//  Deep Blue - Dark theme with blue/cyan accents
//  Matching the web dashboard design
// ═══════════════════════════════════════════════════════════════════════════════

const BG_DARKEST: egui::Color32 = egui::Color32::from_rgb(8, 12, 21);      // Deep dark blue-black
const BG_CARD: egui::Color32 = egui::Color32::from_rgb(15, 20, 32);        // Slightly lighter card bg
const BG_ELEVATED: egui::Color32 = egui::Color32::from_rgb(22, 28, 42);    // Elevated surfaces
const BG_HOVER: egui::Color32 = egui::Color32::from_rgb(30, 38, 55);       // Hover state
const BG_INPUT: egui::Color32 = egui::Color32::from_rgb(18, 24, 38);       // Input field background

const ACCENT_PRIMARY: egui::Color32 = egui::Color32::from_rgb(59, 130, 246);  // Blue accent (#3b82f6)
const ACCENT_CYAN: egui::Color32 = egui::Color32::from_rgb(34, 211, 238);     // Cyan for highlights (#22d3ee)
const STATUS_CONNECTED: egui::Color32 = egui::Color32::from_rgb(52, 211, 153);
const STATUS_WARNING: egui::Color32 = egui::Color32::from_rgb(251, 191, 36);
const STATUS_ERROR: egui::Color32 = egui::Color32::from_rgb(248, 113, 113);
const STATUS_INACTIVE: egui::Color32 = egui::Color32::from_rgb(100, 100, 120);

const TEXT_PRIMARY: egui::Color32 = egui::Color32::from_rgb(250, 250, 255);
const TEXT_SECONDARY: egui::Color32 = egui::Color32::from_rgb(148, 163, 184);  // slate-400
const TEXT_MUTED: egui::Color32 = egui::Color32::from_rgb(100, 116, 139);      // slate-500

#[derive(PartialEq, Clone, Copy)]
enum Tab { Connect, Boost, Settings }

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
    split_tunnel_apps: Vec<String>,

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
            split_tunnel_apps: get_default_tunnel_apps(),
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
                Tab::Connect => "connect", Tab::Boost => "boost", Tab::Settings => "settings",
            }.to_string(),
            update_settings: self.update_settings.clone(),
            minimize_to_tray: self.minimize_to_tray,
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
        // PERFORMANCE FIX: Only request continuous repaint when actually needed
        let is_loading = self.servers_loading || self.finding_best_server.load(Ordering::Relaxed);
        let is_vpn_transitioning = self.vpn_state.is_connecting() || matches!(self.vpn_state, ConnectionState::Disconnecting);
        let is_logging_in = matches!(self.auth_state, AuthState::LoggingIn);
        let is_awaiting_oauth_here = matches!(self.auth_state, AuthState::AwaitingOAuthCallback(_));
        let is_updating = self.update_state.lock().map(|s| s.is_downloading()).unwrap_or(false);

        if is_loading || is_vpn_transitioning || is_logging_in || is_awaiting_oauth_here || is_updating {
            // Only repaint every 100ms during active states (10 FPS for spinners)
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

        // Handle close button - minimize to tray instead of closing if enabled
        let close_requested = ctx.input(|i| i.viewport().close_requested());
        if close_requested && self.minimize_to_tray && self.system_tray.is_some() {
            // Cancel the close and minimize to tray instead
            ctx.send_viewport_cmd(egui::ViewportCommand::CancelClose);
            ctx.send_viewport_cmd(egui::ViewportCommand::Visible(false));
            log::info!("Close button pressed - minimizing to tray");
        }

        // Only actually quit when tray "Quit" is clicked
        if quit {
            // Force save settings before quitting
            self.settings_dirty = true;
            self.last_save_time = std::time::Instant::now() - std::time::Duration::from_secs(10);
            self.save_if_needed(ctx);
            ctx.send_viewport_cmd(egui::ViewportCommand::Close);
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

        // PERFORMANCE FIX: Only check VPN state every 500ms, not every frame
        // Use try_lock to avoid blocking the UI thread
        if self.last_vpn_check.elapsed() >= std::time::Duration::from_millis(500) {
            self.last_vpn_check = std::time::Instant::now();

            // Non-blocking VPN state check using try_lock
            if let Ok(vpn) = self.vpn_connection.try_lock() {
                // Get state directly - the state() method is fast
                self.vpn_state = self.runtime.block_on(vpn.state());
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
                                        Tab::Settings => self.render_settings_tab(ui),
                                    }
                                }
                                ui.add_space(32.0);
                            });
                            ui.add_space(side_margin);
                        });
                    });
            });
    }
}

impl BoosterApp {
    fn render_header(&self, ui: &mut egui::Ui) {
        ui.horizontal(|ui| {
            // Draw wave/tunnel logo icon
            let logo_size = 28.0;
            let (rect, _) = ui.allocate_exact_size(egui::vec2(logo_size, logo_size), egui::Sense::hover());
            let center = rect.center();

            // Draw stylized wave/tunnel shape
            let wave_color = ACCENT_CYAN;
            ui.painter().circle_filled(center, logo_size * 0.45, wave_color.gamma_multiply(0.2));

            // Draw curved lines for wave effect
            for i in 0..3 {
                let offset = (i as f32 - 1.0) * 4.0;
                let start = egui::pos2(center.x - 7.0, center.y + offset);
                let end = egui::pos2(center.x + 7.0, center.y + offset);
                let control1 = egui::pos2(center.x - 3.0, center.y + offset - 3.0);
                let control2 = egui::pos2(center.x + 3.0, center.y + offset + 3.0);

                let points = [start, control1, control2, end];
                let stroke = egui::Stroke::new(1.5, wave_color);
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

            ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                let (status_text, status_color) = if self.vpn_state.is_connected() {
                    ("PROTECTED", STATUS_CONNECTED)
                } else {
                    ("NOT CONNECTED", STATUS_INACTIVE)
                };

                let (rect, _) = ui.allocate_exact_size(egui::vec2(8.0, 8.0), egui::Sense::hover());
                ui.painter().circle_filled(rect.center(), 4.0, status_color);
                ui.add_space(6.0);
                ui.label(egui::RichText::new(status_text).size(11.0).color(status_color));
            });
        });
    }

    fn render_nav_tabs(&mut self, ui: &mut egui::Ui) {
        ui.horizontal(|ui| {
            ui.spacing_mut().item_spacing.x = 8.0;

            for (label, tab) in [("Connect", Tab::Connect), ("Boost", Tab::Boost), ("Settings", Tab::Settings)] {
                let is_active = self.current_tab == tab;
                let (bg, text_color) = if is_active { (ACCENT_PRIMARY, TEXT_PRIMARY) } else { (BG_CARD, TEXT_SECONDARY) };

                if ui.add(
                    egui::Button::new(egui::RichText::new(label).size(14.0).color(text_color))
                        .fill(bg).rounding(8.0).min_size(egui::vec2(100.0, 40.0))
                ).clicked() {
                    self.current_tab = tab;
                    self.mark_dirty();
                }
            }
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
        self.render_region_selector(ui);
        ui.add_space(16.0);
        self.render_quick_info(ui);
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
        let (status_text, status_color, detail_text, show_connected_info) = match &self.vpn_state {
            ConnectionState::Disconnected => ("Disconnected", STATUS_INACTIVE, "Ready to connect".to_string(), false),
            ConnectionState::FetchingConfig => ("Connecting...", STATUS_WARNING, "Fetching config".to_string(), false),
            ConnectionState::CreatingAdapter => ("Connecting...", STATUS_WARNING, "Creating adapter".to_string(), false),
            ConnectionState::Connecting => ("Connecting...", STATUS_WARNING, "Establishing tunnel".to_string(), false),
            ConnectionState::ConfiguringSplitTunnel => ("Connecting...", STATUS_WARNING, "Configuring routing".to_string(), false),
            ConnectionState::Connected { server_region, .. } => {
                let name = if let Ok(list) = self.dynamic_server_list.lock() {
                    list.get_server(server_region)
                        .map(|s| s.name.clone())
                        .unwrap_or_else(|| server_region.clone())
                } else {
                    server_region.clone()
                };
                ("Connected", STATUS_CONNECTED, name, true)
            }
            ConnectionState::Disconnecting => ("Disconnecting...", STATUS_WARNING, "Please wait".to_string(), false),
            ConnectionState::Error(msg) => {
                // Format user-friendly VPN error messages
                let user_friendly = if msg.contains("Administrator privileges required") {
                    "Administrator access required. Please restart the app as Administrator.".to_string()
                } else if msg.contains("wintun.dll not found") {
                    "Required driver not found. Please reinstall SwiftTunnel.".to_string()
                } else if msg.contains("401") || msg.contains("Unauthorized") {
                    "Session expired. Please sign out and sign in again.".to_string()
                } else if msg.contains("404") {
                    "Server not available. Please try a different region.".to_string()
                } else if msg.contains("timeout") || msg.contains("Timeout") {
                    "Connection timed out. Please check your internet and try again.".to_string()
                } else if msg.contains("Network error") || msg.contains("network") {
                    "Network error. Please check your internet connection.".to_string()
                } else if msg.contains("handshake") || msg.contains("Handshake") {
                    "Failed to establish secure connection. Please try again.".to_string()
                } else {
                    msg.clone()
                };
                ("Error", STATUS_ERROR, user_friendly, false)
            }
        };

        let is_connected = self.vpn_state.is_connected();
        let is_connecting = self.vpn_state.is_connecting();

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
                        ui.label(egui::RichText::new(status_text).size(18.0).color(status_color).strong());
                        ui.label(egui::RichText::new(&detail_text).size(13.0).color(TEXT_SECONDARY));
                    });

                    ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                        let (btn_text, btn_color) = if is_connected {
                            ("Disconnect", STATUS_ERROR)
                        } else if is_connecting {
                            ("Cancel", STATUS_WARNING)
                        } else {
                            ("Connect", ACCENT_PRIMARY)
                        };

                        if ui.add(
                            egui::Button::new(egui::RichText::new(btn_text).size(14.0).color(TEXT_PRIMARY).strong())
                                .fill(btn_color).rounding(8.0).min_size(egui::vec2(120.0, 44.0))
                        ).clicked() {
                            if is_connected || is_connecting {
                                do_disconnect = true;
                            } else {
                                do_connect = true;
                            }
                        }
                    });
                });

                if show_connected_info {
                    ui.add_space(16.0);
                    ui.separator();
                    ui.add_space(12.0);

                    ui.horizontal(|ui| {
                        ui.label(egui::RichText::new("IP Address").size(12.0).color(TEXT_MUTED));
                        ui.add_space(8.0);
                        ui.label(egui::RichText::new(&assigned_ip).size(12.0).color(TEXT_PRIMARY));
                        ui.add_space(24.0);
                        ui.label(egui::RichText::new("Uptime").size(12.0).color(TEXT_MUTED));
                        ui.add_space(8.0);
                        ui.label(egui::RichText::new(&uptime_str).size(12.0).color(TEXT_PRIMARY));
                    });

                    // Show split tunnel status
                    if split_tunnel_active {
                        ui.add_space(12.0);
                        ui.horizontal(|ui| {
                            ui.label(egui::RichText::new("Split Tunnel").size(12.0).color(TEXT_MUTED));
                            ui.add_space(8.0);
                            if tunneled_processes.is_empty() {
                                ui.label(egui::RichText::new("⏳ Waiting for Roblox...").size(12.0).color(STATUS_WARNING));
                            } else {
                                let process_names = tunneled_processes.join(", ");
                                ui.label(egui::RichText::new(format!("✓ Tunneling: {}", process_names)).size(12.0).color(STATUS_CONNECTED));
                            }
                        });
                    }
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

        // Section header with loading indicator
        ui.horizontal(|ui| {
            ui.label(egui::RichText::new("SELECT REGION").size(12.0).color(TEXT_MUTED).strong());
            ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                if is_loading {
                    ui.spinner();
                    ui.add_space(4.0);
                    ui.label(egui::RichText::new("Loading servers...").size(11.0).color(ACCENT_PRIMARY));
                } else if is_finding {
                    ui.spinner();
                    ui.add_space(4.0);
                    ui.label(egui::RichText::new("Measuring latency...").size(11.0).color(ACCENT_PRIMARY));
                } else {
                    ui.label(egui::RichText::new(format!("{} regions", regions.len())).size(11.0).color(TEXT_MUTED));
                }
            });
        });
        ui.add_space(12.0);

        // Show loading or error state if no regions
        if regions.is_empty() {
            egui::Frame::none()
                .fill(BG_CARD)
                .stroke(egui::Stroke::new(1.0, BG_ELEVATED))
                .rounding(10.0)
                .inner_margin(egui::Margin::symmetric(20.0, 30.0))
                .show(ui, |ui| {
                    ui.vertical_centered(|ui| {
                        if is_loading {
                            ui.spinner();
                            ui.add_space(12.0);
                            ui.label(egui::RichText::new("Loading server list...")
                                .size(14.0)
                                .color(TEXT_SECONDARY));
                            ui.add_space(8.0);
                            ui.label(egui::RichText::new("Fetching from swifttunnel.net")
                                .size(12.0)
                                .color(TEXT_MUTED));
                        } else if let Some(err) = &error_msg {
                            ui.label(egui::RichText::new("Failed to load servers")
                                .size(14.0)
                                .color(STATUS_ERROR)
                                .strong());
                            ui.add_space(8.0);
                            ui.label(egui::RichText::new(err)
                                .size(12.0)
                                .color(TEXT_MUTED));
                            ui.add_space(16.0);
                            if ui.button(egui::RichText::new("Retry")
                                .size(13.0)
                                .color(ACCENT_PRIMARY)).clicked() {
                                self.retry_load_servers();
                            }
                        } else {
                            ui.label(egui::RichText::new("No servers available")
                                .size(14.0)
                                .color(TEXT_MUTED));
                        }
                    });
                });
            return;
        }

        // Calculate grid dimensions - 2 columns
        let available_width = ui.available_width();
        let card_spacing = 10.0;
        let card_width = (available_width - card_spacing) / 2.0;

        // Create 2-column grid
        let mut region_iter = regions.iter().peekable();
        while region_iter.peek().is_some() {
            ui.horizontal(|ui| {
                ui.spacing_mut().item_spacing.x = card_spacing;

                for _ in 0..2 {
                    if let Some(region) = region_iter.next() {
                        let is_selected = self.selected_region == region.id;
                        let latency = latencies.get(&region.id).and_then(|l| *l);

                        let (bg, border_color) = if is_selected {
                            (ACCENT_PRIMARY.gamma_multiply(0.18), ACCENT_PRIMARY)
                        } else {
                            (BG_CARD, BG_ELEVATED)
                        };

                        let response = egui::Frame::none()
                            .fill(bg)
                            .stroke(egui::Stroke::new(if is_selected { 2.0 } else { 1.0 }, border_color))
                            .rounding(10.0)
                            .inner_margin(egui::Margin::symmetric(12.0, 12.0))
                            .show(ui, |ui| {
                                ui.set_width(card_width - 24.0);
                                ui.set_min_height(70.0);

                                ui.vertical(|ui| {
                                    ui.horizontal(|ui| {
                                        egui::Frame::none()
                                            .fill(if is_selected { ACCENT_PRIMARY } else { BG_ELEVATED })
                                            .rounding(4.0)
                                            .inner_margin(egui::Margin::symmetric(8.0, 4.0))
                                            .show(ui, |ui| {
                                                ui.label(egui::RichText::new(&region.country_code)
                                                    .size(12.0)
                                                    .color(if is_selected { egui::Color32::WHITE } else { TEXT_SECONDARY })
                                                    .strong());
                                            });

                                        ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                                            if let Some(ms) = latency {
                                                let latency_color = if ms < 50 {
                                                    STATUS_CONNECTED
                                                } else if ms < 100 {
                                                    egui::Color32::from_rgb(163, 230, 53)
                                                } else if ms < 150 {
                                                    STATUS_WARNING
                                                } else {
                                                    STATUS_ERROR
                                                };
                                                ui.label(egui::RichText::new(format!("{}ms", ms))
                                                    .size(12.0)
                                                    .color(latency_color)
                                                    .strong());
                                            } else if is_finding {
                                                // Show placeholder during initial measurement
                                                ui.label(egui::RichText::new("...")
                                                    .size(12.0)
                                                    .color(TEXT_MUTED));
                                            }
                                        });
                                    });

                                    ui.add_space(6.0);
                                    ui.label(egui::RichText::new(&region.name)
                                        .size(14.0)
                                        .color(if is_selected { ACCENT_PRIMARY } else { TEXT_PRIMARY })
                                        .strong());
                                    ui.label(egui::RichText::new(&region.description)
                                        .size(11.0)
                                        .color(TEXT_MUTED));
                                });
                            });

                        if response.response.interact(egui::Sense::click()).clicked() {
                            clicked_region = Some(region.id.clone());
                        }
                    }
                }
            });
            ui.add_space(8.0);
        }

        // Handle click - just select the region, don't re-ping
        if let Some(region_id) = clicked_region {
            self.select_region(&region_id);
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

            for (title, desc, icon, profile) in [
                ("Performance", "Maximum FPS", "⚡", OptimizationProfile::LowEnd),
                ("Balanced", "FPS + Quality", "⚖", OptimizationProfile::Balanced),
                ("Quality", "Best Visuals", "✨", OptimizationProfile::HighEnd),
            ] {
                let is_selected = self.selected_profile == profile;
                let (bg, border, text_color) = if is_selected {
                    (ACCENT_PRIMARY.gamma_multiply(0.15), ACCENT_PRIMARY, ACCENT_PRIMARY)
                } else {
                    (BG_CARD, BG_ELEVATED, TEXT_PRIMARY)
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
                    ui.label(egui::RichText::new("TIER 1").size(10.0).color(STATUS_CONNECTED));
                });
                ui.add_space(4.0);
                ui.label(egui::RichText::new("Safe optimizations with no side effects").size(11.0).color(TEXT_MUTED));
                ui.add_space(12.0);

                self.render_toggle_row(ui, "High Priority Mode", "Boosts game process priority",
                    self.state.config.system_optimization.set_high_priority, |app| {
                    app.state.config.system_optimization.set_high_priority = !app.state.config.system_optimization.set_high_priority;
                });
                ui.add_space(10.0);

                self.render_toggle_row(ui, "1ms Timer Resolution", "Smoother frame pacing",
                    self.state.config.system_optimization.timer_resolution_1ms, |app| {
                    app.state.config.system_optimization.timer_resolution_1ms = !app.state.config.system_optimization.timer_resolution_1ms;
                });
                ui.add_space(10.0);

                self.render_toggle_row(ui, "MMCSS Gaming Profile", "Better thread scheduling",
                    self.state.config.system_optimization.mmcss_gaming_profile, |app| {
                    app.state.config.system_optimization.mmcss_gaming_profile = !app.state.config.system_optimization.mmcss_gaming_profile;
                });
                ui.add_space(10.0);

                self.render_toggle_row(ui, "Windows Game Mode", "System resource prioritization",
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
                    ui.label(egui::RichText::new("TIER 1").size(10.0).color(STATUS_CONNECTED));
                });
                ui.add_space(4.0);
                ui.label(egui::RichText::new("Lower latency for online games").size(11.0).color(TEXT_MUTED));
                ui.add_space(12.0);

                self.render_toggle_row(ui, "Disable Nagle's Algorithm", "Faster packet delivery (-5-15ms)",
                    self.state.config.network_settings.disable_nagle, |app| {
                    app.state.config.network_settings.disable_nagle = !app.state.config.network_settings.disable_nagle;
                });
                ui.add_space(10.0);

                self.render_toggle_row(ui, "Disable Network Throttling", "Full bandwidth for games",
                    self.state.config.network_settings.disable_network_throttling, |app| {
                    app.state.config.network_settings.disable_network_throttling = !app.state.config.network_settings.disable_network_throttling;
                });
                ui.add_space(10.0);

                self.render_toggle_row(ui, "Optimize MTU", "Find & apply best packet size",
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
                ui.label(egui::RichText::new("Gaming VPN & Optimization Suite").size(12.0).color(TEXT_SECONDARY));
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
    fn render_toggle_row(&mut self, ui: &mut egui::Ui, label: &str, description: &str, value: bool, on_toggle: fn(&mut Self)) {
        ui.horizontal(|ui| {
            ui.vertical(|ui| {
                ui.label(egui::RichText::new(label).size(13.0).color(TEXT_PRIMARY));
                ui.label(egui::RichText::new(description).size(11.0).color(TEXT_MUTED));
            });
            ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                let size = egui::vec2(44.0, 24.0);
                let (rect, response) = ui.allocate_exact_size(size, egui::Sense::click());
                if response.clicked() {
                    on_toggle(self);
                    self.mark_dirty();
                }
                let bg = if value { ACCENT_PRIMARY } else { BG_ELEVATED };
                let knob_x = if value { rect.right() - 12.0 } else { rect.left() + 12.0 };
                ui.painter().rect_filled(rect, 12.0, bg);
                ui.painter().circle_filled(egui::pos2(knob_x, rect.center().y), 8.0, TEXT_PRIMARY);
            });
        });
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

        let region = self.selected_server.clone();
        let apps = self.split_tunnel_apps.clone();
        let vpn = Arc::clone(&self.vpn_connection);
        let rt = Arc::clone(&self.runtime);

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
            self.state.optimizations_active = false;
            self.set_status("Optimizations disabled", STATUS_WARNING);
        } else {
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
}
