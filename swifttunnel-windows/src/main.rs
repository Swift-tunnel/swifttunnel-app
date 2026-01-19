// Hide console window in release builds on Windows
#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

mod auth;
mod gui;
mod network_booster;
mod performance_monitor;
mod roblox_optimizer;
mod settings;
mod structs;
mod system_optimizer;
mod tray;
mod updater;
mod utils;
mod vpn;

// Re-export hidden_command for use in other modules
pub use utils::hidden_command;

use crate::structs::*;
use crate::system_optimizer::SystemOptimizer;
use crate::roblox_optimizer::RobloxOptimizer;
use crate::performance_monitor::PerformanceMonitor;
use crate::network_booster::NetworkBooster;
use crate::gui::BoosterApp;
use crate::settings::load_settings;

use eframe::NativeOptions;
use log::{error, info, warn};
use std::sync::{Arc, Mutex};
use std::time::Duration;
use std::panic;
use tokio::runtime::Runtime;
use url::Url;

/// Parsed OAuth callback data from deep link
#[derive(Debug, Clone)]
pub struct OAuthCallbackData {
    pub token: String,
    pub state: String,
}

/// Parse command line args for OAuth deep link callback
/// Returns Some(OAuthCallbackData) if a valid swifttunnel://callback URL was found
fn parse_deep_link_args() -> Option<OAuthCallbackData> {
    let args: Vec<String> = std::env::args().collect();

    // Log all args for debugging
    info!("Command line args: {:?}", args);

    for arg in args.iter().skip(1) { // Skip the executable name
        if arg.starts_with("swifttunnel://") {
            info!("Found deep link URL: {}", arg);

            match Url::parse(arg) {
                Ok(url) => {
                    // Check if this is a callback URL
                    if url.host_str() == Some("callback") || url.path() == "/callback" {
                        let mut token = None;
                        let mut state = None;

                        for (key, value) in url.query_pairs() {
                            match key.as_ref() {
                                "token" => token = Some(value.to_string()),
                                "state" => state = Some(value.to_string()),
                                _ => {}
                            }
                        }

                        if let (Some(t), Some(s)) = (token, state) {
                            info!("Parsed OAuth callback: token={}..., state={}...",
                                &t[..t.len().min(8)], &s[..s.len().min(8)]);
                            return Some(OAuthCallbackData { token: t, state: s });
                        } else {
                            warn!("OAuth callback URL missing token or state parameter");
                        }
                    }
                }
                Err(e) => {
                    warn!("Failed to parse deep link URL: {}", e);
                }
            }
        }
    }

    None
}


/// Set up crash logging to capture panics
fn setup_panic_hook() {
    panic::set_hook(Box::new(|info| {
        // Get location info
        let location = info.location()
            .map(|l| format!("{}:{}:{}", l.file(), l.line(), l.column()))
            .unwrap_or_else(|| "unknown location".to_string());

        // Get panic message
        let message = if let Some(s) = info.payload().downcast_ref::<&str>() {
            s.to_string()
        } else if let Some(s) = info.payload().downcast_ref::<String>() {
            s.clone()
        } else {
            "Unknown panic".to_string()
        };

        // Log to stderr (visible in console)
        eprintln!("PANIC at {}: {}", location, message);

        // Try to write crash log
        if let Some(data_dir) = dirs::data_local_dir() {
            let crash_dir = data_dir.join("SwiftTunnel");
            let _ = std::fs::create_dir_all(&crash_dir);
            let crash_file = crash_dir.join("crash.log");

            let crash_info = format!(
                "[{}] PANIC at {}: {}\nBacktrace (if RUST_BACKTRACE=1):\n{:?}\n\n",
                chrono::Local::now().format("%Y-%m-%d %H:%M:%S"),
                location,
                message,
                std::backtrace::Backtrace::capture()
            );

            if std::fs::write(&crash_file, &crash_info).is_ok() {
                eprintln!("Crash log written to: {}", crash_file.display());
            }
        }
    }));
}

fn main() -> eframe::Result<()> {
    // Set up panic hook FIRST, before any other initialization
    setup_panic_hook();

    // Create log directory
    let log_dir = dirs::data_local_dir()
        .map(|d| d.join("SwiftTunnel"))
        .unwrap_or_else(|| std::path::PathBuf::from("."));
    let _ = std::fs::create_dir_all(&log_dir);

    // Set up file logging for release builds (console is hidden)
    let log_file_path = log_dir.join("swifttunnel.log");

    // Initialize logger - write to file so we can debug release builds
    let log_level = std::env::var("RUST_LOG")
        .map(|_| log::LevelFilter::Debug)
        .unwrap_or(log::LevelFilter::Info);

    // Try to set up file logging
    if let Ok(log_file) = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(&log_file_path)
    {
        env_logger::Builder::from_default_env()
            .filter_level(log_level)
            .format_timestamp_millis()
            .target(env_logger::Target::Pipe(Box::new(log_file)))
            .init();
    } else {
        // Fallback to stderr if file logging fails
        env_logger::Builder::from_default_env()
            .filter_level(log_level)
            .format_timestamp_millis()
            .init();
    }

    info!("========================================");
    info!("Starting SwiftTunnel v{}", env!("CARGO_PKG_VERSION"));
    info!("Log file: {}", log_file_path.display());
    info!("Log level: {:?}", log_level);

    // Check for OAuth callback deep link in command line args
    let oauth_callback = parse_deep_link_args();
    if oauth_callback.is_some() {
        info!("OAuth callback detected in command line args");
    }

    // Create tokio runtime for async operations
    let rt = Runtime::new().expect("Failed to create tokio runtime");

    // Create shared state
    let app_state = Arc::new(Mutex::new(AppState::default()));
    let state_clone = Arc::clone(&app_state);

    // Spawn background monitoring task
    rt.spawn(async move {
        let mut monitor = PerformanceMonitor::new();
        let mut system_optimizer = SystemOptimizer::new();
        let roblox_optimizer = RobloxOptimizer::new();
        let mut network_booster = NetworkBooster::new();

        let mut last_roblox_running = false;
        let mut optimizations_applied = false;

        loop {
            tokio::time::sleep(Duration::from_secs(1)).await;

            let mut state = state_clone.lock().unwrap();

            // Update performance metrics
            monitor.update_metrics(&mut state.metrics);

            // Check if Roblox started
            if state.metrics.roblox_running && !last_roblox_running {
                info!("Roblox process detected!");
                last_roblox_running = true;

                // Auto-apply optimizations if enabled
                if state.optimizations_active {
                    if let Some(pid) = state.metrics.process_id {
                        info!("Auto-applying optimizations...");

                        if let Err(e) = system_optimizer.apply_optimizations(
                            &state.config.system_optimization,
                            pid
                        ) {
                            error!("Failed to apply system optimizations: {}", e);
                            state.last_error = Some(format!("System optimization error: {}", e));
                        }

                        if let Err(e) = roblox_optimizer.apply_optimizations(&state.config.roblox_settings) {
                            error!("Failed to apply Roblox optimizations: {}", e);
                            state.last_error = Some(format!("Roblox optimization error: {}", e));
                        }

                        if let Err(e) = network_booster.apply_optimizations(&state.config.network_settings) {
                            error!("Failed to apply network optimizations: {}", e);
                            state.last_error = Some(format!("Network optimization error: {}", e));
                        }

                        optimizations_applied = true;
                        info!("Optimizations applied successfully!");
                    }
                }
            }

            // Check if Roblox stopped
            if !state.metrics.roblox_running && last_roblox_running {
                info!("Roblox process stopped");
                last_roblox_running = false;

                // Restore settings if optimizations were applied
                if optimizations_applied {
                    info!("Restoring original settings...");

                    if let Some(pid) = state.metrics.process_id {
                        let _ = system_optimizer.restore(pid);
                    }

                    let _ = roblox_optimizer.restore_settings();
                    let _ = network_booster.restore();

                    optimizations_applied = false;
                    info!("Settings restored");
                }
            }

            // Manual optimization toggle
            if state.optimizations_active && !optimizations_applied && state.metrics.roblox_running {
                if let Some(pid) = state.metrics.process_id {
                    info!("Manually applying optimizations...");

                    if let Err(e) = system_optimizer.apply_optimizations(
                        &state.config.system_optimization,
                        pid
                    ) {
                        error!("Failed to apply system optimizations: {}", e);
                        state.last_error = Some(format!("System optimization error: {}", e));
                    } else if let Err(e) = roblox_optimizer.apply_optimizations(&state.config.roblox_settings) {
                        error!("Failed to apply Roblox optimizations: {}", e);
                        state.last_error = Some(format!("Roblox optimization error: {}", e));
                    } else if let Err(e) = network_booster.apply_optimizations(&state.config.network_settings) {
                        error!("Failed to apply network optimizations: {}", e);
                        state.last_error = Some(format!("Network optimization error: {}", e));
                    } else {
                        optimizations_applied = true;
                        state.last_error = None;
                        info!("Optimizations applied successfully!");
                    }
                }
            }

            // Manual optimization disable
            if !state.optimizations_active && optimizations_applied {
                info!("Disabling optimizations...");

                if let Some(pid) = state.metrics.process_id {
                    let _ = system_optimizer.restore(pid);
                }

                let _ = roblox_optimizer.restore_settings();
                let _ = network_booster.restore();

                optimizations_applied = false;
                state.last_error = None;
                info!("Optimizations disabled");
            }

            drop(state); // Release lock
        }
    });

    // Load saved settings for window state
    let saved_settings = load_settings();
    let window_state = &saved_settings.window_state;

    // Build viewport - ALWAYS start maximized (fullscreen)
    let viewport = egui::ViewportBuilder::default()
        .with_title("SwiftTunnel")
        .with_min_inner_size([480.0, 600.0])  // Smaller minimum for flexibility
        .with_inner_size([window_state.width, window_state.height])
        .with_resizable(true)           // Allow window resizing
        .with_decorations(true)         // Show title bar with min/max/close buttons
        .with_transparent(false)        // Solid window background
        .with_maximized(true);          // FORCE maximized on startup

    // Launch GUI with glow (OpenGL) for better performance and compatibility
    let options = NativeOptions {
        viewport,
        renderer: eframe::Renderer::Glow,
        ..Default::default()
    };

    eframe::run_native(
        "SwiftTunnel FPS Booster",
        options,
        Box::new(move |cc| {
            let mut app = BoosterApp::new(cc);

            // Set initial system info
            let monitor = PerformanceMonitor::new();
            app.set_system_info(monitor.get_system_info());

            // Process OAuth callback if present (from deep link)
            if let Some(callback) = oauth_callback {
                info!("Processing OAuth callback from deep link...");
                app.process_oauth_callback(&callback.token, &callback.state);
            }

            // Update app state periodically from background thread
            let state_for_gui = Arc::clone(&app_state);
            let ctx = cc.egui_ctx.clone();

            std::thread::spawn(move || {
                loop {
                    std::thread::sleep(Duration::from_millis(100));

                    if let Ok(_state) = state_for_gui.try_lock() {
                        // Update GUI state from background state
                    }

                    ctx.request_repaint();
                }
            });

            Ok(Box::new(app))
        }),
    )
}
