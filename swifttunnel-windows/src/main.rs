// Hide console window in release builds on Windows
#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

// GUI module is only used by the main binary, not the library
mod gui;
mod tray;

// Use modules from the library crate
use swifttunnel_fps_booster::auth;
use swifttunnel_fps_booster::network_analyzer;
use swifttunnel_fps_booster::network_booster;
use swifttunnel_fps_booster::performance_monitor;
use swifttunnel_fps_booster::roblox_optimizer;
use swifttunnel_fps_booster::settings;
use swifttunnel_fps_booster::structs;
use swifttunnel_fps_booster::system_optimizer;
use swifttunnel_fps_booster::updater;
use swifttunnel_fps_booster::utils;
use swifttunnel_fps_booster::vpn;

// Re-export hidden_command for use in other modules
pub use swifttunnel_fps_booster::hidden_command;

use structs::*;
use system_optimizer::SystemOptimizer;
use roblox_optimizer::RobloxOptimizer;
use performance_monitor::PerformanceMonitor;
use network_booster::NetworkBooster;
use crate::gui::BoosterApp;  // Local module
use settings::load_settings;
use updater::{run_auto_updater, AutoUpdateResult};
use vpn::split_tunnel::SplitTunnelDriver;

use eframe::NativeOptions;
use log::{error, info, warn};
use std::sync::{Arc, Mutex};
use std::time::Duration;
use std::panic;
use tokio::runtime::Runtime;
use windows::core::PCSTR;
use windows::Win32::Foundation::{HANDLE, CloseHandle, GetLastError, ERROR_ALREADY_EXISTS};
use windows::Win32::System::Threading::CreateMutexA;

// Note: OAuth callback is now handled via localhost HTTP server (auth::oauth_server)
// instead of deep links. This eliminates the second-instance problem.

/// Single-instance mutex name
const SINGLE_INSTANCE_MUTEX: &str = "SwiftTunnel_SingleInstance_Mutex_v1";

/// RAII wrapper for Windows mutex handle
struct SingleInstanceGuard {
    _handle: HANDLE,
}

impl Drop for SingleInstanceGuard {
    fn drop(&mut self) {
        // Handle will be released when dropped, mutex is released on process exit
    }
}

/// Try to acquire single-instance mutex
/// Returns Some(guard) if we're the first instance, None if another instance is running
fn try_acquire_single_instance() -> Option<SingleInstanceGuard> {
    unsafe {
        let mutex_name = std::ffi::CString::new(SINGLE_INSTANCE_MUTEX).unwrap();
        let handle = CreateMutexA(
            None,           // Default security attributes
            true,           // Initially owned
            PCSTR(mutex_name.as_ptr() as *const u8),
        );

        match handle {
            Ok(h) => {
                let error = GetLastError();
                if error == ERROR_ALREADY_EXISTS {
                    // Another instance is already running
                    let _ = CloseHandle(h);
                    None
                } else {
                    // We're the first instance
                    Some(SingleInstanceGuard { _handle: h })
                }
            }
            Err(_) => {
                // Failed to create mutex - assume we can run
                warn!("Failed to create single-instance mutex, continuing anyway");
                None
            }
        }
    }
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

    // Single-instance check - prevent multiple app instances (and multiple tray icons)
    // Note: OAuth is now handled via localhost HTTP server, so we don't need to handle
    // second instances for OAuth callbacks anymore.
    let _instance_guard = match try_acquire_single_instance() {
        Some(guard) => {
            info!("Single-instance lock acquired");
            guard
        }
        None => {
            info!("Another instance of SwiftTunnel is already running. Exiting.");
            return Ok(());
        }
    };

    // Run Discord-like auto-updater before main app (splash screen)
    info!("Running auto-updater check...");
    match run_auto_updater() {
        AutoUpdateResult::NoUpdate => {
            info!("No update available, continuing to main app");
        }
        AutoUpdateResult::UpdateInstalled => {
            info!("Update installed, exiting for restart");
            // The installer will restart the app
            return Ok(());
        }
        AutoUpdateResult::Failed(e) => {
            // Don't block app launch on update failure
            warn!("Auto-update failed: {}, continuing to main app", e);
        }
        AutoUpdateResult::Skipped => {
            info!("Auto-update skipped");
        }
    }

    // Create tokio runtime for async operations
    let rt = Runtime::new().expect("Failed to create tokio runtime");

    // Clean up any stale state from previous crash/force kill
    // This ensures split tunnel driver is reset before we start
    SplitTunnelDriver::cleanup_stale_state();

    // Ensure Base Filtering Engine (BFE) service is running
    // BFE is required for WFP operations - auto-start if stopped
    let _ = vpn::ensure_bfe_running();

    // Clean up any stale WFP callouts from previous sessions
    // This MUST happen before any driver.initialize() calls
    vpn::cleanup_stale_wfp_callouts();

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

            // Note: OAuth callback is now handled via localhost HTTP server
            // (auth::oauth_server) and processed in the GUI update loop,
            // not from deep links.

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
