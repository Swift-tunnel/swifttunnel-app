// Hide console window in release builds on Windows
#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

// GUI module is only used by the main binary, not the library
mod gui;
mod tray;

// Use modules from the library crate
use swifttunnel_fps_booster::auth;
use swifttunnel_fps_booster::discord_rpc;
use swifttunnel_fps_booster::geolocation;
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
use updater::{run_auto_updater, AutoUpdateResult, cleanup_updates};
use utils::{rotate_log_if_needed, load_pending_connection};
use vpn::split_tunnel::SplitTunnelDriver;
use vpn::{recover_tso_on_startup, emergency_tso_restore};
use crate::gui::set_auto_connect_pending;

use eframe::NativeOptions;
use log::{error, info, warn};
use std::sync::{Arc, Mutex};
use std::time::Duration;
use std::panic;
use tokio::runtime::Runtime;
use windows::core::PCSTR;
use windows::Win32::Foundation::{HANDLE, CloseHandle, GetLastError, ERROR_ALREADY_EXISTS};
use windows::Win32::System::Threading::CreateMutexA;
use windows::Win32::UI::WindowsAndMessaging::{GetSystemMetrics, SM_REMOTESESSION};

// Note: OAuth callback is now handled via localhost HTTP server (auth::oauth_server)
// instead of deep links. This eliminates the second-instance problem.

/// Single-instance mutex name
const SINGLE_INSTANCE_MUTEX: &str = "SwiftTunnel_SingleInstance_Mutex_v1";

/// Check if running in a Remote Desktop (RDP) session
/// Uses GetSystemMetrics(SM_REMOTESESSION) which returns nonzero if in RDP
fn is_rdp_session() -> bool {
    unsafe {
        GetSystemMetrics(SM_REMOTESESSION) != 0
    }
}


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
        // CRITICAL: Restore TSO settings before anything else
        // This prevents users from being stuck with degraded network performance
        emergency_tso_restore();

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

    // Rotate log files if they exceed 1MB
    if let Err(e) = rotate_log_if_needed(&log_file_path) {
        eprintln!("Failed to rotate log: {}", e);
    }
    let update_log_path = log_dir.join("update_install.log");
    if let Err(e) = rotate_log_if_needed(&update_log_path) {
        eprintln!("Failed to rotate update log: {}", e);
    }

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

    // Recover TSO settings if app previously crashed while TSO was disabled
    // This prevents users from being stuck with degraded network performance
    recover_tso_on_startup();

    // Check for --resume-connect flag (set when relaunching with elevation)
    // This is used to continue a VPN connection after UAC elevation
    let args: Vec<String> = std::env::args().collect();
    let is_resume_connect = args.iter().any(|a| a == "--resume-connect");
    if is_resume_connect {
        info!("--resume-connect flag detected, checking for pending connection...");
        if let Some(pending) = load_pending_connection() {
            info!("Found pending connection: region={}, server={}", pending.region, pending.server);
            set_auto_connect_pending(pending);
        } else {
            warn!("--resume-connect flag present but no valid pending connection found");
        }
    }

    // Single-instance check - prevent multiple app instances (and multiple tray icons)
    // Note: OAuth is now handled via localhost HTTP server, so we don't need to handle
    // second instances for OAuth callbacks anymore.
    //
    // IMPORTANT: When --resume-connect is used, the old process may still be exiting.
    // We retry a few times to handle this race condition.
    let _instance_guard = {
        let max_attempts = if is_resume_connect { 10 } else { 1 };
        let mut guard = None;

        for attempt in 1..=max_attempts {
            match try_acquire_single_instance() {
                Some(g) => {
                    info!("Single-instance lock acquired (attempt {})", attempt);
                    guard = Some(g);
                    break;
                }
                None => {
                    if attempt < max_attempts {
                        info!("Waiting for previous instance to exit (attempt {}/{})", attempt, max_attempts);
                        std::thread::sleep(Duration::from_millis(200));
                    }
                }
            }
        }

        match guard {
            Some(g) => g,
            None => {
                if is_resume_connect {
                    warn!("Could not acquire lock after {} attempts, previous instance may still be running", max_attempts);
                }
                info!("Another instance of SwiftTunnel is already running. Exiting.");
                return Ok(());
            }
        }
    };

    // Cleanup old update files from previous sessions
    // Create a quick runtime just for this async cleanup
    {
        let rt = tokio::runtime::Runtime::new().expect("Failed to create cleanup runtime");
        rt.block_on(async {
            if let Err(e) = cleanup_updates().await {
                warn!("Failed to cleanup old updates: {}", e);
            } else {
                info!("Old update files cleaned up");
            }
        });
    }

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
    // Include version in title for easier user support
    let app_title = format!("SwiftTunnel v{}", env!("CARGO_PKG_VERSION"));
    let viewport = egui::ViewportBuilder::default()
        .with_title(&app_title)
        .with_min_inner_size([480.0, 600.0])  // Smaller minimum for flexibility
        .with_inner_size([window_state.width, window_state.height])
        .with_resizable(true)           // Allow window resizing
        .with_decorations(true)         // Show title bar with min/max/close buttons
        .with_transparent(false)        // Solid window background
        .with_maximized(true);          // FORCE maximized on startup

    // Check if running in RDP session and warn user
    let in_rdp = is_rdp_session();
    if in_rdp {
        warn!("Running in RDP session - OpenGL may not work. Please run SwiftTunnel directly on your gaming PC.");
    }

    // Use glow (OpenGL) renderer - requires GPU/OpenGL 2.0+
    info!("Using glow (OpenGL) renderer");
    let options = NativeOptions {
        viewport,
        renderer: eframe::Renderer::Glow,
        vsync: true, // Enable VSync to cap frame rate and reduce GPU usage
        ..Default::default()
    };

    // Try to run the GUI - handle failure gracefully in RDP/VM environments
    let result = eframe::run_native(
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

            // GUI repainting is handled by gui.rs with smart conditional logic:
            // - Fast repaints (60 FPS) during animations/loading
            // - Slow repaints (10 FPS) when connected
            // - No repaints when idle (only on user interaction)
            // This reduces GPU usage from ~36% to ~1-3% when idle.

            Ok(Box::new(app))
        }),
    );

    // Handle GUI startup failure
    match result {
        Ok(()) => Ok(()),
        Err(e) => {
            let error_msg = format!("{}", e);

            error!("GUI startup failed: {}", e);

            // Check if this is a graphics/OpenGL issue
            if error_msg.contains("opengl") || error_msg.contains("OpenGL") ||
               error_msg.contains("adapter") || error_msg.contains("swap") {
                // Show a user-friendly message box
                use windows::Win32::UI::WindowsAndMessaging::{MessageBoxW, MB_OK, MB_ICONERROR};
                use windows::core::PCWSTR;

                let title: Vec<u16> = "SwiftTunnel - Graphics Error\0".encode_utf16().collect();

                let msg = if in_rdp {
                    "SwiftTunnel cannot start in Remote Desktop.\n\n\
                    OpenGL graphics are not available over RDP.\n\n\
                    Please run SwiftTunnel directly on your gaming PC,\n\
                    not through Remote Desktop.\0"
                } else {
                    "SwiftTunnel cannot start - OpenGL 2.0+ required.\n\n\
                    Please ensure your graphics drivers are up to date.\n\n\
                    If you're using a VM, enable 3D acceleration.\0"
                };

                let message: Vec<u16> = msg.encode_utf16().collect();

                unsafe {
                    MessageBoxW(
                        None,
                        PCWSTR(message.as_ptr()),
                        PCWSTR(title.as_ptr()),
                        MB_OK | MB_ICONERROR,
                    );
                }
            }

            Err(e)
        }
    }
}
