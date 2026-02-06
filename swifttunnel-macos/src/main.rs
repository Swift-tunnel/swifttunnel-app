// GUI and tray modules are only used by the main binary, not the library
mod gui;
mod tray;

// Use modules from the library crate
use swifttunnel_macos::auth;
use swifttunnel_macos::discord_rpc;
use swifttunnel_macos::geolocation;
use swifttunnel_macos::network_analyzer;
use swifttunnel_macos::network_booster;
use swifttunnel_macos::performance_monitor;
use swifttunnel_macos::roblox_optimizer;
use swifttunnel_macos::settings;
use swifttunnel_macos::structs;
use swifttunnel_macos::system_optimizer;
use swifttunnel_macos::updater;
use swifttunnel_macos::utils;
use swifttunnel_macos::vpn;

// Re-export hidden_command for use in other modules
pub use swifttunnel_macos::hidden_command;

use structs::*;
use system_optimizer::SystemOptimizer;
use roblox_optimizer::RobloxOptimizer;
use performance_monitor::PerformanceMonitor;
use network_booster::NetworkBooster;
use crate::gui::BoosterApp;
use settings::load_settings;
use updater::{run_auto_updater, AutoUpdateResult, cleanup_updates};
use utils::{rotate_log_if_needed, load_pending_connection};
use crate::gui::set_auto_connect_pending;

use eframe::NativeOptions;
use log::{error, info, warn};
use std::sync::{Arc, Mutex, OnceLock};
use std::time::Duration;
use std::panic;
use tokio::runtime::Runtime;

/// Path for single-instance lock file
const LOCK_FILE_PATH: &str = "/tmp/swifttunnel.lock";

/// RAII wrapper for file-based single-instance lock
struct SingleInstanceGuard {
    _fd: i32,
}

impl Drop for SingleInstanceGuard {
    fn drop(&mut self) {
        // Lock is released when file descriptor is closed on process exit
    }
}

/// Result of single-instance check
enum SingleInstanceResult {
    Acquired(SingleInstanceGuard),
    AlreadyRunning,
    CheckFailed,
}

/// Try to acquire single-instance lock using flock
fn try_acquire_single_instance() -> SingleInstanceResult {
    use std::ffi::CString;

    let path = CString::new(LOCK_FILE_PATH).unwrap();

    unsafe {
        // Open or create the lock file
        let fd = libc::open(
            path.as_ptr(),
            libc::O_CREAT | libc::O_RDWR,
            0o600,
        );

        if fd < 0 {
            warn!("Failed to open lock file, continuing anyway");
            return SingleInstanceResult::CheckFailed;
        }

        // Try non-blocking exclusive lock
        let result = libc::flock(fd, libc::LOCK_EX | libc::LOCK_NB);

        if result == 0 {
            // Lock acquired successfully
            SingleInstanceResult::Acquired(SingleInstanceGuard { _fd: fd })
        } else {
            let err = *libc::__error();
            libc::close(fd);

            if err == libc::EWOULDBLOCK {
                SingleInstanceResult::AlreadyRunning
            } else {
                warn!("flock() failed with errno {}, continuing anyway", err);
                SingleInstanceResult::CheckFailed
            }
        }
    }
}

/// Check if running as root (euid == 0)
fn is_root() -> bool {
    unsafe { libc::geteuid() == 0 }
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

        // Log to stderr
        eprintln!("PANIC at {}: {}", location, message);

        // Try to write crash log to ~/Library/Application Support/SwiftTunnel/crash.log
        if let Some(data_dir) = dirs::data_dir() {
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

        // Check if this is a graphics/renderer panic
        let msg_lower = message.to_lowercase();
        let is_graphics_panic = location.contains("glow")
            || location.contains("wgpu")
            || msg_lower.contains("opengl")
            || msg_lower.contains("metal")
            || msg_lower.contains("vulkan");

        if is_graphics_panic {
            eprintln!("Graphics error detected. Please ensure your macOS is up to date.");
            // Try to show a notification
            let _ = mac_notification_sys::send_notification(
                "SwiftTunnel - Graphics Error",
                Some("Error"),
                "SwiftTunnel crashed due to a graphics error. Please update macOS.",
                None,
            );
        }
    }));
}

fn main() -> eframe::Result<()> {
    // Set up panic hook FIRST, before any other initialization
    setup_panic_hook();

    // Create log directory at ~/Library/Application Support/SwiftTunnel/
    let log_dir = dirs::data_dir()
        .map(|d| d.join("SwiftTunnel"))
        .unwrap_or_else(|| std::path::PathBuf::from("."));
    let _ = std::fs::create_dir_all(&log_dir);

    // Set up file logging
    let log_file_path = log_dir.join("swifttunnel.log");

    // Rotate log files if they exceed 1MB
    if let Err(e) = rotate_log_if_needed(&log_file_path) {
        eprintln!("Failed to rotate log: {}", e);
    }
    let update_log_path = log_dir.join("update_install.log");
    if let Err(e) = rotate_log_if_needed(&update_log_path) {
        eprintln!("Failed to rotate update log: {}", e);
    }

    // Initialize logger
    let log_level = std::env::var("RUST_LOG")
        .map(|_| log::LevelFilter::Debug)
        .unwrap_or(log::LevelFilter::Info);

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
        env_logger::Builder::from_default_env()
            .filter_level(log_level)
            .format_timestamp_millis()
            .init();
    }

    info!("========================================");
    info!("Starting SwiftTunnel v{}", env!("CARGO_PKG_VERSION"));
    info!("Log file: {}", log_file_path.display());
    info!("Log level: {:?}", log_level);
    info!("Running as root: {}", is_root());

    // Check for --resume-connect flag (set when relaunching with elevation)
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

    // Single-instance check using file lock
    let _instance_guard: Option<SingleInstanceGuard> = {
        let max_attempts = if is_resume_connect { 10 } else { 1 };
        let mut result = SingleInstanceResult::AlreadyRunning;

        for attempt in 1..=max_attempts {
            result = try_acquire_single_instance();
            match &result {
                SingleInstanceResult::Acquired(_) => {
                    info!("Single-instance lock acquired (attempt {})", attempt);
                    break;
                }
                SingleInstanceResult::CheckFailed => {
                    info!("Single-instance check failed, continuing anyway");
                    break;
                }
                SingleInstanceResult::AlreadyRunning => {
                    if attempt < max_attempts {
                        info!("Waiting for previous instance to exit (attempt {}/{})", attempt, max_attempts);
                        std::thread::sleep(Duration::from_millis(200));
                    }
                }
            }
        }

        match result {
            SingleInstanceResult::Acquired(g) => Some(g),
            SingleInstanceResult::CheckFailed => None,
            SingleInstanceResult::AlreadyRunning => {
                if is_resume_connect {
                    warn!("Could not acquire lock after {} attempts, previous instance may still be running", max_attempts);
                }
                info!("Another instance of SwiftTunnel is already running. Exiting.");
                eprintln!("SwiftTunnel is already running. Check your menu bar for the SwiftTunnel icon.");
                return Ok(());
            }
        }
    };

    // Cleanup old update files
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

    // Run auto-updater check
    info!("Running auto-updater check...");
    match run_auto_updater() {
        AutoUpdateResult::NoUpdate => {
            info!("No update available, continuing to main app");
        }
        AutoUpdateResult::UpdateInstalled => {
            info!("Update installed, exiting for restart");
            return Ok(());
        }
        AutoUpdateResult::Failed(e) => {
            warn!("Auto-update failed: {}, continuing to main app", e);
        }
        AutoUpdateResult::Skipped => {
            info!("Auto-update skipped");
        }
    }

    // Create tokio runtime for async operations
    static RUNTIME: OnceLock<Runtime> = OnceLock::new();
    let rt = RUNTIME.get_or_init(|| Runtime::new().expect("Failed to create tokio runtime"));

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

            drop(state);
        }
    });

    // Load saved settings for window state
    let saved_settings = load_settings();
    let window_state = &saved_settings.window_state;

    // Build viewport
    let app_title = format!("SwiftTunnel v{}", env!("CARGO_PKG_VERSION"));
    let viewport = egui::ViewportBuilder::default()
        .with_title(&app_title)
        .with_min_inner_size([560.0, 650.0])
        .with_inner_size([window_state.width, window_state.height])
        .with_resizable(true)
        .with_decorations(true)
        .with_transparent(false)
        .with_maximized(true);

    // Try wgpu (Metal backend on macOS) first, fall back to glow (OpenGL)
    info!("Trying wgpu (Metal) renderer");
    let result = eframe::run_native(
        "SwiftTunnel",
        NativeOptions {
            viewport: viewport.clone(),
            renderer: eframe::Renderer::Wgpu,
            vsync: true,
            ..Default::default()
        },
        Box::new(move |cc| {
            let mut app = BoosterApp::new(cc);
            app.set_system_info(performance_monitor::get_system_info_lightweight());
            Ok(Box::new(app))
        }),
    );

    if result.is_ok() {
        return Ok(());
    }

    // wgpu failed -- fall back to glow (OpenGL)
    let wgpu_err = result.unwrap_err();
    warn!("wgpu renderer failed: {}. Falling back to glow (OpenGL)", wgpu_err);

    let result = eframe::run_native(
        "SwiftTunnel",
        NativeOptions {
            viewport,
            renderer: eframe::Renderer::Glow,
            vsync: true,
            ..Default::default()
        },
        Box::new(move |cc| {
            let mut app = BoosterApp::new(cc);
            app.set_system_info(performance_monitor::get_system_info_lightweight());
            Ok(Box::new(app))
        }),
    );

    match result {
        Ok(()) => Ok(()),
        Err(e) => {
            error!("Both renderers failed. wgpu: {}, glow: {}", wgpu_err, e);
            eprintln!(
                "SwiftTunnel cannot start - no compatible graphics found.\n\
                Please ensure macOS is up to date.\n\
                wgpu error: {}\nglow error: {}",
                wgpu_err, e
            );
            Err(e)
        }
    }
}
