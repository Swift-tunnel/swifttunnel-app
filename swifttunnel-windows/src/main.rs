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
use std::sync::{Arc, Mutex, OnceLock};
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

/// Result of single-instance check
enum SingleInstanceResult {
    /// We acquired the lock - we're the only instance
    Acquired(SingleInstanceGuard),
    /// Another instance is already running
    AlreadyRunning,
    /// Failed to check (permissions, etc.) - let the app run anyway
    CheckFailed,
}

/// Try to acquire single-instance mutex
fn try_acquire_single_instance() -> SingleInstanceResult {
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
                    SingleInstanceResult::AlreadyRunning
                } else {
                    // We're the first instance
                    SingleInstanceResult::Acquired(SingleInstanceGuard { _handle: h })
                }
            }
            Err(e) => {
                // Failed to create mutex - let the app run anyway
                // This can happen due to permissions or other system issues
                warn!("Failed to create single-instance mutex: {:?}, continuing anyway", e);
                SingleInstanceResult::CheckFailed
            }
        }
    }
}

/// Detect GPU vendor from registry
fn detect_gpu_vendor() -> Option<(&'static str, &'static str)> {
    use winreg::enums::*;
    use winreg::RegKey;

    // Check display adapter registry keys
    let hklm = RegKey::predef(HKEY_LOCAL_MACHINE);
    let display_key = hklm.open_subkey(
        r"SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}"
    ).ok()?;

    // Check subkeys 0000, 0001, etc for GPU info
    for i in 0..10 {
        let subkey_name = format!("{:04}", i);
        if let Ok(subkey) = display_key.open_subkey(&subkey_name) {
            if let Ok(desc) = subkey.get_value::<String, _>("DriverDesc") {
                let desc_lower = desc.to_lowercase();
                if desc_lower.contains("nvidia") || desc_lower.contains("geforce") {
                    return Some(("NVIDIA", "https://www.nvidia.com/Download/index.aspx"));
                } else if desc_lower.contains("amd") || desc_lower.contains("radeon") {
                    return Some(("AMD", "https://www.amd.com/en/support"));
                } else if desc_lower.contains("intel") {
                    return Some(("Intel", "https://www.intel.com/content/www/us/en/download-center/home.html"));
                }
            }
        }
    }
    None
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

        // Check if this is a graphics/renderer panic and show user-friendly message
        let msg_lower = message.to_lowercase();
        let is_graphics_panic = location.contains("glow")
            || location.contains("glutin")
            || msg_lower.contains("opengl")
            || msg_lower.contains("gl context")
            || msg_lower.contains("egl")
            || msg_lower.contains("wgl")
            || message.contains("0x1F0");  // GL_VENDOR/RENDERER/VERSION constants

        if is_graphics_panic {
            use windows::Win32::UI::WindowsAndMessaging::{MessageBoxW, MB_YESNO, MB_ICONERROR, IDYES};
            use windows::core::PCWSTR;

            // Detect GPU vendor for targeted driver update link
            let gpu_info = detect_gpu_vendor();
            let (vendor_name, driver_url) = gpu_info.unwrap_or(("Unknown", "https://www.google.com/search?q=update+graphics+driver"));

            let title: Vec<u16> = "SwiftTunnel - Graphics Error\0".encode_utf16().collect();
            let msg = format!(
                "SwiftTunnel failed to initialize graphics.\n\n\
                This can happen if:\n\
                - Your graphics drivers are very outdated\n\
                - You're running via Remote Desktop (RDP)\n\
                - Your system doesn't support OpenGL 2.1+\n\n\
                Would you like to open the {} driver download page?\n\n\
                You can also report this issue at swifttunnel.net/support\0",
                vendor_name
            );
            let message_wide: Vec<u16> = msg.encode_utf16().collect();

            let result = unsafe {
                MessageBoxW(
                    None,
                    PCWSTR(message_wide.as_ptr()),
                    PCWSTR(title.as_ptr()),
                    MB_YESNO | MB_ICONERROR,
                )
            };

            // If user clicked Yes, open the driver download page
            if result == IDYES {
                utils::open_url(driver_url);
            }
        }
    }));
}

fn main() -> eframe::Result<()> {
    // Velopack MUST be first - it handles install/uninstall/update hooks
    // and may terminate the process during those lifecycle events
    velopack::VelopackApp::build()
        .on_first_run(|version| {
            // First launch after fresh install via Velopack
            let _ = log::info!("First run after Velopack install: v{}", version);
        })
        .on_restarted(|version| {
            // App restarted after an update was applied
            let _ = log::info!("Restarted after update to v{}", version);
        })
        .on_before_uninstall_fast_callback(|_version| {
            // Cleanup before uninstall (30 second timeout)
            // Remove WinPkFilter driver state and firewall rules
            vpn::split_tunnel::SplitTunnelDriver::cleanup_stale_state();
            // Restore any modified network settings
            vpn::emergency_tso_restore();
        })
        .run();

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

    // Auto-elevate to admin on startup (once) so VPN/driver features work
    // without repeated UAC prompts during the session
    if !utils::is_administrator() {
        info!("Not running as admin, requesting elevation...");
        match utils::relaunch_elevated() {
            Ok(()) => {
                info!("Relaunched elevated, exiting this process");
                return Ok(());
            }
            Err(e) => {
                // User cancelled UAC or elevation failed — continue without admin
                // VPN features will prompt again when needed
                warn!("Elevation failed or cancelled: {}, continuing without admin", e);
            }
        }
    } else {
        info!("Running with administrator privileges");
    }

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
            SingleInstanceResult::CheckFailed => {
                // Mutex check failed - let the app run anyway
                // This prevents the app from being unusable due to permission issues
                None
            }
            SingleInstanceResult::AlreadyRunning => {
                if is_resume_connect {
                    warn!("Could not acquire lock after {} attempts, previous instance may still be running", max_attempts);
                }
                info!("Another instance of SwiftTunnel is already running. Restoring existing window.");

                // Restore the existing window instead of showing a message box
                use windows::Win32::UI::WindowsAndMessaging::{
                    FindWindowW, SetForegroundWindow, ShowWindow, SW_RESTORE, SW_SHOW,
                };
                use windows::core::PCWSTR;

                let app_title: Vec<u16> = format!("SwiftTunnel v{}\0", env!("CARGO_PKG_VERSION"))
                    .encode_utf16()
                    .collect();
                unsafe {
                    if let Ok(hwnd) = FindWindowW(PCWSTR::null(), PCWSTR(app_title.as_ptr())) {
                        if !hwnd.is_invalid() {
                            let _ = ShowWindow(hwnd, SW_RESTORE);
                            let _ = ShowWindow(hwnd, SW_SHOW);
                            let _ = SetForegroundWindow(hwnd);
                        }
                    }
                }

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
    // Stored in OnceLock for 'static lifetime (must outlive run_native call)
    static RUNTIME: OnceLock<Runtime> = OnceLock::new();
    let rt = RUNTIME.get_or_init(|| Runtime::new().expect("Failed to create tokio runtime"));

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
            // When the boost tab isn't visible and no optimizations are applied,
            // slow down polling to reduce CPU usage (5s instead of 1s)
            let active = structs::PERF_MONITOR_ACTIVE.load(std::sync::atomic::Ordering::Relaxed);
            let sleep_secs = if active || optimizations_applied { 1 } else { 5 };
            tokio::time::sleep(Duration::from_secs(sleep_secs)).await;

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
        .with_min_inner_size([560.0, 650.0])  // Minimum size for 3-col game cards + 2-col region grid
        .with_inner_size([window_state.width, window_state.height])
        .with_resizable(true)           // Allow window resizing
        .with_decorations(true)         // Show title bar with min/max/close buttons
        .with_transparent(false)        // Solid window background
        .with_maximized(true);          // FORCE maximized on startup

    // Check if running in RDP session and warn user
    let in_rdp = is_rdp_session();
    if in_rdp {
        warn!("Running in RDP session - graphics may not work. Please run SwiftTunnel directly on your gaming PC.");
    }

    // Launch with glow (OpenGL) renderer for maximum compatibility
    info!("Starting OpenGL renderer");
    let result = eframe::run_native(
        "SwiftTunnel FPS Booster",
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
            error!("OpenGL renderer failed: {}", e);

            use windows::Win32::UI::WindowsAndMessaging::{MessageBoxW, MB_OK, MB_ICONERROR};
            use windows::core::PCWSTR;

            let title: Vec<u16> = "SwiftTunnel - Graphics Error\0".encode_utf16().collect();

            let msg = if in_rdp {
                "SwiftTunnel cannot start in Remote Desktop.\n\n\
                Graphics are not available over RDP.\n\n\
                Please run SwiftTunnel directly on your gaming PC,\n\
                not through Remote Desktop.\0"
            } else {
                "SwiftTunnel could not initialize OpenGL graphics.\n\n\
                Try these steps:\n\
                1. Update your graphics drivers\n\
                2. If in a VM, enable 3D acceleration\n\
                3. Report the issue at swifttunnel.net/support\0"
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

            Err(e)
        }
    }
}
