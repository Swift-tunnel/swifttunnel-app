#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

#[cfg(windows)]
fn append_driver_install_log(message: &str) {
    use std::io::Write;

    let program_data =
        std::env::var("ProgramData").unwrap_or_else(|_| "C:\\ProgramData".to_string());
    let log_dir = std::path::PathBuf::from(program_data)
        .join("SwiftTunnel")
        .join("logs");
    let _ = std::fs::create_dir_all(&log_dir);
    let log_path = log_dir.join("driver-install.log");

    if let Ok(mut file) = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(log_path)
    {
        let _ = writeln!(file, "{}", message);
    }
}

#[cfg(windows)]
fn install_driver_for_installer() -> Result<(), String> {
    append_driver_install_log("SwiftTunnel driver install helper starting.");

    let initial = swifttunnel_core::vpn::SplitTunnelDriver::health_check();
    append_driver_install_log(&format!(
        "Initial health: status={}, ready={}, message={}",
        initial.status.as_str(),
        initial.ready,
        initial.message
    ));
    if initial.ready {
        append_driver_install_log("Driver already ready; helper exiting.");
        return Ok(());
    }

    let exe_dir = std::env::current_exe()
        .ok()
        .and_then(|p| p.parent().map(|d| d.to_path_buf()));
    let program_files_dir = std::path::PathBuf::from(
        std::env::var("ProgramFiles").unwrap_or_else(|_| "C:\\Program Files".to_string()),
    );
    let force_reinstall =
        initial.recommended_action == swifttunnel_core::vpn::DriverRecommendedAction::Reinstall;

    let result = swifttunnel_core::vpn::SplitTunnelDriver::install_driver_from_bundled_package(
        None,
        exe_dir.as_deref(),
        &program_files_dir,
        force_reinstall,
    );

    match &result {
        Ok(()) => append_driver_install_log("Driver install helper completed successfully."),
        Err(e) => append_driver_install_log(&format!("Driver install helper failed: {}", e)),
    }

    result
}

fn main() {
    // Admin is required for ndisapi, WFP, and system optimizations. The
    // Windows application manifest embedded in build.rs declares
    // `requireAdministrator`, so UAC elevation is handled by Windows before
    // main() runs — no runtime self-elevation needed.
    let is_cleanup = std::env::args().any(|a| a == "--cleanup");
    let is_install_driver = std::env::args().any(|a| a == "--install-driver");

    // --cleanup: stateless removal of all SwiftTunnel system modifications.
    // Used by the MSI/NSIS uninstaller to clean up before removing files.
    if is_cleanup {
        match swifttunnel_core::network_booster::cleanup_all_system_state() {
            Ok(()) => std::process::exit(0),
            Err(e) => {
                eprintln!("Cleanup failed: {}", e);
                std::process::exit(1);
            }
        }
    }

    #[cfg(windows)]
    if is_install_driver {
        match install_driver_for_installer() {
            Ok(()) => std::process::exit(0),
            Err(e) => {
                eprintln!("Driver install failed: {}", e);
                std::process::exit(1);
            }
        }
    }

    #[cfg(not(windows))]
    if is_install_driver {
        std::process::exit(0);
    }

    swifttunnel_desktop::run();
}
