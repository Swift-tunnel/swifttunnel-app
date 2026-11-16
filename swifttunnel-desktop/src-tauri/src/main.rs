#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

#[cfg(windows)]
fn append_driver_install_log(message: &str) {
    use swifttunnel_installer_cache::{CacheNote, InstallerCache};
    // This helper may run as SYSTEM. Reuse the verified cache directory and
    // guarded publication instead of following a pre-created log path.
    if let Err(error) = InstallerCache::open()
        .and_then(|cache| cache.append_note(CacheNote::DriverInstall, message))
    {
        eprintln!("Could not save driver installer diagnostics: {error}");
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

    // A healthy driver needs no installer remediation. Startup owns stale
    // session recovery; an install must not reset a working client's network
    // state merely to discover that the shared driver is already ready.
    cleanup_stale_network_state_for_installer();

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

#[cfg(windows)]
fn cleanup_stale_network_state_for_installer() {
    append_driver_install_log("Running pre-install stale network cleanup.");

    swifttunnel_core::vpn::SplitTunnelDriver::cleanup_stale_state();

    match swifttunnel_core::vpn::SplitTunnelDriver::disable_leftover_winpkfilter_bindings() {
        Ok(disabled) if disabled.is_empty() => {
            append_driver_install_log("No stale WinpkFilter bindings found before install.");
        }
        Ok(disabled) => {
            append_driver_install_log(&format!(
                "Disabled stale WinpkFilter bindings before install: {}",
                disabled.join(", ")
            ));
        }
        Err(e) => {
            append_driver_install_log(&format!(
                "Pre-install WinpkFilter binding cleanup failed: {}",
                e
            ));
        }
    }

    swifttunnel_core::vpn::recover_tso_on_startup();
    swifttunnel_core::vpn::recover_ipv6_on_startup();
    swifttunnel_core::vpn::wfp_block::cleanup_stale();
    swifttunnel_core::roblox_proxy::hosts::recover_stale();
}

#[cfg(windows)]
fn wait_for_relaunch_parent_if_requested() {
    use windows::Win32::Foundation::CloseHandle;
    use windows::Win32::System::Threading::{
        OpenProcess, PROCESS_SYNCHRONIZE, WaitForSingleObject,
    };

    const WAIT_RELAUNCH_ARG: &str = "--wait-relaunch";
    const RELAUNCH_WAIT_MS: u32 = 10_000;

    let mut args = std::env::args_os().skip(1);
    while let Some(arg) = args.next() {
        if arg != WAIT_RELAUNCH_ARG {
            continue;
        }

        let Some(pid_arg) = args.next() else {
            return;
        };
        let Some(pid) = pid_arg.to_str().and_then(|value| value.parse::<u32>().ok()) else {
            return;
        };

        unsafe {
            if let Ok(handle) = OpenProcess(PROCESS_SYNCHRONIZE, false, pid) {
                let _ = WaitForSingleObject(handle, RELAUNCH_WAIT_MS);
                let _ = CloseHandle(handle);
            }
        }
        return;
    }
}

fn main() {
    // Admin is required for ndisapi, WFP, and system optimizations. The
    // Windows application manifest embedded in build.rs declares
    // `requireAdministrator`, so UAC elevation is handled by Windows before
    // main() runs — no runtime self-elevation needed.
    let is_cleanup = std::env::args_os().skip(1).any(|a| a == "--cleanup");
    let is_install_driver = std::env::args_os().skip(1).any(|a| a == "--install-driver");

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

    #[cfg(windows)]
    wait_for_relaunch_parent_if_requested();

    swifttunnel_desktop::run();
}
