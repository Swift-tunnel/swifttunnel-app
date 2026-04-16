#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

fn main() {
    let is_cleanup = std::env::args().any(|a| a == "--cleanup");

    // Admin is required for core functionality (ndisapi, WFP, system optimizations).
    // Self-elevate via UAC prompt before doing anything else.
    // --cleanup also needs admin for registry/hosts/firewall modifications.
    #[cfg(windows)]
    {
        if is_cleanup && !swifttunnel_core::is_administrator() {
            match swifttunnel_core::relaunch_elevated_with_args_and_wait() {
                Ok(code) => std::process::exit(code),
                Err(e) => {
                    eprintln!("Failed to elevate cleanup: {}", e);
                    std::process::exit(1);
                }
            }
        }

        if !is_cleanup && !swifttunnel_core::is_administrator() {
            match swifttunnel_core::relaunch_elevated_with_args() {
                Ok(_) => std::process::exit(0),
                Err(e) => {
                    eprintln!("Failed to elevate: {}", e);
                    std::process::exit(1);
                }
            }
        }
    }

    // --cleanup: stateless removal of all SwiftTunnel system modifications.
    // Used by the MSI/NSIS uninstaller to clean up before removing files.
    // Runs after elevation to ensure registry/hosts/firewall access.
    if is_cleanup {
        match swifttunnel_core::network_booster::cleanup_all_system_state() {
            Ok(()) => std::process::exit(0),
            Err(e) => {
                eprintln!("Cleanup failed: {}", e);
                std::process::exit(1);
            }
        }
    }

    swifttunnel_desktop::run();
}
