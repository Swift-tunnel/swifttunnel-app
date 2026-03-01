#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

fn main() {
    let is_cleanup = std::env::args().any(|a| a == "--cleanup");

    // Admin is required for core functionality (ndisapi, WFP, system optimizations).
    // Self-elevate via UAC prompt before doing anything else.
    // --cleanup also needs admin for registry/hosts/firewall modifications.
    #[cfg(windows)]
    {
        if !swifttunnel_core::is_administrator() {
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
    // Used by the NSIS uninstaller to clean up before removing files.
    // Runs after elevation to ensure registry/hosts/firewall access.
    if is_cleanup {
        swifttunnel_core::network_booster::cleanup_all_system_state();
        std::process::exit(0);
    }

    swifttunnel_desktop::run();
}
