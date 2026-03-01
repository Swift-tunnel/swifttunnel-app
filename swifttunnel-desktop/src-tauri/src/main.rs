#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

fn main() {
    // --cleanup: stateless removal of all SwiftTunnel system modifications.
    // Used by the NSIS uninstaller to clean up before removing files.
    if std::env::args().any(|a| a == "--cleanup") {
        swifttunnel_core::network_booster::cleanup_all_system_state();
        std::process::exit(0);
    }

    // Admin is required for core functionality (ndisapi, WFP, system optimizations).
    // Self-elevate via UAC prompt before doing anything else.
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

    swifttunnel_desktop::run();
}
