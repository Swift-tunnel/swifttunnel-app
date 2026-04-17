#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

fn main() {
    // Admin is required for ndisapi, WFP, and system optimizations. The
    // Windows application manifest embedded in build.rs declares
    // `requireAdministrator`, so UAC elevation is handled by Windows before
    // main() runs — no runtime self-elevation needed.
    let is_cleanup = std::env::args().any(|a| a == "--cleanup");

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

    swifttunnel_desktop::run();
}
