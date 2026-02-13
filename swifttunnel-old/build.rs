use embed_manifest::manifest::{DpiAwareness, ExecutionLevel};
use embed_manifest::{embed_manifest, new_manifest};

fn main() {
    if std::env::var_os("CARGO_CFG_WINDOWS").is_some() {
        let bin_name = std::env::var("CARGO_BIN_NAME").unwrap_or_default();
        let is_driver_installer = bin_name == "driver-installer";

        // Driver installer always requires admin (it installs a kernel driver).
        // Main app: AsInvoker always — Velopack installs per-user, no admin needed.
        // The app auto-elevates via ShellExecuteW "runas" when VPN connect needs admin.
        let execution_level = if is_driver_installer {
            ExecutionLevel::RequireAdministrator
        } else {
            ExecutionLevel::AsInvoker
        };

        let manifest_name = if is_driver_installer {
            "SwiftTunnel.DriverInstaller"
        } else {
            "SwiftTunnel.FPSBooster"
        };

        embed_manifest(
            new_manifest(manifest_name)
                .version(1, 0, 0, 0)
                .requested_execution_level(execution_level)
                .dpi_awareness(DpiAwareness::PerMonitorV2),
        )
        .expect("Failed to embed manifest");

        // Embed icon and version info into executable (shows in Task Manager, Explorer, etc.)
        // Only for the main binary - driver-installer doesn't need an icon
        if !is_driver_installer {
            let mut res = winres::WindowsResource::new();
            res.set_icon("installer/swifttunnel.ico");
            res.set("ProductName", "SwiftTunnel");
            res.set("FileDescription", "SwiftTunnel Game Booster");
            res.set("CompanyName", "SwiftTunnel");
            res.set("OriginalFilename", "swifttunnel-fps-booster.exe");
            res.set("InternalName", "swifttunnel-fps-booster");
            res.set("LegalCopyright", "Copyright © 2024-2026 SwiftTunnel");
            // Set version from Cargo.toml - CRITICAL: ensures Windows Properties shows correct version
            res.set("FileVersion", env!("CARGO_PKG_VERSION"));
            res.set("ProductVersion", env!("CARGO_PKG_VERSION"));
            if let Err(e) = res.compile() {
                eprintln!("Warning: Failed to embed icon: {}", e);
            }
        }
    }
}
