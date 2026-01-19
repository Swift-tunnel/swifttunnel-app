use embed_manifest::{embed_manifest, new_manifest};
use embed_manifest::manifest::{ExecutionLevel, DpiAwareness};

fn main() {
    if std::env::var_os("CARGO_CFG_WINDOWS").is_some() {
        // Use AsInvoker for development - app will request elevation when needed
        // For release builds, change to RequireAdministrator
        let execution_level = if std::env::var("PROFILE").as_deref() == Ok("release") {
            ExecutionLevel::RequireAdministrator
        } else {
            ExecutionLevel::AsInvoker
        };

        embed_manifest(
            new_manifest("SwiftTunnel.FPSBooster")
                .version(1, 0, 0, 0)
                .requested_execution_level(execution_level)
                .dpi_awareness(DpiAwareness::PerMonitorV2)
        )
        .expect("Failed to embed manifest");
    }
}
