//! Embeds a manifest requiring administrator.
//!
//! Same reason the full app needs it: bringing the tunnel up installs and binds
//! the packet filter driver and edits the routing table, none of which a
//! standard user can do. Requesting elevation up front is better than starting
//! unelevated and failing at connect time.
//!
//! Also declares per-monitor DPI awareness, so the window is not bitmap
//! stretched on a scaled display.

use embed_manifest::manifest::{DpiAwareness, ExecutionLevel};
use embed_manifest::{embed_manifest, new_manifest};

fn main() {
    if std::env::var_os("CARGO_CFG_WINDOWS").is_some() {
        // Debug builds run as the invoking user. Elevation is only needed to
        // install and bind the packet filter driver, and an elevated window
        // cannot be captured or driven by an unelevated tool, which makes the
        // UI impossible to inspect while working on it.
        let level = if std::env::var("PROFILE").as_deref() == Ok("debug") {
            ExecutionLevel::AsInvoker
        } else {
            ExecutionLevel::RequireAdministrator
        };

        embed_manifest(
            new_manifest("SwiftTunnel.Lite")
                .requested_execution_level(level)
                .dpi_awareness(DpiAwareness::PerMonitorV2),
        )
        .expect("failed to embed the Lite manifest");
    }

    // The exe's own icon. WM_SETICON covers the running window, but Explorer,
    // the Start Menu and a pinned taskbar button read the file's icon resource,
    // and without this they all show the generic default.
    if std::env::var_os("CARGO_CFG_WINDOWS").is_some() {
        embed_resource::compile("icon.rc", embed_resource::NONE)
            .manifest_optional()
            .expect("failed to embed the Lite icon");
    }

    println!("cargo:rerun-if-changed=build.rs");
    println!("cargo:rerun-if-changed=icon.rc");
    println!("cargo:rerun-if-changed=resources/icon.ico");
}
