//! Auto-updater module for SwiftTunnel
//!
//! Uses Velopack for installer/updater framework.
//! Falls back gracefully when not installed via Velopack (dev mode).

pub mod types;
pub mod auto_updater;

pub use types::{UpdateState, UpdateSettings};
pub use auto_updater::{run_auto_updater, AutoUpdateResult};

/// Clean up old update files (no-op with Velopack, kept for API compat)
pub async fn cleanup_updates() -> Result<(), String> {
    Ok(())
}
