//! Auto-updater module for SwiftTunnel
//!
//! Uses Velopack for installer/updater framework.
//! Falls back gracefully when not installed via Velopack (dev mode).

pub mod auto_updater;
pub mod types;

pub use auto_updater::{AutoUpdateResult, run_auto_updater};
pub use types::{UpdateChannel, UpdateSettings, UpdateState};

/// Clean up old update files (no-op with Velopack, kept for API compat)
pub async fn cleanup_updates() -> Result<(), String> {
    Ok(())
}
