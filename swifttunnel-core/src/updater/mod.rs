//! Auto-updater module for SwiftTunnel
//!
//! Uses Velopack for installer/updater framework when the `velopack-updater` feature is enabled.
//! Falls back gracefully when not installed via Velopack (dev mode).

#[cfg(feature = "velopack-updater")]
pub mod auto_updater;
pub mod types;

#[cfg(feature = "velopack-updater")]
pub use auto_updater::{
    AutoUpdateResult, check_for_updates_background, download_and_apply_update, run_auto_updater,
};
pub use types::{UpdateChannel, UpdateSettings, UpdateState};

#[cfg(not(feature = "velopack-updater"))]
pub use self::no_velopack::*;

/// Stub implementations when velopack is not available
#[cfg(not(feature = "velopack-updater"))]
mod no_velopack {
    use super::types::{UpdateChannel, UpdateState};
    use std::sync::{Arc, Mutex};

    /// Result of the auto-update check
    #[derive(Clone)]
    pub enum AutoUpdateResult {
        NoUpdate,
        UpdateInstalled,
        Failed(String),
        Skipped,
    }

    /// No-op auto-updater when velopack feature is disabled
    pub fn run_auto_updater(_channel: UpdateChannel) -> AutoUpdateResult {
        AutoUpdateResult::Skipped
    }

    /// No-op background check when velopack feature is disabled
    pub fn check_for_updates_background(
        _update_state: Arc<Mutex<UpdateState>>,
        _channel: UpdateChannel,
    ) {
    }

    /// No-op download when velopack feature is disabled
    pub fn download_and_apply_update(
        _update_state: Arc<Mutex<UpdateState>>,
        _version: String,
        _channel: UpdateChannel,
    ) {
    }
}

/// Clean up old update files (no-op with Velopack, kept for API compat)
pub async fn cleanup_updates() -> Result<(), String> {
    Ok(())
}
