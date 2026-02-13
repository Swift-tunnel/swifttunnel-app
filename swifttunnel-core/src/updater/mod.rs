//! Updater-related shared types for SwiftTunnel.
//!
//! The desktop app uses the Tauri updater. This module only contains the shared
//! update settings/channel types that are persisted in `%APPDATA%\\SwiftTunnel\\settings.json`.

pub mod types;

pub use types::{UpdateChannel, UpdateSettings, UpdateState};

/// Clean up old update files (kept for API compatibility; currently a no-op).
pub async fn cleanup_updates() -> Result<(), String> {
    Ok(())
}
