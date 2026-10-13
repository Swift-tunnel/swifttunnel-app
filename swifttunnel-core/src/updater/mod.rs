//! Updater-related shared types for SwiftTunnel.
//!
//! The desktop app uses the Tauri updater. This module only contains the shared
//! update settings/channel types that are persisted in `%APPDATA%\\SwiftTunnel\\settings.json`.

pub mod types;

pub use types::{UpdateChannel, UpdateSettings};
