//! Updater-related shared types for SwiftTunnel.
//!
//! The desktop app verifies and installs updates through its native commands.
//! This module only contains the shared
//! update settings/channel types that are persisted in `%APPDATA%\\SwiftTunnel\\settings.json`.

pub mod types;

pub use types::{UpdateChannel, UpdateSettings};
