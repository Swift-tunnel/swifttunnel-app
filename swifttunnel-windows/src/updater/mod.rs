//! Auto-updater module for SwiftTunnel
//!
//! Checks for updates from GitHub Releases, downloads MSI installers,
//! verifies SHA256 checksums, and performs silent installation.

pub mod types;
pub mod checker;
pub mod downloader;
mod verifier;
mod installer;
mod auto_updater;
mod marker;

pub use types::{UpdateState, UpdateInfo, UpdateSettings};
pub use checker::UpdateChecker;
pub use downloader::{download_update, download_checksum, cleanup_updates};
pub use verifier::verify_checksum;
pub use installer::install_update;
pub use auto_updater::{run_auto_updater, AutoUpdateResult};
pub use marker::{write_marker, delete_marker, should_skip_update_check};
