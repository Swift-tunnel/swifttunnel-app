//! SwiftTunnel FPS Booster Library
//!
//! This library module exposes the core functionality for use by
//! test binaries and the CLI testbench.

pub mod auth;
pub mod geolocation;
pub mod network_analyzer;
pub mod network_booster;
pub mod performance_monitor;
pub mod roblox_optimizer;
pub mod settings;
pub mod structs;
pub mod system_optimizer;
pub mod updater;
pub mod utils;
pub mod vpn;

// Re-export commonly used items
pub use utils::hidden_command;
pub use utils::is_administrator;
pub use utils::with_retry;
pub use utils::rotate_log_if_needed;
