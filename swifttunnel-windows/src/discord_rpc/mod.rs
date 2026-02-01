//! Discord Rich Presence integration
//!
//! Shows VPN connection status and game activity in Discord.
//! Enabled by default, can be disabled in Settings.

mod manager;
mod state;

pub use manager::DiscordManager;
pub use state::{DiscordActivity, DiscordState};
