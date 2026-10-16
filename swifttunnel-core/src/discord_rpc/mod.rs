//! Discord Rich Presence integration
//!
//! Shows VPN connection status and game activity in Discord.
//! Enabled by default, can be disabled in Settings.

mod mailbox;
mod manager;
mod state;

pub use manager::DiscordManager;
pub use state::{DiscordActivity, DiscordState, region_display_label};
