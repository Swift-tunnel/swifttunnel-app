//! Discord activity state types

use std::time::Instant;

/// Current state for Discord Rich Presence display
#[derive(Debug, Clone)]
pub enum DiscordState {
    /// App is open but VPN is disconnected
    Idle,
    /// VPN is connecting to a region
    Connecting { region: String },
    /// VPN is connected to a region
    Connected {
        region: String,
        /// When the connection was established
        connected_at: Instant,
    },
    /// Playing a game while connected
    PlayingGame {
        game_name: String,
        region: String,
        connected_at: Instant,
    },
}

impl Default for DiscordState {
    fn default() -> Self {
        Self::Idle
    }
}

/// Activity message to send to Discord RPC thread
#[derive(Debug, Clone)]
pub enum DiscordActivity {
    /// Set the current activity
    SetActivity(DiscordState),
    /// Clear presence (user disabled RPC or app closing)
    Clear,
    /// Shutdown the RPC thread
    Shutdown,
}

/// Get region display name for Discord
pub fn region_display_name(region_id: &str) -> &'static str {
    match region_id {
        "singapore" => "Singapore",
        "mumbai" => "Mumbai",
        "tokyo" => "Tokyo",
        "sydney" => "Sydney",
        "germany" | "frankfurt" => "Germany",
        "paris" => "Paris",
        "america" | "us-east" | "us-west" => "America",
        "brazil" | "sao-paulo" => "Brazil",
        _ => "Unknown Region",
    }
}

/// Get region flag emoji for Discord (uses country codes for flag rendering)
pub fn region_flag_key(region_id: &str) -> &'static str {
    match region_id {
        "singapore" => "flag_sg",
        "mumbai" => "flag_in",
        "tokyo" => "flag_jp",
        "sydney" => "flag_au",
        "germany" | "frankfurt" => "flag_de",
        "paris" => "flag_fr",
        "america" | "us-east" | "us-west" => "flag_us",
        "brazil" | "sao-paulo" => "flag_br",
        _ => "flag_us",
    }
}

/// Get game icon key for Discord Rich Presence assets
pub fn game_icon_key(game_name: &str) -> &'static str {
    match game_name.to_lowercase().as_str() {
        "roblox" | "robloxplayerbeta" | "robloxplayerbeta.exe" => "game_roblox",
        "valorant" | "valorant.exe" => "game_valorant",
        "fortnite" | "fortnitelauncherbeinstaller" => "game_fortnite",
        _ => "game_generic",
    }
}

/// Get game display name for Discord
pub fn game_display_name(game_name: &str) -> &'static str {
    match game_name.to_lowercase().as_str() {
        "roblox" | "robloxplayerbeta" | "robloxplayerbeta.exe" => "Roblox",
        "valorant" | "valorant.exe" => "VALORANT",
        "fortnite" | "fortnitelauncherbeinstaller" => "Fortnite",
        _ => "Game",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_region_display_name() {
        assert_eq!(region_display_name("singapore"), "Singapore");
        assert_eq!(region_display_name("mumbai"), "Mumbai");
        assert_eq!(region_display_name("germany"), "Germany");
        assert_eq!(region_display_name("unknown"), "Unknown Region");
    }

    #[test]
    fn test_game_display_name() {
        assert_eq!(game_display_name("roblox"), "Roblox");
        assert_eq!(game_display_name("RobloxPlayerBeta.exe"), "Roblox");
        assert_eq!(game_display_name("valorant"), "VALORANT");
        assert_eq!(game_display_name("unknown_game"), "Game");
    }
}
