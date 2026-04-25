//! Discord activity state types

use std::borrow::Cow;
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
    const UNKNOWN_REGION: &str = "Unknown Region";

    // Server IDs like "us-east-nj" should match their region prefix "us-east"
    match region_id {
        "singapore" => "Singapore",
        "mumbai" => "Mumbai",
        "tokyo" => "Tokyo",
        "sydney" => "Sydney",
        "germany" | "frankfurt" => "Germany",
        "paris" => "Paris",
        "london" => "London",
        "amsterdam" => "Amsterdam",
        "korea" => "Korea",
        "brazil" | "sao-paulo" => "Brazil",
        _ if region_id.starts_with("singapore-") => "Singapore",
        _ if region_id.starts_with("mumbai-") => "Mumbai",
        _ if region_id.starts_with("tokyo-") => "Tokyo",
        _ if region_id.starts_with("sydney-") => "Sydney",
        _ if region_id.starts_with("germany-") => "Germany",
        _ if region_id.starts_with("paris-") => "Paris",
        _ if region_id.starts_with("london-") => "London",
        _ if region_id.starts_with("amsterdam-") => "Amsterdam",
        _ if region_id.starts_with("korea-") => "Korea",
        _ if region_id.starts_with("brazil-") => "Brazil",
        // US regions are multi-segment ("us-east", "us-west", "us-central") and servers append
        // a location suffix ("us-east-nj"). Require a "-" boundary to avoid false positives.
        _ if region_id == "us-east" || region_id.starts_with("us-east-") => "US East",
        _ if region_id == "us-west" || region_id.starts_with("us-west-") => "US West",
        _ if region_id == "us-central" || region_id.starts_with("us-central-") => "US Central",
        _ => UNKNOWN_REGION,
    }
}

fn format_region_token(token: &str) -> String {
    if token.is_empty() {
        return String::new();
    }

    let lower = token.to_ascii_lowercase();
    if lower.chars().all(|c| c.is_ascii_digit()) {
        return lower;
    }

    match lower.as_str() {
        "us" | "eu" | "uk" | "uae" | "na" | "sa" | "ap" | "af" | "latam" | "emea" => {
            lower.to_ascii_uppercase()
        }
        _ => {
            let mut chars = lower.chars();
            let first = chars
                .next()
                .map(|c| c.to_ascii_uppercase())
                .unwrap_or_default();
            format!("{}{}", first, chars.as_str())
        }
    }
}

/// Resolve a Discord region label, preserving existing mappings and falling back
/// to a readable label when the region id is meaningful but not yet mapped.
pub fn region_display_label(region_id: &str) -> Cow<'static, str> {
    let known = region_display_name(region_id);
    if known != "Unknown Region" {
        return Cow::Borrowed(known);
    }

    let trimmed = region_id.trim();
    if trimmed.is_empty() {
        return Cow::Borrowed("Unknown Region");
    }

    let lower = trimmed.to_ascii_lowercase();
    if matches!(
        lower.as_str(),
        "unknown"
            | "unknown-region"
            | "unknown_region"
            | "auto"
            | "automatic"
            | "default"
            | "none"
            | "null"
    ) {
        return Cow::Borrowed("Unknown Region");
    }

    let pretty = trimmed
        .split(|c: char| c == '-' || c == '_' || c.is_whitespace())
        .filter(|part| !part.is_empty())
        .map(format_region_token)
        .filter(|part| !part.is_empty())
        .collect::<Vec<_>>()
        .join(" ");

    if pretty.is_empty() {
        Cow::Borrowed("Unknown Region")
    } else {
        Cow::Owned(pretty)
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
        "london" => "flag_gb",
        "amsterdam" => "flag_nl",
        "korea" => "flag_kr",
        "brazil" | "sao-paulo" => "flag_br",
        _ if region_id.starts_with("singapore-") => "flag_sg",
        _ if region_id.starts_with("mumbai-") => "flag_in",
        _ if region_id.starts_with("tokyo-") => "flag_jp",
        _ if region_id.starts_with("sydney-") => "flag_au",
        _ if region_id.starts_with("germany-") => "flag_de",
        _ if region_id.starts_with("paris-") => "flag_fr",
        _ if region_id.starts_with("london-") => "flag_gb",
        _ if region_id.starts_with("amsterdam-") => "flag_nl",
        _ if region_id.starts_with("korea-") => "flag_kr",
        _ if region_id.starts_with("brazil-") => "flag_br",
        _ if region_id.starts_with("us-") => "flag_us",
        _ => "flag_us",
    }
}

/// Get game icon key for Discord Rich Presence assets
pub fn game_icon_key(game_name: &str) -> &'static str {
    match game_name.to_lowercase().as_str() {
        "roblox" | "robloxplayerbeta" | "robloxplayerbeta.exe" => "game_roblox",
        _ => "game_generic",
    }
}

/// Get game display name for Discord
pub fn game_display_name(game_name: &str) -> &'static str {
    match game_name.to_lowercase().as_str() {
        "roblox" | "robloxplayerbeta" | "robloxplayerbeta.exe" => "Roblox",
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
        assert_eq!(region_display_name("us-east"), "US East");
        assert_eq!(region_display_name("us-east-nj"), "US East");
        assert_eq!(region_display_name("us-west-la"), "US West");
        assert_eq!(region_display_name("us-central-dallas"), "US Central");
        assert_eq!(region_display_name("us-east2"), "Unknown Region"); // no "-" boundary
        assert_eq!(region_display_name("unknown"), "Unknown Region");
    }

    #[test]
    fn test_region_display_label_uses_known_mapping() {
        assert_eq!(region_display_label("us-east-nj"), "US East");
    }

    #[test]
    fn test_region_display_label_formats_unknown_region_slug() {
        assert_eq!(region_display_label("eu-west"), "EU West");
        assert_eq!(region_display_label("na-east-1"), "NA East 1");
    }

    #[test]
    fn test_region_display_label_keeps_unknown_for_non_meaningful_values() {
        assert_eq!(region_display_label("unknown"), "Unknown Region");
        assert_eq!(region_display_label(""), "Unknown Region");
        assert_eq!(region_display_label("auto"), "Unknown Region");
    }

    #[test]
    fn test_game_display_name() {
        assert_eq!(game_display_name("roblox"), "Roblox");
        assert_eq!(game_display_name("RobloxPlayerBeta.exe"), "Roblox");
        assert_eq!(game_display_name("unknown_game"), "Game");
    }
}
