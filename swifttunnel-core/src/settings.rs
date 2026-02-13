//! Settings persistence module
//!
//! Saves and loads app settings to/from disk

use crate::network_analyzer::NetworkTestResultsCache;
use crate::structs::Config;
use crate::updater::{UpdateChannel, UpdateSettings};
use log::{debug, error, info};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fs;
use std::path::PathBuf;

const SETTINGS_FILE: &str = "settings.json";
const APP_NAME: &str = "SwiftTunnel";

// Routing mode removed - V3 (UDP relay) is the only mode now.
// V1 (process-based WireGuard) and V2 (hybrid WireGuard) have been removed.
// Legacy settings files with routing_mode field are handled via serde(default).

/// Window state for persistence
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WindowState {
    /// Window X position (None = center)
    pub x: Option<f32>,
    /// Window Y position (None = center)
    pub y: Option<f32>,
    /// Window width
    pub width: f32,
    /// Window height
    pub height: f32,
    /// Whether window is maximized
    pub maximized: bool,
}

impl Default for WindowState {
    fn default() -> Self {
        Self {
            x: None, // Let OS center the window
            y: None,
            width: 560.0,  // Good default width for the UI
            height: 750.0, // Good default height
            maximized: false,
        }
    }
}

/// App settings including theme preference
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AppSettings {
    /// Theme preference: "dark" or "light"
    pub theme: String,
    /// App configuration
    pub config: Config,
    /// Whether optimizations were active on last exit
    pub optimizations_active: bool,
    /// Window state (position, size, maximized)
    #[serde(default)]
    pub window_state: WindowState,
    /// Selected gaming region (e.g., "singapore", "mumbai")
    #[serde(default = "default_region")]
    pub selected_region: String,
    /// Selected VPN server within region (auto-selected by best ping)
    #[serde(default = "default_server")]
    pub selected_server: String,
    /// Current tab
    #[serde(default)]
    pub current_tab: String,
    /// Update settings
    #[serde(default)]
    pub update_settings: UpdateSettings,
    /// Selected update channel (Live = pre-release builds, Stable = vetted releases)
    #[serde(default)]
    pub update_channel: UpdateChannel,
    /// Whether to minimize to tray instead of closing
    #[serde(default = "default_minimize_to_tray")]
    pub minimize_to_tray: bool,
    /// Last successfully connected region (for "LAST USED" badge)
    #[serde(default)]
    pub last_connected_region: Option<String>,
    /// Expanded boost info panel IDs (user preference to show detailed info)
    #[serde(default)]
    pub expanded_boost_info: Vec<String>,
    /// Selected game presets for split tunneling (stored as strings: "roblox", "valorant", "fortnite")
    #[serde(default = "default_game_presets")]
    pub selected_game_presets: Vec<String>,
    /// Cached network test results
    #[serde(default)]
    pub network_test_results: NetworkTestResultsCache,
    /// Forced server selection per region (region_id -> server_id)
    /// If a region has an entry, that server will be used instead of auto-selecting best ping
    #[serde(default)]
    pub forced_servers: HashMap<String, String>,
    /// Artificial latency to add to VPN connection (0-100ms)
    /// Used for practice mode to simulate high ping
    #[serde(default)]
    pub artificial_latency_ms: u32,
    /// Enable experimental features (Practice Mode, etc.)
    #[serde(default)]
    pub experimental_mode: bool,
    /// Legacy routing mode field - ignored, V3 is always used.
    /// Kept for backwards-compatible deserialization of old settings files.
    #[serde(default, skip_serializing)]
    pub _routing_mode: serde_json::Value,
    /// Custom relay server override (experimental feature)
    /// Format: "host:port" - leave empty for auto (uses VPN server IP:51821)
    #[serde(default)]
    pub custom_relay_server: String,
    /// Enable Discord Rich Presence (show VPN status in Discord)
    #[serde(default = "default_discord_rpc")]
    pub enable_discord_rpc: bool,
    /// Enable auto-routing: automatically switch relay server when game server region changes
    #[serde(default = "default_auto_routing")]
    pub auto_routing_enabled: bool,
    /// Whitelisted game regions where VPN should be bypassed during auto-routing
    /// Stored as RobloxRegion display names (e.g., "Singapore", "Tokyo", "US East")
    #[serde(default)]
    pub whitelisted_regions: Vec<String>,
}

fn default_discord_rpc() -> bool {
    true // Enabled by default
}

fn default_auto_routing() -> bool {
    false // Off by default (public option in Connect tab)
}

fn default_minimize_to_tray() -> bool {
    false
}

fn default_region() -> String {
    "singapore".to_string()
}

fn default_server() -> String {
    "singapore".to_string()
}

fn default_game_presets() -> Vec<String> {
    vec!["roblox".to_string()] // Default to Roblox selected
}

impl Default for AppSettings {
    fn default() -> Self {
        Self {
            theme: "dark".to_string(),
            config: Config::default(),
            optimizations_active: false,
            window_state: WindowState::default(),
            selected_region: "singapore".to_string(),
            selected_server: "singapore".to_string(),
            current_tab: "connect".to_string(),
            update_settings: UpdateSettings::default(),
            update_channel: UpdateChannel::Stable,
            minimize_to_tray: false,
            last_connected_region: None,
            expanded_boost_info: Vec::new(),
            selected_game_presets: default_game_presets(),
            network_test_results: NetworkTestResultsCache::default(),
            forced_servers: HashMap::new(),
            artificial_latency_ms: 0,
            experimental_mode: false,
            _routing_mode: serde_json::Value::Null,
            custom_relay_server: String::new(),
            enable_discord_rpc: default_discord_rpc(),
            auto_routing_enabled: default_auto_routing(),
            whitelisted_regions: Vec::new(),
        }
    }
}

/// Get the settings directory path
/// Windows: %APPDATA%\SwiftTunnel\
fn get_settings_dir() -> Option<PathBuf> {
    dirs::config_dir().map(|p| p.join(APP_NAME))
}

/// Get the full path to the settings file
fn get_settings_path() -> Option<PathBuf> {
    get_settings_dir().map(|p| p.join(SETTINGS_FILE))
}

/// Load settings from disk
pub fn load_settings() -> AppSettings {
    let path = match get_settings_path() {
        Some(p) => p,
        None => {
            debug!("Could not determine settings path, using defaults");
            return AppSettings::default();
        }
    };

    if !path.exists() {
        debug!("Settings file does not exist, using defaults");
        return AppSettings::default();
    }

    match fs::read_to_string(&path) {
        Ok(content) => match serde_json::from_str(&content) {
            Ok(settings) => {
                info!("Loaded settings from {:?}", path);
                settings
            }
            Err(e) => {
                error!("Failed to parse settings file: {}", e);
                AppSettings::default()
            }
        },
        Err(e) => {
            error!("Failed to read settings file: {}", e);
            AppSettings::default()
        }
    }
}

/// Save settings to disk
pub fn save_settings(settings: &AppSettings) -> Result<(), String> {
    let dir = match get_settings_dir() {
        Some(d) => d,
        None => return Err("Could not determine settings directory".to_string()),
    };

    // Create directory if it doesn't exist
    if !dir.exists() {
        if let Err(e) = fs::create_dir_all(&dir) {
            return Err(format!("Failed to create settings directory: {}", e));
        }
    }

    let path = dir.join(SETTINGS_FILE);

    let json = match serde_json::to_string_pretty(settings) {
        Ok(j) => j,
        Err(e) => return Err(format!("Failed to serialize settings: {}", e)),
    };

    match fs::write(&path, json) {
        Ok(_) => {
            info!("Saved settings to {:?}", path);
            Ok(())
        }
        Err(e) => Err(format!("Failed to write settings file: {}", e)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_settings() {
        let settings = AppSettings::default();
        assert_eq!(settings.theme, "dark");
        assert!(!settings.optimizations_active);
        assert_eq!(settings.selected_region, "singapore");
        assert_eq!(settings.selected_server, "singapore");
        assert_eq!(settings.update_channel, UpdateChannel::Stable);
        assert!(
            !settings.minimize_to_tray,
            "Default should allow closing via X; tray behavior is opt-in"
        );
    }

    #[test]
    fn test_settings_roundtrip() {
        let mut settings = AppSettings::default();
        settings.theme = "light".to_string();
        settings.optimizations_active = true;
        settings.selected_region = "tokyo".to_string();
        settings.selected_server = "tokyo-02".to_string();
        settings.update_channel = UpdateChannel::Live;

        let json = serde_json::to_string(&settings).unwrap();
        let loaded: AppSettings = serde_json::from_str(&json).unwrap();

        assert_eq!(loaded.theme, "light");
        assert!(loaded.optimizations_active);
        assert_eq!(loaded.selected_region, "tokyo");
        assert_eq!(loaded.selected_server, "tokyo-02");
        assert_eq!(loaded.update_channel, UpdateChannel::Live);
    }

    #[test]
    fn test_settings_auto_routing_default() {
        // Settings without auto_routing_enabled should default to false (public option, default OFF)
        let json = r#"{"theme": "dark", "config": {}, "optimizations_active": false}"#;
        let loaded: AppSettings = serde_json::from_str(json).unwrap();
        assert!(!loaded.auto_routing_enabled);
    }

    #[test]
    fn test_settings_minimize_to_tray_default() {
        // Settings without minimize_to_tray should default to false (quit on X).
        let json = r#"{"theme": "dark", "config": {}, "optimizations_active": false}"#;
        let loaded: AppSettings = serde_json::from_str(json).unwrap();
        assert!(!loaded.minimize_to_tray);
    }

    #[test]
    fn test_settings_whitelisted_regions_default() {
        // Settings without whitelisted_regions should default to empty vec
        let json = r#"{"theme": "dark", "config": {}, "optimizations_active": false}"#;
        let loaded: AppSettings = serde_json::from_str(json).unwrap();
        assert!(loaded.whitelisted_regions.is_empty());
    }

    #[test]
    fn test_settings_whitelisted_regions_roundtrip() {
        let mut settings = AppSettings::default();
        settings.whitelisted_regions = vec!["Singapore".to_string(), "US East".to_string()];

        let json = serde_json::to_string(&settings).unwrap();
        let loaded: AppSettings = serde_json::from_str(&json).unwrap();

        assert_eq!(loaded.whitelisted_regions.len(), 2);
        assert!(
            loaded
                .whitelisted_regions
                .contains(&"Singapore".to_string())
        );
        assert!(loaded.whitelisted_regions.contains(&"US East".to_string()));
    }

    #[test]
    fn test_settings_backward_compat() {
        // Test that settings without selected_region still deserialize
        let old_json = r#"{
            "theme": "dark",
            "config": {},
            "optimizations_active": false,
            "window_state": {"width": 350.0, "height": 520.0, "maximized": false},
            "selected_server": "mumbai-02",
            "current_tab": "connect"
        }"#;

        let loaded: AppSettings = serde_json::from_str(old_json).unwrap();
        assert_eq!(loaded.selected_region, "singapore"); // Default value
        assert_eq!(loaded.selected_server, "mumbai-02");
    }
}
