//! Settings persistence module
//!
//! Saves and loads app settings to/from disk

use crate::network_analyzer::NetworkTestResultsCache;
use crate::structs::Config;
use crate::updater::{UpdateChannel, UpdateSettings};
use crate::utils::normalize_guid_ascii_lowercase;
use log::{debug, error, info};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fs;
use std::path::PathBuf;

const SETTINGS_FILE: &str = "settings.json";

const APP_NAME: &str = "SwiftTunnel";
pub const MIN_WINDOW_WIDTH: f32 = 800.0;
pub const MIN_WINDOW_HEIGHT: f32 = 600.0;

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

impl WindowState {
    pub fn sanitize_in_place(&mut self) {
        if !self.width.is_finite() || self.width < MIN_WINDOW_WIDTH {
            self.width = MIN_WINDOW_WIDTH;
        }

        if !self.height.is_finite() || self.height < MIN_WINDOW_HEIGHT {
            self.height = MIN_WINDOW_HEIGHT;
        }

        if self.x.is_some_and(|x| !x.is_finite()) {
            self.x = None;
        }

        if self.y.is_some_and(|y| !y.is_finite()) {
            self.y = None;
        }
    }
}

impl Default for WindowState {
    fn default() -> Self {
        Self {
            x: None, // Let OS center the window
            y: None,
            width: 1020.0,
            height: 660.0,
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
    /// Legacy field from the removed master boost toggle.
    ///
    /// Kept only for backwards-compatible deserialization of older settings files.
    /// Runtime behavior now uses per-boost config and ignores this field.
    #[serde(default, skip_serializing)]
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
    /// Launch app automatically at Windows sign-in
    #[serde(default = "default_run_on_startup")]
    pub run_on_startup: bool,
    /// Reconnect VPN automatically on next launch after an active session
    #[serde(default = "default_auto_reconnect")]
    pub auto_reconnect: bool,
    /// Internal marker: set true after successful connect, cleared on disconnect/logout
    #[serde(default)]
    pub resume_vpn_on_startup: bool,
    /// Last successfully connected region (for "LAST USED" badge)
    #[serde(default)]
    pub last_connected_region: Option<String>,
    /// Expanded boost info panel IDs (user preference to show detailed info)
    #[serde(default)]
    pub expanded_boost_info: Vec<String>,
    /// Selected game presets for split tunneling (stored as strings: "roblox")
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
    /// Preferred physical network adapter GUID to bind split tunneling to.
    ///
    /// When set, SwiftTunnel will prefer this adapter over default-route auto-detection.
    /// Stored as lowercase `xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx`.
    #[serde(default)]
    pub preferred_physical_adapter_guid: Option<String>,
    /// Per-network remembered split-tunnel adapter overrides for Smart Auto.
    ///
    /// Keyed by a stable network signature built from the active route plus UP adapters.
    #[serde(default)]
    pub network_binding_overrides: HashMap<String, String>,
    /// Physical adapter binding strategy for split tunnel interception.
    #[serde(default)]
    pub adapter_binding_mode: AdapterBindingMode,
    /// Game-process performance tuning controls (Windows-only, per target game process).
    ///
    /// All options are opt-in and default OFF.
    #[serde(default)]
    pub game_process_performance: GameProcessPerformanceSettings,

    /// Route Roblox TCP/HTTPS traffic through the relay to bypass ISP blocking.
    ///
    /// When enabled, TCP packets from tunnel apps and browser-owned Roblox
    /// login/API HTTP(S) flows are forwarded through the V3 relay alongside
    /// UDP game traffic. Off by default.
    #[serde(default)]
    pub enable_api_tunneling: bool,
    /// Bypass a FULL country block (whole platform banned, e.g. Egypt).
    ///
    /// Runs the scoped GoodbyeDPI helper for Roblox hostnames AND relays the
    /// Roblox control plane, launch-critical settings hosts, and gameplay UDP —
    /// the censor may block Roblox's IP ranges wholesale, so nothing is
    /// trusted to the direct path. Off by default.
    #[serde(default)]
    pub enable_country_ban: bool,

    /// Throttle background polling while the window is not focused.
    ///
    /// The UI lives in a WebView2 process, and while connected the Connect
    /// tab polls throughput, state and ping several times a second. None of
    /// that is being read once the player alt-tabs into a game, but it keeps
    /// costing IPC round trips and re-renders that compete with the game for
    /// CPU. Users have reported exactly this as SwiftTunnel making the game
    /// stutter, and traced it to the Edge WebView process.
    ///
    /// On by default. Exposed as a setting because anyone watching the graph
    /// on a second monitor genuinely wants the fast rate.
    #[serde(default = "default_idle_when_unfocused")]
    pub idle_when_unfocused: bool,

    /// Draw the live throughput graph on the Connect tab.
    ///
    /// The graph is the most expensive thing in the UI: a canvas redrawn on
    /// a requestAnimationFrame loop, fed by a throughput sample every 500ms.
    /// That is fine while someone is looking at it, and pure cost for anyone
    /// who keeps the window open on a second monitor while playing, where it
    /// competes with the game for GPU and CPU.
    ///
    /// On by default. Turning it off stops both the redraw and the sampling.
    #[serde(default = "default_show_live_graph")]
    pub show_live_graph: bool,

    /// Lifetime milliseconds spent tunnelling.
    ///
    /// Lives here rather than in the webview's localStorage so the full app
    /// and Lite share one number. Each Tauri app gets its own webview data
    /// directory, keyed by bundle identifier, so a browser-side counter would
    /// silently fork into two the moment somebody installed both.
    #[serde(default)]
    pub total_tunneled_ms: u64,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
#[derive(Default)]
pub enum AdapterBindingMode {
    SmartAuto,
    #[default]
    Manual,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Default)]
#[serde(default)]
pub struct GameProcessPerformanceSettings {
    /// Persist a high-performance GPU preference for each target game executable.
    pub high_performance_gpu_binding: bool,
    /// Prefer performance-core CPU sets for target game processes on hybrid CPUs.
    pub prefer_performance_cores: bool,
    /// Exclude logical CPU 0 from target game process scheduling when possible.
    pub unbind_cpu0: bool,
}

fn default_discord_rpc() -> bool {
    true // Enabled by default
}

fn default_auto_routing() -> bool {
    false // Off by default (public option in Connect tab)
}

fn default_show_live_graph() -> bool {
    true
}

fn default_idle_when_unfocused() -> bool {
    true
}

fn default_minimize_to_tray() -> bool {
    true
}

fn default_run_on_startup() -> bool {
    false
}

fn default_auto_reconnect() -> bool {
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
            minimize_to_tray: default_minimize_to_tray(),
            run_on_startup: default_run_on_startup(),
            auto_reconnect: default_auto_reconnect(),
            resume_vpn_on_startup: false,
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
            preferred_physical_adapter_guid: None,
            network_binding_overrides: HashMap::new(),
            adapter_binding_mode: AdapterBindingMode::Manual,
            game_process_performance: GameProcessPerformanceSettings::default(),
            enable_api_tunneling: false,
            enable_country_ban: false,
            idle_when_unfocused: default_idle_when_unfocused(),
            show_live_graph: default_show_live_graph(),
            total_tunneled_ms: 0,
        }
    }
}

impl AppSettings {
    pub fn sanitize_in_place(&mut self) {
        self.window_state.sanitize_in_place();
        self.preferred_physical_adapter_guid = self
            .preferred_physical_adapter_guid
            .as_deref()
            .and_then(normalize_guid_ascii_lowercase);
        self.network_binding_overrides = self
            .network_binding_overrides
            .drain()
            .filter_map(|(signature, guid)| {
                normalize_guid_ascii_lowercase(&guid).map(|normalized| (signature, normalized))
            })
            .collect();
        self.config.network_settings.normalize_legacy_master_boost();
        self.selected_game_presets = default_game_presets();
        // Older releases serialized false as the default even though the app has
        // no user-facing toggle. Keep app-close safe for shared/cafe PCs.
        self.minimize_to_tray = true;
        // Partial Bypass was removed. A saved `enable_partial_country_ban`
        // is ignored as an unknown field, so upgrading users simply lose the
        // mode rather than hitting a parse error. Both normalisation rules
        // that lived here existed only to reconcile it against the other two
        // modes, so they went with it.
    }
}

fn sanitize_settings(mut settings: AppSettings) -> AppSettings {
    settings.sanitize_in_place();
    settings
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
            return sanitize_settings(AppSettings::default());
        }
    };

    if !path.exists() {
        debug!("Settings file does not exist, using defaults");
        return sanitize_settings(AppSettings::default());
    }

    match fs::read_to_string(&path) {
        Ok(content) => match serde_json::from_str(&content) {
            Ok(settings) => {
                info!("Loaded settings from {:?}", path);
                sanitize_settings(settings)
            }
            Err(e) => {
                error!("Failed to parse settings file: {}", e);
                if let Some(backup) = backup_corrupt_settings(&path) {
                    error!("Backed up corrupt settings to {:?}", backup);
                }
                sanitize_settings(AppSettings::default())
            }
        },
        Err(e) => {
            error!("Failed to read settings file: {}", e);
            sanitize_settings(AppSettings::default())
        }
    }
}

/// Rename a corrupt settings file to `settings.json.corrupt-{unix_ms}` so the
/// user can recover their original config and so we don't silently overwrite
/// it on the next save.
fn backup_corrupt_settings(path: &std::path::Path) -> Option<std::path::PathBuf> {
    let stamp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .ok()?
        .as_millis();
    let backup = path.with_file_name(format!(
        "{}.corrupt-{}",
        path.file_name()?.to_string_lossy(),
        stamp
    ));
    fs::rename(path, &backup).ok()?;
    Some(backup)
}

/// Save settings to disk
pub fn save_settings(settings: &AppSettings) -> Result<(), String> {
    let dir = match get_settings_dir() {
        Some(d) => d,
        None => return Err("Could not determine settings directory".to_string()),
    };

    // Create directory if it doesn't exist
    if !dir.exists()
        && let Err(e) = fs::create_dir_all(&dir)
    {
        return Err(format!("Failed to create settings directory: {}", e));
    }

    let path = dir.join(SETTINGS_FILE);

    let mut settings_to_save = settings.clone();
    settings_to_save.sanitize_in_place();

    let json = match serde_json::to_string_pretty(&settings_to_save) {
        Ok(j) => j,
        Err(e) => return Err(format!("Failed to serialize settings: {}", e)),
    };

    // Write-then-rename so a crash/power loss mid-write can never leave a
    // half-written settings.json (which would reset every setting on the next
    // launch). Rename within the same directory is atomic on NTFS.
    let tmp_path = dir.join(format!("{}.tmp", SETTINGS_FILE));
    if let Err(e) = fs::write(&tmp_path, &json) {
        return Err(format!("Failed to write settings file: {}", e));
    }
    match fs::rename(&tmp_path, &path) {
        Ok(_) => {
            info!("Saved settings to {:?}", path);
            Ok(())
        }
        Err(rename_err) => {
            // Rename can fail if another process holds the destination open
            // (AV scanners, backup tools). Fall back to a direct write so the
            // save still lands, and clean up the temp file.
            let fallback = fs::write(&path, &json);
            let _ = fs::remove_file(&tmp_path);
            match fallback {
                Ok(_) => {
                    info!("Saved settings to {:?} (direct write fallback)", path);
                    Ok(())
                }
                Err(e) => Err(format!(
                    "Failed to write settings file: {} (rename failed first: {})",
                    e, rename_err
                )),
            }
        }
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
            settings.minimize_to_tray,
            "Default should hide to tray so X/taskbar close keeps the tunnel alive"
        );
        assert!(!settings.run_on_startup);
        assert!(!settings.auto_reconnect);
        assert!(!settings.resume_vpn_on_startup);
        assert!(settings.preferred_physical_adapter_guid.is_none());
        assert_eq!(settings.adapter_binding_mode, AdapterBindingMode::Manual);
        assert!(
            !settings
                .game_process_performance
                .high_performance_gpu_binding
        );
        assert!(!settings.game_process_performance.prefer_performance_cores);
        assert!(!settings.game_process_performance.unbind_cpu0);
    }

    #[test]
    fn test_settings_roundtrip() {
        let mut settings = AppSettings {
            theme: "light".to_string(),
            optimizations_active: true,
            selected_region: "tokyo".to_string(),
            selected_server: "tokyo-02".to_string(),
            update_channel: UpdateChannel::Live,
            preferred_physical_adapter_guid: Some(
                "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee".to_string(),
            ),
            adapter_binding_mode: AdapterBindingMode::Manual,
            ..Default::default()
        };
        settings
            .game_process_performance
            .high_performance_gpu_binding = true;
        settings.game_process_performance.prefer_performance_cores = true;
        settings.game_process_performance.unbind_cpu0 = true;

        let json = serde_json::to_string(&settings).unwrap();
        let loaded: AppSettings = serde_json::from_str(&json).unwrap();

        assert_eq!(loaded.theme, "light");
        assert!(
            !json.contains("optimizations_active"),
            "legacy master boost field should not be serialized"
        );
        assert!(!loaded.optimizations_active);
        assert_eq!(loaded.selected_region, "tokyo");
        assert_eq!(loaded.selected_server, "tokyo-02");
        assert_eq!(loaded.update_channel, UpdateChannel::Live);
        assert_eq!(
            loaded.preferred_physical_adapter_guid.as_deref(),
            Some("aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee")
        );
        assert_eq!(loaded.adapter_binding_mode, AdapterBindingMode::Manual);
        assert!(loaded.game_process_performance.high_performance_gpu_binding);
        assert!(loaded.game_process_performance.prefer_performance_cores);
        assert!(loaded.game_process_performance.unbind_cpu0);
    }

    #[test]
    fn test_settings_sanitize_normalizes_preferred_physical_adapter_guid() {
        let mut settings = AppSettings {
            preferred_physical_adapter_guid: Some(
                "  {AAAAAAAA-BBBB-CCCC-DDDD-EEEEEEEEEEEE}  ".to_string(),
            ),
            ..Default::default()
        };
        settings.sanitize_in_place();
        assert_eq!(
            settings.preferred_physical_adapter_guid.as_deref(),
            Some("aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee")
        );
    }

    #[test]
    fn test_settings_adapter_binding_mode_defaults_to_manual() {
        let json = r#"{"theme": "dark", "config": {}, "optimizations_active": false}"#;
        let loaded: AppSettings = serde_json::from_str(json).unwrap();
        assert_eq!(loaded.adapter_binding_mode, AdapterBindingMode::Manual);
    }

    #[test]
    fn test_settings_game_process_performance_defaults_disabled() {
        let json = r#"{"theme": "dark", "config": {}, "optimizations_active": false}"#;
        let loaded: AppSettings = serde_json::from_str(json).unwrap();
        assert!(!loaded.game_process_performance.high_performance_gpu_binding);
        assert!(!loaded.game_process_performance.prefer_performance_cores);
        assert!(!loaded.game_process_performance.unbind_cpu0);
    }

    #[test]
    fn test_settings_auto_routing_default() {
        // Settings without auto_routing_enabled should default to false (public option, default OFF)
        let json = r#"{"theme": "dark", "config": {}, "optimizations_active": false}"#;
        let loaded: AppSettings = serde_json::from_str(json).unwrap();
        assert!(!loaded.auto_routing_enabled);
    }

    #[test]
    fn test_settings_sanitize_migrates_legacy_network_boost_master() {
        let mut settings: AppSettings = serde_json::from_str(
            r#"{
              "theme": "dark",
              "config": {
                "network_settings": {
                  "enable_network_boost": true
                }
              }
            }"#,
        )
        .unwrap();

        settings.sanitize_in_place();

        assert!(settings.config.network_settings.enable_network_boost);
        assert!(settings.config.network_settings.disable_nagle);
        assert!(settings.config.network_settings.disable_network_throttling);
        assert!(!settings.config.network_settings.firewall_fix);
    }

    #[test]
    fn test_settings_sanitize_preserves_all_off_network_boosts() {
        let mut settings: AppSettings = serde_json::from_str(
            r#"{
              "theme": "dark",
              "config": {
                "network_settings": {
                  "enable_network_boost": false
                }
              }
            }"#,
        )
        .unwrap();

        settings.sanitize_in_place();

        assert!(!settings.config.network_settings.enable_network_boost);
        assert!(!settings.config.network_settings.disable_nagle);
        assert!(!settings.config.network_settings.disable_network_throttling);
    }

    #[test]
    fn test_settings_minimize_to_tray_default() {
        // Settings without minimize_to_tray should default to true (hide to tray).
        let json = r#"{"theme": "dark", "config": {}, "optimizations_active": false}"#;
        let loaded: AppSettings = serde_json::from_str(json).unwrap();
        assert!(loaded.minimize_to_tray);
    }

    #[test]
    fn test_settings_sanitize_migrates_legacy_minimize_to_tray_false() {
        let mut settings = AppSettings {
            minimize_to_tray: false,
            ..Default::default()
        };

        settings.sanitize_in_place();

        assert!(settings.minimize_to_tray);
    }

    #[test]
    fn test_settings_startup_reconnect_defaults() {
        let json = r#"{"theme": "dark", "config": {}, "optimizations_active": false}"#;
        let loaded: AppSettings = serde_json::from_str(json).unwrap();
        assert!(!loaded.run_on_startup);
        assert!(!loaded.auto_reconnect);
        assert!(!loaded.resume_vpn_on_startup);
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
        let settings = AppSettings {
            whitelisted_regions: vec!["Singapore".to_string(), "US East".to_string()],
            ..Default::default()
        };

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
    fn test_settings_api_tunneling_default() {
        let json = r#"{"theme": "dark", "config": {}, "optimizations_active": false}"#;
        let loaded: AppSettings = serde_json::from_str(json).unwrap();
        assert!(!loaded.enable_api_tunneling);
        assert!(!loaded.enable_country_ban);
    }

    #[test]
    fn test_settings_api_tunneling_roundtrip() {
        let settings = AppSettings {
            enable_api_tunneling: true,
            enable_country_ban: true,
            ..Default::default()
        };
        let json = serde_json::to_string(&settings).unwrap();
        let loaded: AppSettings = serde_json::from_str(&json).unwrap();
        assert!(loaded.enable_api_tunneling);
        assert!(loaded.enable_country_ban);
    }

    #[test]
    fn ignores_a_saved_partial_bypass_flag() {
        // Partial Bypass was removed. Anyone upgrading still has
        // `enable_partial_country_ban` in their settings.json, and the parse
        // must survive it rather than throwing the whole file away.
        let json = r#"{
            "theme": "dark",
            "config": {},
            "optimizations_active": false,
            "enable_country_ban": true,
            "enable_partial_country_ban": true
        }"#;

        let loaded: AppSettings = serde_json::from_str(json).unwrap();

        assert!(loaded.enable_country_ban, "the surviving mode is preserved");
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

    #[test]
    fn test_window_state_sanitize_in_place_clamps_invalid_values() {
        let mut ws = WindowState {
            x: Some(f32::NAN),
            y: Some(f32::INFINITY),
            width: 120.0,
            height: -1.0,
            maximized: false,
        };

        ws.sanitize_in_place();

        assert_eq!(ws.x, None);
        assert_eq!(ws.y, None);
        assert_eq!(ws.width, MIN_WINDOW_WIDTH);
        assert_eq!(ws.height, MIN_WINDOW_HEIGHT);
    }

    #[test]
    fn test_app_settings_sanitize_in_place_updates_window_state() {
        let mut settings = AppSettings::default();
        settings.window_state.width = 1.0;
        settings.window_state.height = 2.0;
        settings.window_state.x = Some(f32::NAN);
        settings.window_state.y = Some(f32::NAN);

        settings.sanitize_in_place();

        assert_eq!(settings.window_state.width, MIN_WINDOW_WIDTH);
        assert_eq!(settings.window_state.height, MIN_WINDOW_HEIGHT);
        assert_eq!(settings.window_state.x, None);
        assert_eq!(settings.window_state.y, None);
    }

    #[test]
    fn test_corrupt_settings_file_is_renamed_with_timestamp() {
        let dir = std::env::temp_dir().join(format!(
            "swifttunnel-settings-test-{}",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        fs::create_dir_all(&dir).unwrap();
        let path = dir.join("settings.json");
        fs::write(&path, "{ this is not valid json").unwrap();

        let backup = backup_corrupt_settings(&path).expect("backup should be created");

        assert!(!path.exists(), "original file should be renamed");
        assert!(backup.exists(), "backup file should exist");
        let backup_name = backup.file_name().unwrap().to_string_lossy().into_owned();
        assert!(
            backup_name.starts_with("settings.json.corrupt-"),
            "unexpected backup name: {}",
            backup_name
        );

        let _ = fs::remove_dir_all(&dir);
    }
}
