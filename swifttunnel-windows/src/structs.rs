use serde::{Deserialize, Serialize};

/// Optimization profile presets
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum OptimizationProfile {
    LowEnd,
    Balanced,
    HighEnd,
    Custom,
}

/// Configuration for the FPS booster
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Config {
    pub profile: OptimizationProfile,
    pub system_optimization: SystemOptimizationConfig,
    pub roblox_settings: RobloxSettingsConfig,
    pub network_settings: NetworkConfig,
    pub auto_start_with_roblox: bool,
    pub show_overlay: bool,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            profile: OptimizationProfile::Balanced,
            system_optimization: SystemOptimizationConfig::default(),
            roblox_settings: RobloxSettingsConfig::default(),
            network_settings: NetworkConfig::default(),
            auto_start_with_roblox: false,
            show_overlay: true,
        }
    }
}

/// System-level optimization settings
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SystemOptimizationConfig {
    pub set_high_priority: bool,
    pub set_cpu_affinity: bool,
    pub cpu_cores: Vec<usize>,
    pub disable_fullscreen_optimization: bool,
    pub clear_standby_memory: bool,
    pub disable_game_bar: bool,
    pub power_plan: PowerPlan,
    // Tier 1 (Safe) Boosts
    #[serde(default = "default_true")]
    pub timer_resolution_1ms: bool,
    #[serde(default = "default_true")]
    pub mmcss_gaming_profile: bool,
    #[serde(default = "default_true")]
    pub game_mode_enabled: bool,
}

fn default_true() -> bool { true }

impl Default for SystemOptimizationConfig {
    fn default() -> Self {
        Self {
            set_high_priority: true,
            set_cpu_affinity: false,
            cpu_cores: vec![],
            disable_fullscreen_optimization: true,
            clear_standby_memory: true,
            disable_game_bar: true,
            power_plan: PowerPlan::HighPerformance,
            // Tier 1 boosts enabled by default
            timer_resolution_1ms: true,
            mmcss_gaming_profile: true,
            game_mode_enabled: true,
        }
    }
}

/// Power plan options
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum PowerPlan {
    Balanced,
    HighPerformance,
    Ultimate,
}

/// Roblox-specific settings
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RobloxSettingsConfig {
    pub graphics_quality: GraphicsQuality,
    pub unlock_fps: bool,
    pub target_fps: u32,
    pub disable_shadows: bool,
    pub reduce_texture_quality: bool,
    pub disable_post_processing: bool,
}

impl Default for RobloxSettingsConfig {
    fn default() -> Self {
        Self {
            graphics_quality: GraphicsQuality::Manual,
            unlock_fps: true,
            target_fps: 144,
            disable_shadows: false,
            reduce_texture_quality: false,
            disable_post_processing: false,
        }
    }
}

/// Graphics quality levels
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum GraphicsQuality {
    Automatic,
    Manual,
    Level1,
    Level2,
    Level3,
    Level4,
    Level5,
    Level6,
    Level7,
    Level8,
    Level9,
    Level10,
}

/// Network optimization settings
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkConfig {
    pub enable_network_boost: bool,
    pub optimize_dns: bool,
    pub prioritize_roblox_traffic: bool,
    pub custom_dns_primary: Option<String>,
    pub custom_dns_secondary: Option<String>,
    // Tier 1 (Safe) Network Boosts
    #[serde(default = "default_true")]
    pub disable_nagle: bool,
    #[serde(default = "default_true")]
    pub disable_network_throttling: bool,
    #[serde(default)]
    pub optimize_mtu: bool,
}

impl Default for NetworkConfig {
    fn default() -> Self {
        Self {
            enable_network_boost: true,
            optimize_dns: true,
            prioritize_roblox_traffic: true,
            custom_dns_primary: Some("1.1.1.1".to_string()), // Cloudflare
            custom_dns_secondary: Some("8.8.8.8".to_string()), // Google
            // Tier 1 network boosts enabled by default
            disable_nagle: true,
            disable_network_throttling: true,
            optimize_mtu: false, // Off by default as it requires admin and takes a few seconds
        }
    }
}

/// Real-time performance metrics
#[derive(Debug, Clone, Default)]
pub struct PerformanceMetrics {
    pub fps: f32,
    pub cpu_usage: f32,
    pub ram_usage: f64, // in MB
    pub ram_total: f64, // in MB
    pub ping: u32,
    pub roblox_running: bool,
    pub process_id: Option<u32>,
}

/// System Restore Point info
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RestorePointInfo {
    pub created_at: String,
    pub description: String,
}

/// Application state
#[derive(Debug)]
pub struct AppState {
    pub config: Config,
    pub metrics: PerformanceMetrics,
    pub optimizations_active: bool,
    pub backup_created: bool,
    pub last_error: Option<String>,
    pub restore_point: Option<RestorePointInfo>,
    pub timer_resolution_active: bool, // Track if 1ms timer is active (needs cleanup)
}

impl Default for AppState {
    fn default() -> Self {
        Self {
            config: Config::default(),
            metrics: PerformanceMetrics::default(),
            optimizations_active: false,
            backup_created: false,
            last_error: None,
            restore_point: None,
            timer_resolution_active: false,
        }
    }
}

/// Result type for operations
pub type Result<T> = anyhow::Result<T>;
