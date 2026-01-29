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
#[serde(default)]
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
    /// Dynamic render optimization: reduces render resolution for improved FPS on low-end hardware
    #[serde(default)]
    pub dynamic_render_optimization: DynamicRenderMode,
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
            dynamic_render_optimization: DynamicRenderMode::Off, // Disabled by default, user opt-in
        }
    }
}

/// Dynamic render optimization modes
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
pub enum DynamicRenderMode {
    #[default]
    Off,
    Low,    // Value: 3 - Least aggressive, minimal visual impact
    Medium, // Value: 2 - Balanced performance/quality
    High,   // Value: 1 - Most aggressive, maximum FPS gain
}

impl DynamicRenderMode {
    /// Get the render value for this mode (lower = more aggressive optimization)
    pub fn render_value(&self) -> Option<u32> {
        match self {
            DynamicRenderMode::Off => None,
            DynamicRenderMode::Low => Some(3),
            DynamicRenderMode::Medium => Some(2),
            DynamicRenderMode::High => Some(1),
        }
    }

    /// Check if optimization is enabled
    pub fn is_enabled(&self) -> bool {
        !matches!(self, DynamicRenderMode::Off)
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

impl GraphicsQuality {
    /// Convert graphics quality to integer level (1-10, 0 for auto/manual)
    pub fn to_level(&self) -> i32 {
        match self {
            GraphicsQuality::Automatic => 0,
            GraphicsQuality::Manual => 0,
            GraphicsQuality::Level1 => 1,
            GraphicsQuality::Level2 => 2,
            GraphicsQuality::Level3 => 3,
            GraphicsQuality::Level4 => 4,
            GraphicsQuality::Level5 => 5,
            GraphicsQuality::Level6 => 6,
            GraphicsQuality::Level7 => 7,
            GraphicsQuality::Level8 => 8,
            GraphicsQuality::Level9 => 9,
            GraphicsQuality::Level10 => 10,
        }
    }

    /// Create graphics quality from integer level (1-10)
    pub fn from_level(level: i32) -> Self {
        match level {
            1 => GraphicsQuality::Level1,
            2 => GraphicsQuality::Level2,
            3 => GraphicsQuality::Level3,
            4 => GraphicsQuality::Level4,
            5 => GraphicsQuality::Level5,
            6 => GraphicsQuality::Level6,
            7 => GraphicsQuality::Level7,
            8 => GraphicsQuality::Level8,
            9 => GraphicsQuality::Level9,
            10 => GraphicsQuality::Level10,
            _ => GraphicsQuality::Level5, // Default to 5 for invalid values
        }
    }
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
    /// Gaming QoS - Marks game packets with DSCP EF (46) for router prioritization
    #[serde(default = "default_true")]
    pub gaming_qos: bool,
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
            gaming_qos: true, // Enabled by default
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

// ═══════════════════════════════════════════════════════════════════════════════
//  BOOST INFO - Detailed explanations for each optimization toggle
// ═══════════════════════════════════════════════════════════════════════════════

/// Detailed information about a boost/optimization setting
#[derive(Debug, Clone)]
pub struct BoostInfo {
    pub id: &'static str,
    pub title: &'static str,
    pub short_desc: &'static str,
    pub long_desc: &'static str,
    pub impact: &'static str,
    pub risk_level: RiskLevel,
    pub requires_admin: bool,
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum RiskLevel {
    Safe,
    LowRisk,
    MediumRisk,
}

impl RiskLevel {
    pub fn label(&self) -> &'static str {
        match self {
            RiskLevel::Safe => "Safe",
            RiskLevel::LowRisk => "Low Risk",
            RiskLevel::MediumRisk => "Medium Risk",
        }
    }
}

/// All boost info constants
pub mod boost_info {
    use super::{BoostInfo, RiskLevel};

    // System Boosts (Tier 1)
    pub const HIGH_PRIORITY: BoostInfo = BoostInfo {
        id: "high_priority",
        title: "High Priority Mode",
        short_desc: "Boosts game process priority",
        long_desc: "Sets Roblox process priority to 'High' in Windows Task Manager. This tells the CPU scheduler to give Roblox more processing time over background applications. Reverts automatically when Roblox closes.",
        impact: "+5-15 FPS in CPU-bound scenarios",
        risk_level: RiskLevel::Safe,
        requires_admin: false,
    };

    pub const TIMER_RESOLUTION: BoostInfo = BoostInfo {
        id: "timer_resolution",
        title: "1ms Timer Resolution",
        short_desc: "Smoother frame pacing",
        long_desc: "Increases Windows system timer precision from ~15.6ms to 1ms. This allows more precise frame timing and reduces micro-stuttering. Automatically restored when SwiftTunnel closes.",
        impact: "Smoother frame delivery, reduced stutter",
        risk_level: RiskLevel::Safe,
        requires_admin: false,
    };

    pub const MMCSS: BoostInfo = BoostInfo {
        id: "mmcss",
        title: "MMCSS Gaming Profile",
        short_desc: "Better thread scheduling",
        long_desc: "Enables Windows Multimedia Class Scheduler Service for gaming. This prioritizes game threads over background tasks for more consistent CPU time allocation. Built into Windows, fully reversible.",
        impact: "More stable frame times",
        risk_level: RiskLevel::Safe,
        requires_admin: false,
    };

    pub const GAME_MODE: BoostInfo = BoostInfo {
        id: "game_mode",
        title: "Windows Game Mode",
        short_desc: "System resource prioritization",
        long_desc: "Enables Windows built-in Game Mode which reduces background activity, pauses Windows Update, and prioritizes game processes. This is a standard Windows feature that can be toggled on/off anytime.",
        impact: "More consistent performance",
        risk_level: RiskLevel::Safe,
        requires_admin: false,
    };

    // Network Boosts (Tier 1)
    pub const DISABLE_NAGLE: BoostInfo = BoostInfo {
        id: "disable_nagle",
        title: "Disable Nagle's Algorithm",
        short_desc: "Faster packet delivery (-5-15ms)",
        long_desc: "Nagle's algorithm batches small packets together to reduce network overhead. Disabling it sends packets immediately, reducing latency for real-time games. This is a registry tweak that's easily reversible.",
        impact: "-5-15ms latency reduction",
        risk_level: RiskLevel::Safe,
        requires_admin: false,
    };

    pub const NETWORK_THROTTLING: BoostInfo = BoostInfo {
        id: "network_throttling",
        title: "Disable Network Throttling",
        short_desc: "Full bandwidth for games",
        long_desc: "Windows throttles network throughput for multimedia applications by default. Disabling this allows games to use full network bandwidth without artificial limits. Registry change, easily reversible.",
        impact: "Reduced network latency spikes",
        risk_level: RiskLevel::Safe,
        requires_admin: false,
    };

    pub const OPTIMIZE_MTU: BoostInfo = BoostInfo {
        id: "optimize_mtu",
        title: "Optimize MTU",
        short_desc: "Find & apply best packet size",
        long_desc: "Automatically discovers and sets the optimal Maximum Transmission Unit (MTU) for your network. Properly sized packets reduce fragmentation and can improve throughput. Requires admin to modify network settings.",
        impact: "Reduced packet fragmentation",
        risk_level: RiskLevel::LowRisk,
        requires_admin: true,
    };

    pub const GAMING_QOS: BoostInfo = BoostInfo {
        id: "gaming_qos",
        title: "Gaming QoS",
        short_desc: "Router traffic prioritization",
        long_desc: "Marks Roblox packets with DSCP EF (Expedited Forwarding) priority. If your router supports QoS, game traffic will be prioritized over downloads, streaming, and other network activity. Safe, no side effects.",
        impact: "-5-20ms if router honors QoS",
        risk_level: RiskLevel::Safe,
        requires_admin: true,
    };

    // Roblox Boosts
    pub const DYNAMIC_RENDER: BoostInfo = BoostInfo {
        id: "dynamic_render",
        title: "Dynamic Render Optimization",
        short_desc: "Adaptive render resolution",
        long_desc: "Dynamically adjusts render resolution based on performance needs. Choose Low for minimal impact, Medium for balanced performance, or High for maximum FPS gain. Higher settings reduce visual quality but significantly improve frame rates.",
        impact: "Low: +5-10% FPS | Medium: +10-20% FPS | High: +20-30% FPS",
        risk_level: RiskLevel::Safe,
        requires_admin: false,
    };

    /// Get all system boost infos
    pub fn system_boosts() -> [&'static BoostInfo; 4] {
        [&HIGH_PRIORITY, &TIMER_RESOLUTION, &MMCSS, &GAME_MODE]
    }

    /// Get all network boost infos
    pub fn network_boosts() -> [&'static BoostInfo; 4] {
        [&DISABLE_NAGLE, &NETWORK_THROTTLING, &OPTIMIZE_MTU, &GAMING_QOS]
    }

    /// Get all Roblox boost infos
    pub fn roblox_boosts() -> [&'static BoostInfo; 1] {
        [&DYNAMIC_RENDER]
    }
}

/// Profile preset information for tooltips
#[derive(Debug, Clone)]
pub struct ProfileInfo {
    pub name: &'static str,
    pub description: &'static str,
    pub settings_summary: &'static str,
    pub best_for: &'static str,
    pub graphics_level: &'static str,
    pub fps_target: &'static str,
}

pub mod profile_info {
    use super::ProfileInfo;

    pub const PERFORMANCE: ProfileInfo = ProfileInfo {
        name: "Performance",
        description: "Maximum FPS with minimal visual quality",
        settings_summary: "• All system boosts enabled\n• All network boosts enabled\n• Lowest graphics settings\n• Max FPS unlocked",
        best_for: "Low-end PCs, competitive play",
        graphics_level: "Level 1-3",
        fps_target: "Uncapped",
    };

    pub const BALANCED: ProfileInfo = ProfileInfo {
        name: "Balanced",
        description: "Good FPS with decent visual quality",
        settings_summary: "• Core system boosts enabled\n• Network boosts enabled\n• Medium graphics settings\n• 144 FPS target",
        best_for: "Most users, mid-range PCs",
        graphics_level: "Level 5-7",
        fps_target: "144 FPS",
    };

    pub const QUALITY: ProfileInfo = ProfileInfo {
        name: "Quality",
        description: "Best visuals with stable performance",
        settings_summary: "• Essential boosts only\n• Network boosts enabled\n• High graphics settings\n• 60 FPS target",
        best_for: "High-end PCs, immersive play",
        graphics_level: "Level 8-10",
        fps_target: "60 FPS",
    };
}

/// Tier explanation for tooltips
pub mod tier_info {
    pub const TIER_1_TITLE: &str = "TIER 1 - Safe Optimizations";
    pub const TIER_1_DESC: &str = "These optimizations have no side effects and are fully reversible. They use standard Windows APIs and registry settings that are commonly used by gaming software. All changes revert when SwiftTunnel closes or when you disable the boost.";
}
