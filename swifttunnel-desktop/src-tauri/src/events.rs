use serde::Serialize;

// Event name constants
pub const VPN_STATE_CHANGED: &str = "vpn-state-changed";
pub const AUTH_STATE_CHANGED: &str = "auth-state-changed";
pub const SERVER_LIST_UPDATED: &str = "server-list-updated";
pub const THROUGHPUT_UPDATE: &str = "throughput-update";
pub const PERFORMANCE_METRICS_UPDATE: &str = "performance-metrics-update";
pub const RAM_CLEAN_PROGRESS: &str = "ram-clean-progress";
pub const COUNTRY_BAN_BYPASS_UNAVAILABLE: &str = "country-ban-bypass-unavailable";
pub const ROBLOX_GAME_JOINED: &str = "roblox-game-joined";
/// Fired once the startup network self-heal (stale-state recovery) has finished,
/// so the UI can drop its "preparing your connection" screen.
pub const STARTUP_RECOVERY_COMPLETE: &str = "startup-recovery-complete";

/// Emitted when Roblox joins a game server (parsed from the Roblox log). Drives
/// the optional auto RAM clean + in-game overlay, and game-aware UI.
#[derive(Clone, Serialize)]
pub struct RobloxGameJoinedEvent {
    pub ip: String,
}

/// VPN state change event payload
#[derive(Clone, Serialize)]
pub struct VpnStateEvent {
    pub state: String,
    pub region: Option<String>,
    pub server_endpoint: Option<String>,
    pub assigned_ip: Option<String>,
    pub error: Option<String>,
}

/// Auth state change event payload
#[derive(Clone, Serialize)]
pub struct AuthStateEvent {
    pub state: String,
    pub email: Option<String>,
    pub user_id: Option<String>,
    pub is_tester: bool,
    pub is_banned: bool,
    pub banned_reason: Option<String>,
    pub banned_at: Option<String>,
}

/// Throughput stats event payload
#[derive(Clone, Serialize)]
pub struct ThroughputEvent {
    pub bytes_up: u64,
    pub bytes_down: u64,
    pub packets_tunneled: u64,
    pub packets_bypassed: u64,
}

/// Performance metrics event payload
#[derive(Clone, Serialize)]
pub struct PerformanceMetricsEvent {
    pub cpu_usage: f32,
    pub ram_usage: f64,
    pub ram_total: f64,
    pub fps: f32,
    pub roblox_running: bool,
}

/// RAM cleaner progress event payload
#[derive(Clone, Serialize)]
pub struct RamCleanProgressEvent {
    pub stage: String,
    pub total_mb: u64,
    pub used_mb: u64,
    pub available_mb: u64,
    pub load_pct: u8,
    pub standby_mb: Option<u64>,
    pub modified_mb: Option<u64>,
    pub trimmed_count: u32,
    pub current_process: Option<String>,
    pub warning: Option<String>,
}
