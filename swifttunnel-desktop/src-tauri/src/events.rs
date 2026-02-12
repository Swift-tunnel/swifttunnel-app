use serde::Serialize;

// Event name constants
pub const VPN_STATE_CHANGED: &str = "vpn-state-changed";
pub const AUTH_STATE_CHANGED: &str = "auth-state-changed";
pub const SERVER_LIST_UPDATED: &str = "server-list-updated";
pub const THROUGHPUT_UPDATE: &str = "throughput-update";
pub const PERFORMANCE_METRICS_UPDATE: &str = "performance-metrics-update";

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
