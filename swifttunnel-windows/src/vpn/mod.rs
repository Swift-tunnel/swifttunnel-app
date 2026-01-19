//! VPN Module for SwiftTunnel
//!
//! This module provides WireGuard-based VPN tunneling with per-process split tunneling.
//!
//! Architecture:
//! - config.rs: VPN configuration types and API fetching
//! - adapter.rs: Wintun virtual network adapter management
//! - tunnel.rs: WireGuard tunnel using BoringTun
//! - wfp.rs: Windows Filtering Platform integration for split tunneling
//! - split_tunnel.rs: Per-process routing via win-split-tunnel driver
//! - connection.rs: Connection state machine and lifecycle management
//! - servers.rs: Server list and latency measurement

pub mod config;
pub mod adapter;
pub mod tunnel;
pub mod wfp;
pub mod split_tunnel;
pub mod connection;
pub mod servers;

pub use config::{fetch_vpn_config, VpnConfigRequest};
pub use adapter::WintunAdapter;
pub use tunnel::WireguardTunnel;
pub use wfp::{WfpEngine, setup_wfp_for_split_tunnel};
pub use split_tunnel::{SplitTunnelDriver, SplitTunnelConfig, GamePreset, get_apps_for_presets, get_apps_for_preset_set};
pub use connection::{VpnConnection, ConnectionState};
pub use servers::{
    DynamicServerList, DynamicServerInfo, DynamicGamingRegion,
    load_server_list, ServerListSource,
};

/// VPN-related errors
#[derive(Debug, thiserror::Error)]
pub enum VpnError {
    #[error("Failed to fetch VPN config: {0}")]
    ConfigFetch(String),

    #[error("Failed to create Wintun adapter: {0}")]
    AdapterCreate(String),

    #[error("Failed to initialize WireGuard tunnel: {0}")]
    TunnelInit(String),

    #[error("WireGuard handshake failed: {0}")]
    HandshakeFailed(String),

    #[error("Split tunnel driver error: {0}")]
    SplitTunnel(String),

    #[error("Connection error: {0}")]
    Connection(String),

    #[error("Network error: {0}")]
    Network(String),

    #[error("Invalid configuration: {0}")]
    InvalidConfig(String),

    #[error("Not authenticated")]
    NotAuthenticated,

    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),
}

pub type VpnResult<T> = Result<T, VpnError>;
