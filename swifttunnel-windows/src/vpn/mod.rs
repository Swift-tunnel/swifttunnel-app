//! VPN Module for SwiftTunnel
//!
//! This module provides WireGuard-based VPN tunneling with per-process split tunneling.
//!
//! Architecture:
//! - config.rs: VPN configuration types and API fetching
//! - adapter.rs: Wintun virtual network adapter management
//! - tunnel.rs: WireGuard tunnel using BoringTun
//! - process_tracker.rs: Maps network connections to PIDs via IP Helper APIs
//! - process_cache.rs: Lock-free RCU-style process cache for <0.1ms lookups
//! - packet_interceptor.rs: ndisapi-based packet interception for split tunneling
//! - parallel_interceptor.rs: Per-CPU parallel packet processing (WireGuard-like)
//! - split_tunnel.rs: Per-process routing coordination
//! - routes.rs: Route management for VPN traffic routing
//! - connection.rs: Connection state machine and lifecycle management
//! - servers.rs: Server list and latency measurement

pub mod config;
pub mod adapter;
pub mod tunnel;
pub mod process_tracker;
pub mod process_cache;
pub mod packet_interceptor;
pub mod parallel_interceptor;
pub mod split_tunnel;
pub mod routes;
pub mod connection;
pub mod servers;

pub use config::{fetch_vpn_config, VpnConfigRequest};
pub use adapter::WintunAdapter;
pub use tunnel::{WireguardTunnel, InboundHandler};
pub use packet_interceptor::WireguardContext;
pub use process_cache::{LockFreeProcessCache, ProcessSnapshot};
pub use parallel_interceptor::{ParallelInterceptor, ThroughputStats, VpnEncryptContext};
pub use split_tunnel::{SplitTunnelDriver, SplitTunnelConfig, GamePreset, get_apps_for_presets, get_apps_for_preset_set, get_tunnel_apps_for_presets};
pub use routes::{RouteManager, get_interface_index, get_internet_interface_ip};
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

    #[error("Split tunnel driver not available - please install Windows Packet Filter driver")]
    SplitTunnelNotAvailable,

    #[error("Split tunnel setup failed: {0}")]
    SplitTunnelSetupFailed(String),

    #[error("Split tunnel driver not open")]
    DriverNotOpen,

    #[error("Split tunnel driver not initialized - call initialize() first")]
    DriverNotInitialized,

    #[error("Connection error: {0}")]
    Connection(String),

    #[error("Network error: {0}")]
    Network(String),

    #[error("Route error: {0}")]
    Route(String),

    #[error("Invalid configuration: {0}")]
    InvalidConfig(String),

    #[error("Not authenticated")]
    NotAuthenticated,

    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),
}

pub type VpnResult<T> = Result<T, VpnError>;
