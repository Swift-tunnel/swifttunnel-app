//! VPN Module for SwiftTunnel macOS
//!
//! This module provides WireGuard-based VPN tunneling with process-based split tunneling
//! on macOS. Uses utun interfaces (via tun-rs) instead of Windows Wintun.
//!
//! ## Split Tunnel (macOS)
//!
//! Uses BPF (Berkeley Packet Filter) for packet capture and pf (packet filter) for
//! routing decisions. Routes traffic by process ownership - only specified game
//! processes use the VPN tunnel, everything else bypasses.
//!
//! ## Architecture
//!
//! - config.rs: VPN configuration types and API fetching
//! - adapter.rs: macOS utun adapter management (replaces Wintun)
//! - tunnel.rs: WireGuard tunnel using BoringTun
//! - routes.rs: macOS route management for VPN server
//! - process_tracker.rs: Maps network connections to PIDs via libproc
//! - process_cache.rs: Lock-free RCU-style process cache for <0.1ms lookups
//! - process_watcher.rs: Game process detection via sysinfo + kqueue
//! - packet_interceptor.rs: BPF-based packet capture for connection tracking
//! - firewall.rs: pf firewall rule management for split tunnel routing
//! - split_tunnel.rs: Coordinator that ties all split tunnel components together
//! - connection.rs: Connection state machine and lifecycle management
//! - servers.rs: Server list and latency measurement

pub mod config;
pub mod adapter;
pub mod tunnel;
pub mod process_tracker;
pub mod process_cache;
pub mod process_watcher;
pub mod packet_interceptor;
pub mod firewall;
pub mod split_tunnel;
pub mod routes;
pub mod connection;
pub mod servers;
pub mod error_messages;
pub mod udp_relay;

pub use config::{fetch_vpn_config, update_latency, VpnConfigRequest};
pub use adapter::UtunAdapter;
pub use tunnel::{WireguardTunnel, TunnelStats};
pub use packet_interceptor::{PacketMonitor, ThroughputStats, PacketInfo};
pub use process_cache::{LockFreeProcessCache, ProcessSnapshot};
pub use process_watcher::{ProcessWatcher, ProcessStartEvent};
pub use firewall::{PfFirewall, detect_physical_interface};
pub use udp_relay::UdpRelay;
pub use split_tunnel::{MacSplitTunnel, SplitTunnelConfig, GamePreset, DriverState,
    get_apps_for_presets, get_apps_for_preset_set, get_tunnel_apps_for_presets};
pub use routes::{RouteManager, get_default_gateway, get_internet_interface_ip};
pub use connection::{VpnConnection, ConnectionState};
pub use servers::{
    DynamicServerList, DynamicServerInfo, DynamicGamingRegion,
    load_server_list, ServerListSource,
};
pub use error_messages::{user_friendly_error, short_error};

/// VPN-related errors
#[derive(Debug, thiserror::Error)]
pub enum VpnError {
    #[error("Failed to fetch VPN config: {0}")]
    ConfigFetch(String),

    #[error("Failed to create utun adapter: {0}")]
    AdapterCreate(String),

    #[error("Failed to initialize WireGuard tunnel: {0}")]
    TunnelInit(String),

    #[error("WireGuard handshake failed: {0}")]
    HandshakeFailed(String),

    #[error("Split tunnel error: {0}")]
    SplitTunnel(String),

    #[error("Split tunnel not available - root privileges required")]
    SplitTunnelNotAvailable,

    #[error("Split tunnel setup failed: {0}")]
    SplitTunnelSetupFailed(String),

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
