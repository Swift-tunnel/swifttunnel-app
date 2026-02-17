//! VPN Module for SwiftTunnel
//!
//! This module provides V3 UDP relay tunneling with process-based split tunneling.
//!
//! ## Split Tunnel
//!
//! Uses ndisapi for packet interception at NDIS level. Routes traffic by process
//! ownership - only specified game processes use the VPN tunnel, everything else
//! bypasses. This matches ExitLag's behavior.
//!
//! ## Architecture
//!
//! - config.rs: VPN configuration types and API fetching
//! - routes.rs: Internet interface IP detection
//! - process_tracker.rs: Maps network connections to PIDs via IP Helper APIs
//! - process_cache.rs: Lock-free RCU-style process cache for <0.1ms lookups
//! - parallel_interceptor.rs: Per-CPU parallel packet processing
//! - split_tunnel.rs: Per-process routing coordination
//! - connection.rs: Connection state machine and lifecycle management
//! - servers.rs: Server list and latency measurement

pub mod auto_routing;
pub mod config;
pub mod connection;
pub mod error_messages;
pub mod parallel_interceptor;
pub mod process_cache;
pub mod process_tracker;
pub mod process_watcher;
pub mod routes;
pub mod servers;
pub mod split_tunnel;
pub mod tso_recovery;
pub mod udp_relay;
pub mod wfp_block;

pub use auto_routing::{AutoRouter, AutoRoutingAction, AutoRoutingEvent};
pub use config::{VpnConfigRequest, fetch_vpn_config, update_latency};
pub use connection::{ConnectionState, VpnConnection};
pub use error_messages::{short_error, user_friendly_error};
pub use parallel_interceptor::{ParallelInterceptor, ThroughputStats};
pub use process_cache::{LockFreeProcessCache, ProcessSnapshot};
pub use process_watcher::{ProcessStartEvent, ProcessWatcher};
pub use servers::{
    DynamicGamingRegion, DynamicServerInfo, DynamicServerList, ServerListSource, load_server_list,
};
pub use split_tunnel::{
    GamePreset, SplitTunnelConfig, SplitTunnelDriver, get_apps_for_preset_set,
    get_apps_for_presets, get_tunnel_apps_for_presets,
};
pub use tso_recovery::{emergency_tso_restore, recover_tso_on_startup};
pub use udp_relay::{RelayAuthAckStatus, RelayContext, UdpRelay};

/// VPN-related errors
#[derive(Debug, thiserror::Error)]
pub enum VpnError {
    #[error("Failed to fetch VPN config: {0}")]
    ConfigFetch(String),

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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_vpn_error_display_config_fetch() {
        let err = VpnError::ConfigFetch("timeout".to_string());
        assert_eq!(err.to_string(), "Failed to fetch VPN config: timeout");
    }

    #[test]
    fn test_vpn_error_display_split_tunnel() {
        let err = VpnError::SplitTunnel("driver error".to_string());
        assert_eq!(err.to_string(), "Split tunnel driver error: driver error");
    }

    #[test]
    fn test_vpn_error_display_split_tunnel_not_available() {
        let err = VpnError::SplitTunnelNotAvailable;
        assert_eq!(
            err.to_string(),
            "Split tunnel driver not available - please install Windows Packet Filter driver"
        );
    }

    #[test]
    fn test_vpn_error_display_split_tunnel_setup_failed() {
        let err = VpnError::SplitTunnelSetupFailed("no interface".to_string());
        assert_eq!(err.to_string(), "Split tunnel setup failed: no interface");
    }

    #[test]
    fn test_vpn_error_display_driver_not_open() {
        let err = VpnError::DriverNotOpen;
        assert_eq!(err.to_string(), "Split tunnel driver not open");
    }

    #[test]
    fn test_vpn_error_display_driver_not_initialized() {
        let err = VpnError::DriverNotInitialized;
        assert_eq!(
            err.to_string(),
            "Split tunnel driver not initialized - call initialize() first"
        );
    }

    #[test]
    fn test_vpn_error_display_connection() {
        let err = VpnError::Connection("already connected".to_string());
        assert_eq!(err.to_string(), "Connection error: already connected");
    }

    #[test]
    fn test_vpn_error_display_network() {
        let err = VpnError::Network("socket bind failed".to_string());
        assert_eq!(err.to_string(), "Network error: socket bind failed");
    }

    #[test]
    fn test_vpn_error_display_route() {
        let err = VpnError::Route("add route failed".to_string());
        assert_eq!(err.to_string(), "Route error: add route failed");
    }

    #[test]
    fn test_vpn_error_display_invalid_config() {
        let err = VpnError::InvalidConfig("missing key".to_string());
        assert_eq!(err.to_string(), "Invalid configuration: missing key");
    }

    #[test]
    fn test_vpn_error_display_not_authenticated() {
        let err = VpnError::NotAuthenticated;
        assert_eq!(err.to_string(), "Not authenticated");
    }

    #[test]
    fn test_vpn_error_display_io() {
        let io_err = std::io::Error::new(std::io::ErrorKind::NotFound, "file not found");
        let err = VpnError::Io(io_err);
        assert_eq!(err.to_string(), "IO error: file not found");
    }

    #[test]
    fn test_vpn_error_from_io_error() {
        let io_err = std::io::Error::new(std::io::ErrorKind::PermissionDenied, "access denied");
        let vpn_err: VpnError = io_err.into();
        match vpn_err {
            VpnError::Io(e) => {
                assert_eq!(e.kind(), std::io::ErrorKind::PermissionDenied);
                assert_eq!(e.to_string(), "access denied");
            }
            other => panic!("Expected VpnError::Io, got {:?}", other),
        }
    }
}
