//! Error types for the VPN native library

use thiserror::Error;

#[derive(Debug, Error)]
pub enum VpnError {
    #[error("Failed to create Wintun adapter: {0}")]
    AdapterCreate(String),

    #[error("Failed to initialize WireGuard tunnel: {0}")]
    TunnelInit(String),

    #[error("WireGuard handshake failed: {0}")]
    HandshakeFailed(String),

    #[error("Split tunnel error: {0}")]
    SplitTunnel(String),

    #[error("Route error: {0}")]
    Route(String),

    #[error("Connection error: {0}")]
    Connection(String),

    #[error("Invalid configuration: {0}")]
    InvalidConfig(String),

    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io;

    #[test]
    fn test_display_adapter_create() {
        let err = VpnError::AdapterCreate("no driver".to_string());
        assert_eq!(err.to_string(), "Failed to create Wintun adapter: no driver");
    }

    #[test]
    fn test_display_tunnel_init() {
        let err = VpnError::TunnelInit("timeout".to_string());
        assert_eq!(err.to_string(), "Failed to initialize WireGuard tunnel: timeout");
    }

    #[test]
    fn test_display_handshake_failed() {
        let err = VpnError::HandshakeFailed("key mismatch".to_string());
        assert_eq!(err.to_string(), "WireGuard handshake failed: key mismatch");
    }

    #[test]
    fn test_display_split_tunnel() {
        let err = VpnError::SplitTunnel("not supported".to_string());
        assert_eq!(err.to_string(), "Split tunnel error: not supported");
    }

    #[test]
    fn test_display_route() {
        let err = VpnError::Route("table full".to_string());
        assert_eq!(err.to_string(), "Route error: table full");
    }

    #[test]
    fn test_display_connection() {
        let err = VpnError::Connection("refused".to_string());
        assert_eq!(err.to_string(), "Connection error: refused");
    }

    #[test]
    fn test_display_invalid_config() {
        let err = VpnError::InvalidConfig("missing key".to_string());
        assert_eq!(err.to_string(), "Invalid configuration: missing key");
    }

    #[test]
    fn test_display_io() {
        let io_err = io::Error::new(io::ErrorKind::NotFound, "file not found");
        let err = VpnError::Io(io_err);
        assert_eq!(err.to_string(), "IO error: file not found");
    }

    #[test]
    fn test_from_io_error() {
        let io_err = io::Error::new(io::ErrorKind::PermissionDenied, "access denied");
        let vpn_err: VpnError = io_err.into();
        match vpn_err {
            VpnError::Io(ref e) => assert_eq!(e.kind(), io::ErrorKind::PermissionDenied),
            _ => panic!("Expected VpnError::Io variant"),
        }
    }

    #[test]
    fn test_vpn_error_is_debug() {
        let err = VpnError::Connection("test".to_string());
        let debug_str = format!("{:?}", err);
        assert!(debug_str.contains("Connection"));
    }
}
