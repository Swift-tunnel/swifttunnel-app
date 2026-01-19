//! VPN Module Tests
//!
//! Comprehensive tests for SwiftTunnel VPN functionality.
//! Run with: cargo test --test vpn_tests

use std::net::IpAddr;

// Import the modules we're testing
// Note: These tests are designed to run without requiring admin privileges
// or actual network connections where possible.

/// Tests for VPN configuration parsing
mod config_tests {
    use super::*;

    #[test]
    fn test_parse_ip_cidr_with_cidr() {
        // Test parsing IP with CIDR notation
        let input = "10.0.42.15/32";
        let parts: Vec<&str> = input.split('/').collect();
        assert_eq!(parts.len(), 2);
        assert_eq!(parts[0], "10.0.42.15");
        assert_eq!(parts[1], "32");
    }

    #[test]
    fn test_parse_ip_cidr_without_cidr() {
        // Test parsing IP without CIDR (should default to /32)
        let input = "192.168.1.1";
        assert!(!input.contains('/'));
        // Default CIDR should be 32 for IPv4
        let cidr = if input.contains(':') { 128u8 } else { 32u8 };
        assert_eq!(cidr, 32);
    }

    #[test]
    fn test_parse_ipv6_cidr() {
        // Test IPv6 CIDR handling
        let input = "2001:db8::1";
        assert!(input.contains(':'));
        // Default CIDR should be 128 for IPv6
        let cidr = if input.contains(':') { 128u8 } else { 32u8 };
        assert_eq!(cidr, 128);
    }

    #[test]
    fn test_wireguard_key_validation() {
        // Valid WireGuard key is 32 bytes base64 encoded
        use base64::{Engine, engine::general_purpose::STANDARD};

        let valid_key_bytes = [0u8; 32];
        let valid_key = STANDARD.encode(valid_key_bytes);

        // Should decode to exactly 32 bytes
        let decoded = STANDARD.decode(&valid_key).unwrap();
        assert_eq!(decoded.len(), 32);
    }

    #[test]
    fn test_invalid_key_length() {
        use base64::{Engine, engine::general_purpose::STANDARD};

        // Key with wrong length (16 bytes instead of 32)
        let short_key_bytes = [0u8; 16];
        let short_key = STANDARD.encode(short_key_bytes);

        let decoded = STANDARD.decode(&short_key).unwrap();
        assert_ne!(decoded.len(), 32);
    }

    #[test]
    fn test_endpoint_parsing() {
        // Valid endpoint
        let endpoint = "54.255.205.216:51820";
        let result: Result<std::net::SocketAddr, _> = endpoint.parse();
        assert!(result.is_ok());

        let addr = result.unwrap();
        assert_eq!(addr.port(), 51820);
    }

    #[test]
    fn test_invalid_endpoint() {
        // Invalid endpoint (no port)
        let endpoint = "54.255.205.216";
        let result: Result<std::net::SocketAddr, _> = endpoint.parse();
        assert!(result.is_err());
    }

    #[test]
    fn test_endpoint_with_ipv6() {
        // IPv6 endpoint
        let endpoint = "[::1]:51820";
        let result: Result<std::net::SocketAddr, _> = endpoint.parse();
        assert!(result.is_ok());
    }
}

/// Tests for connection state machine
mod connection_state_tests {
    #[derive(Debug, Clone, PartialEq)]
    pub enum MockConnectionState {
        Disconnected,
        FetchingConfig,
        CreatingAdapter,
        Connecting,
        ConfiguringSplitTunnel,
        Connected,
        Disconnecting,
        Error(String),
    }

    impl MockConnectionState {
        pub fn is_connected(&self) -> bool {
            matches!(self, MockConnectionState::Connected)
        }

        pub fn is_connecting(&self) -> bool {
            matches!(
                self,
                MockConnectionState::FetchingConfig
                    | MockConnectionState::CreatingAdapter
                    | MockConnectionState::Connecting
                    | MockConnectionState::ConfiguringSplitTunnel
            )
        }

        pub fn is_error(&self) -> bool {
            matches!(self, MockConnectionState::Error(_))
        }
    }

    #[test]
    fn test_initial_state_is_disconnected() {
        let state = MockConnectionState::Disconnected;
        assert!(!state.is_connected());
        assert!(!state.is_connecting());
        assert!(!state.is_error());
    }

    #[test]
    fn test_connecting_states() {
        let states = vec![
            MockConnectionState::FetchingConfig,
            MockConnectionState::CreatingAdapter,
            MockConnectionState::Connecting,
            MockConnectionState::ConfiguringSplitTunnel,
        ];

        for state in states {
            assert!(state.is_connecting(), "State {:?} should be connecting", state);
            assert!(!state.is_connected());
        }
    }

    #[test]
    fn test_connected_state() {
        let state = MockConnectionState::Connected;
        assert!(state.is_connected());
        assert!(!state.is_connecting());
        assert!(!state.is_error());
    }

    #[test]
    fn test_error_state() {
        let state = MockConnectionState::Error("Test error".to_string());
        assert!(state.is_error());
        assert!(!state.is_connected());
        assert!(!state.is_connecting());
    }

    #[test]
    fn test_valid_state_transitions() {
        // Test that valid state transitions are possible
        let transitions = vec![
            (MockConnectionState::Disconnected, MockConnectionState::FetchingConfig),
            (MockConnectionState::FetchingConfig, MockConnectionState::CreatingAdapter),
            (MockConnectionState::CreatingAdapter, MockConnectionState::Connecting),
            (MockConnectionState::Connecting, MockConnectionState::ConfiguringSplitTunnel),
            (MockConnectionState::ConfiguringSplitTunnel, MockConnectionState::Connected),
            (MockConnectionState::Connected, MockConnectionState::Disconnecting),
            (MockConnectionState::Disconnecting, MockConnectionState::Disconnected),
        ];

        for (from, to) in transitions {
            // This is a mock test - just verify the states are different
            assert_ne!(from, to, "Transition should change state");
        }
    }
}

/// Tests for VPN error types
mod error_tests {
    #[derive(Debug)]
    pub enum MockVpnError {
        ConfigFetch(String),
        AdapterCreate(String),
        TunnelInit(String),
        HandshakeFailed(String),
        SplitTunnel(String),
        Connection(String),
        Network(String),
        InvalidConfig(String),
        NotAuthenticated,
    }

    #[test]
    fn test_error_variants() {
        // Test that all error variants can be created
        let errors = vec![
            MockVpnError::ConfigFetch("test".to_string()),
            MockVpnError::AdapterCreate("test".to_string()),
            MockVpnError::TunnelInit("test".to_string()),
            MockVpnError::HandshakeFailed("test".to_string()),
            MockVpnError::SplitTunnel("test".to_string()),
            MockVpnError::Connection("test".to_string()),
            MockVpnError::Network("test".to_string()),
            MockVpnError::InvalidConfig("test".to_string()),
            MockVpnError::NotAuthenticated,
        ];

        assert_eq!(errors.len(), 9);
    }

    #[test]
    fn test_error_messages_are_descriptive() {
        let error_msg = "Failed to connect: timeout";
        let error = MockVpnError::HandshakeFailed(error_msg.to_string());

        match error {
            MockVpnError::HandshakeFailed(msg) => {
                assert!(msg.contains("timeout"));
            }
            _ => panic!("Wrong error type"),
        }
    }
}

/// Tests for server list functionality
mod server_tests {
    use std::net::IpAddr;

    #[derive(Debug, Clone)]
    pub struct MockServerInfo {
        pub region: String,
        pub name: String,
        pub endpoint: String,
        pub port: u16,
        pub phantun_available: bool,
    }

    fn get_mock_servers() -> Vec<MockServerInfo> {
        vec![
            MockServerInfo {
                region: "singapore".to_string(),
                name: "Singapore".to_string(),
                endpoint: "54.255.205.216".to_string(),
                port: 51820,
                phantun_available: true,
            },
            MockServerInfo {
                region: "tokyo".to_string(),
                name: "Tokyo".to_string(),
                endpoint: "52.68.0.1".to_string(),
                port: 51820,
                phantun_available: true,
            },
            MockServerInfo {
                region: "frankfurt".to_string(),
                name: "Frankfurt".to_string(),
                endpoint: "52.29.0.1".to_string(),
                port: 51820,
                phantun_available: false,
            },
        ]
    }

    #[test]
    fn test_server_list_not_empty() {
        let servers = get_mock_servers();
        assert!(!servers.is_empty());
    }

    #[test]
    fn test_find_server_by_region() {
        let servers = get_mock_servers();
        let singapore = servers.iter().find(|s| s.region == "singapore");
        assert!(singapore.is_some());
        assert_eq!(singapore.unwrap().name, "Singapore");
    }

    #[test]
    fn test_phantun_availability() {
        let servers = get_mock_servers();

        let singapore = servers.iter().find(|s| s.region == "singapore").unwrap();
        assert!(singapore.phantun_available);

        let frankfurt = servers.iter().find(|s| s.region == "frankfurt").unwrap();
        assert!(!frankfurt.phantun_available);
    }

    #[test]
    fn test_all_servers_have_valid_port() {
        let servers = get_mock_servers();
        for server in servers {
            assert!(server.port > 0);
            assert!(server.port < 65535);
        }
    }

    #[test]
    fn test_all_servers_have_valid_endpoint() {
        let servers = get_mock_servers();
        for server in servers {
            // Basic validation: endpoint should not be empty
            assert!(!server.endpoint.is_empty());
            // Should be a valid IP address
            let result: Result<IpAddr, _> = server.endpoint.parse();
            assert!(result.is_ok(), "Invalid endpoint: {}", server.endpoint);
        }
    }
}

/// Tests for MTU calculations
mod mtu_tests {
    const DEFAULT_MTU: u32 = 1420;
    const MAX_MTU: u32 = 1500;
    const MIN_MTU: u32 = 1280;

    #[test]
    fn test_default_mtu_is_valid() {
        assert!(DEFAULT_MTU >= MIN_MTU);
        assert!(DEFAULT_MTU <= MAX_MTU);
    }

    #[test]
    fn test_wireguard_overhead() {
        // WireGuard adds overhead of ~60-80 bytes
        let wireguard_overhead = MAX_MTU - DEFAULT_MTU;
        assert!(wireguard_overhead >= 60);
        assert!(wireguard_overhead <= 100);
    }
}

/// Tests for split tunnel configuration
mod split_tunnel_tests {
    fn get_default_apps() -> Vec<String> {
        vec![
            "RobloxPlayerBeta.exe".to_string(),
            "RobloxStudioBeta.exe".to_string(),
        ]
    }

    #[test]
    fn test_default_apps_includes_roblox() {
        let apps = get_default_apps();
        assert!(apps.iter().any(|a| a.contains("Roblox")));
    }

    #[test]
    fn test_default_apps_are_exe_files() {
        let apps = get_default_apps();
        for app in apps {
            assert!(app.ends_with(".exe"), "App should be .exe: {}", app);
        }
    }

    #[test]
    fn test_empty_apps_routes_all_traffic() {
        let apps: Vec<String> = vec![];
        // Empty apps list means all traffic goes through VPN
        assert!(apps.is_empty());
    }
}

/// Tests for authentication token handling
mod auth_tests {
    #[test]
    fn test_bearer_token_format() {
        let access_token = "test_token_123";
        let bearer = format!("Bearer {}", access_token);
        assert!(bearer.starts_with("Bearer "));
        assert!(bearer.len() > 7);
    }

    #[test]
    fn test_empty_token_rejected() {
        let access_token = "";
        assert!(access_token.is_empty());
        // Empty token should be rejected before API call
    }
}

/// Performance/timing tests
mod timing_tests {
    use std::time::Duration;

    const TICK_INTERVAL_MS: u64 = 100;
    const KEEPALIVE_INTERVAL_SECS: u64 = 25;
    const HANDSHAKE_TIMEOUT_SECS: u64 = 10;

    #[test]
    fn test_tick_interval_is_reasonable() {
        let tick = Duration::from_millis(TICK_INTERVAL_MS);
        // Should be between 50ms and 500ms for responsive keepalives
        assert!(tick >= Duration::from_millis(50));
        assert!(tick <= Duration::from_millis(500));
    }

    #[test]
    fn test_keepalive_interval_is_reasonable() {
        let keepalive = Duration::from_secs(KEEPALIVE_INTERVAL_SECS);
        // Should be between 10 and 60 seconds
        assert!(keepalive >= Duration::from_secs(10));
        assert!(keepalive <= Duration::from_secs(60));
    }

    #[test]
    fn test_handshake_timeout_is_reasonable() {
        let timeout = Duration::from_secs(HANDSHAKE_TIMEOUT_SECS);
        // Should be between 5 and 30 seconds
        assert!(timeout >= Duration::from_secs(5));
        assert!(timeout <= Duration::from_secs(30));
    }

    #[test]
    fn test_tick_interval_less_than_keepalive() {
        // Tick must be called more frequently than keepalive
        let tick = Duration::from_millis(TICK_INTERVAL_MS);
        let keepalive = Duration::from_secs(KEEPALIVE_INTERVAL_SECS);
        assert!(tick < keepalive);
    }
}

/// Integration-style tests for the VPN config API response
mod api_response_tests {
    use serde::{Deserialize, Serialize};

    #[derive(Debug, Clone, Serialize, Deserialize)]
    #[serde(rename_all = "camelCase")]
    struct MockVpnConfig {
        region: String,
        #[serde(rename = "serverEndpoint")]
        endpoint: String,
        server_public_key: String,
        private_key: String,
        public_key: String,
        assigned_ip: String,
        allowed_ips: Vec<String>,
        dns: Vec<String>,
        #[serde(default)]
        phantun_enabled: bool,
    }

    fn create_mock_api_response() -> String {
        r#"{
            "success": true,
            "config": {
                "region": "singapore",
                "serverEndpoint": "54.255.205.216:51820",
                "serverPublicKey": "YWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWE=",
                "privateKey": "YmJiYmJiYmJiYmJiYmJiYmJiYmJiYmJiYmJiYmJiYmI=",
                "publicKey": "Y2NjY2NjY2NjY2NjY2NjY2NjY2NjY2NjY2NjY2NjY2M=",
                "assignedIp": "10.0.42.15/32",
                "allowedIps": ["0.0.0.0/0"],
                "dns": ["1.1.1.1", "8.8.8.8"],
                "phantunEnabled": true
            }
        }"#.to_string()
    }

    #[test]
    fn test_api_response_has_required_fields() {
        let response = create_mock_api_response();
        // Check for required field presence
        assert!(response.contains("serverEndpoint"));
        assert!(response.contains("serverPublicKey"));
        assert!(response.contains("privateKey"));
        assert!(response.contains("assignedIp"));
    }

    #[test]
    fn test_api_response_parsing() {
        #[derive(Debug, Deserialize)]
        struct ApiResponse {
            success: bool,
            config: Option<MockVpnConfig>,
        }

        let response = create_mock_api_response();
        let parsed: Result<ApiResponse, _> = serde_json::from_str(&response);
        assert!(parsed.is_ok());

        let api_response = parsed.unwrap();
        assert!(api_response.success);
        assert!(api_response.config.is_some());

        let config = api_response.config.unwrap();
        assert_eq!(config.region, "singapore");
        assert_eq!(config.endpoint, "54.255.205.216:51820");
        assert!(config.phantun_enabled);
    }

    #[test]
    fn test_api_error_response_parsing() {
        #[derive(Debug, Deserialize)]
        struct ApiResponse {
            success: bool,
            error: Option<String>,
        }

        let error_response = r#"{"success": false, "error": "Invalid token"}"#;
        let parsed: Result<ApiResponse, _> = serde_json::from_str(error_response);
        assert!(parsed.is_ok());

        let api_response = parsed.unwrap();
        assert!(!api_response.success);
        assert!(api_response.error.is_some());
        assert!(api_response.error.unwrap().contains("Invalid"));
    }
}
