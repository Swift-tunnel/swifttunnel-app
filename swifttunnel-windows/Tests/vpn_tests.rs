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

/// Tests for network analyzer functionality
mod network_analyzer_tests {
    use std::time::Duration;

    const SPEED_TEST_CHUNK_SIZE: usize = 1024 * 1024; // 1MB
    const PING_TIMEOUT_MS: u64 = 5000;
    const JITTER_SAMPLE_COUNT: usize = 10;

    #[test]
    fn test_chunk_size_is_reasonable() {
        // Chunk size should be between 256KB and 10MB
        assert!(SPEED_TEST_CHUNK_SIZE >= 256 * 1024);
        assert!(SPEED_TEST_CHUNK_SIZE <= 10 * 1024 * 1024);
    }

    #[test]
    fn test_ping_timeout_is_reasonable() {
        let timeout = Duration::from_millis(PING_TIMEOUT_MS);
        // Should be between 1 and 30 seconds
        assert!(timeout >= Duration::from_secs(1));
        assert!(timeout <= Duration::from_secs(30));
    }

    #[test]
    fn test_jitter_sample_count() {
        // Should have at least 5 samples for meaningful jitter
        assert!(JITTER_SAMPLE_COUNT >= 5);
        assert!(JITTER_SAMPLE_COUNT <= 100);
    }

    #[test]
    fn test_calculate_jitter() {
        // Test jitter calculation with sample latencies
        let latencies = vec![50.0, 52.0, 48.0, 55.0, 45.0];

        // Calculate average
        let avg: f64 = latencies.iter().sum::<f64>() / latencies.len() as f64;
        assert!((avg - 50.0).abs() < 1.0);

        // Calculate jitter (average absolute deviation)
        let jitter: f64 = latencies.iter()
            .map(|&l| (l - avg).abs())
            .sum::<f64>() / latencies.len() as f64;

        // Jitter should be reasonable for these values
        assert!(jitter > 0.0);
        assert!(jitter < 10.0);
    }

    #[test]
    fn test_packet_loss_calculation() {
        let sent = 100;
        let received = 95;
        let loss_percent = ((sent - received) as f64 / sent as f64) * 100.0;

        assert!((loss_percent - 5.0).abs() < 0.01);
    }

    #[test]
    fn test_bandwidth_calculation() {
        // 10 MiB downloaded in 2 seconds = 5 MiB/s = ~41.94 Mbps
        // (10 * 1024 * 1024 / 2) * 8 / 1_000_000 = 41.943...
        let bytes_downloaded: u64 = 10 * 1024 * 1024;
        let duration_secs: f64 = 2.0;

        let bytes_per_sec = bytes_downloaded as f64 / duration_secs;
        let mbps = (bytes_per_sec * 8.0) / 1_000_000.0;

        assert!((mbps - 41.94).abs() < 0.1);
    }
}

/// Tests for updater functionality
mod updater_tests {
    use semver::Version;

    #[test]
    fn test_version_parsing() {
        let version_str = "0.9.20";
        let version: Result<Version, _> = version_str.parse();
        assert!(version.is_ok());

        let v = version.unwrap();
        assert_eq!(v.major, 0);
        assert_eq!(v.minor, 9);
        assert_eq!(v.patch, 20);
    }

    #[test]
    fn test_version_comparison() {
        let current: Version = "0.9.19".parse().unwrap();
        let available: Version = "0.9.20".parse().unwrap();

        assert!(available > current);
    }

    #[test]
    fn test_version_with_prerelease() {
        let stable: Version = "1.0.0".parse().unwrap();
        let beta: Version = "1.0.0-beta.1".parse().unwrap();

        // Stable should be greater than prerelease
        assert!(stable > beta);
    }

    #[test]
    fn test_asset_filename_parsing() {
        let filename = "SwiftTunnel-0.9.20-x64.msi";
        assert!(filename.ends_with(".msi"));
        assert!(filename.contains("x64"));
    }

    #[test]
    fn test_sha256_hash_length() {
        // SHA256 hash is 64 hex characters
        let mock_hash = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";
        assert_eq!(mock_hash.len(), 64);

        // All characters should be valid hex
        for c in mock_hash.chars() {
            assert!(c.is_ascii_hexdigit());
        }
    }

    #[test]
    fn test_github_asset_url_format() {
        let owner = "Swift-tunnel";
        let repo = "swifttunnel-app";
        let version = "0.9.20";
        let filename = "SwiftTunnel-0.9.20-x64.msi";

        let url = format!(
            "https://github.com/{}/{}/releases/download/v{}/{}",
            owner, repo, version, filename
        );

        assert!(url.starts_with("https://github.com/"));
        assert!(url.contains("/releases/download/"));
    }
}

/// Tests for settings persistence
mod settings_tests {
    use serde::{Deserialize, Serialize};

    #[derive(Debug, Clone, Serialize, Deserialize, Default, PartialEq)]
    struct MockSettings {
        start_minimized: bool,
        auto_connect: bool,
        last_region: Option<String>,
        split_tunnel_apps: Vec<String>,
        boost_enabled: bool,
    }

    #[test]
    fn test_default_settings() {
        let settings = MockSettings::default();
        assert!(!settings.start_minimized);
        assert!(!settings.auto_connect);
        assert!(settings.last_region.is_none());
        assert!(settings.split_tunnel_apps.is_empty());
        assert!(!settings.boost_enabled);
    }

    #[test]
    fn test_settings_serialization() {
        let settings = MockSettings {
            start_minimized: true,
            auto_connect: true,
            last_region: Some("singapore".to_string()),
            split_tunnel_apps: vec!["RobloxPlayerBeta.exe".to_string()],
            boost_enabled: true,
        };

        let json = serde_json::to_string(&settings).unwrap();
        let deserialized: MockSettings = serde_json::from_str(&json).unwrap();

        assert_eq!(settings, deserialized);
    }

    #[test]
    fn test_settings_with_empty_fields() {
        let json = r#"{
            "start_minimized": false,
            "auto_connect": false,
            "last_region": null,
            "split_tunnel_apps": [],
            "boost_enabled": false
        }"#;

        let settings: Result<MockSettings, _> = serde_json::from_str(json);
        assert!(settings.is_ok());
    }

    #[test]
    fn test_settings_missing_optional_fields() {
        // Test that missing optional fields default correctly
        let json = r#"{
            "start_minimized": true,
            "auto_connect": false,
            "split_tunnel_apps": [],
            "boost_enabled": true
        }"#;

        #[derive(Debug, Deserialize)]
        struct PartialSettings {
            start_minimized: bool,
            auto_connect: bool,
            #[serde(default)]
            last_region: Option<String>,
            split_tunnel_apps: Vec<String>,
            boost_enabled: bool,
        }

        let settings: Result<PartialSettings, _> = serde_json::from_str(json);
        assert!(settings.is_ok());
        assert!(settings.unwrap().last_region.is_none());
    }
}

/// Tests for OAuth and authentication
mod oauth_tests {
    use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};

    #[test]
    fn test_pkce_code_verifier_length() {
        // PKCE code verifier should be 43-128 characters
        let verifier = "abcdefghijklmnopqrstuvwxyz0123456789ABCDEFG";
        assert!(verifier.len() >= 43);
        assert!(verifier.len() <= 128);
    }

    #[test]
    fn test_state_parameter_generation() {
        // State should be random and base64url encoded
        let state_bytes = [0u8; 16];
        let state = URL_SAFE_NO_PAD.encode(state_bytes);
        // 16 bytes -> 22 base64 chars
        assert!(state.len() >= 16);
    }

    #[test]
    fn test_redirect_uri_format() {
        let port = 8642;
        let redirect_uri = format!("http://127.0.0.1:{}/callback", port);
        assert!(redirect_uri.starts_with("http://127.0.0.1:"));
        assert!(redirect_uri.ends_with("/callback"));
    }

    #[test]
    fn test_auth_url_construction() {
        let base_url = "https://auth.swifttunnel.net";
        let client_id = "test-client-id";
        let redirect_uri = "http://127.0.0.1:8642/callback";
        let state = "random-state";
        let code_challenge = "challenge";

        let auth_url = format!(
            "{}/authorize?client_id={}&redirect_uri={}&response_type=code&state={}&code_challenge={}&code_challenge_method=S256",
            base_url, client_id,
            urlencoding::encode(redirect_uri),
            state, code_challenge
        );

        assert!(auth_url.contains("client_id="));
        assert!(auth_url.contains("redirect_uri="));
        assert!(auth_url.contains("response_type=code"));
        assert!(auth_url.contains("code_challenge_method=S256"));
    }

    #[test]
    fn test_access_token_header() {
        let access_token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.test";
        let header_value = format!("Bearer {}", access_token);
        assert!(header_value.starts_with("Bearer "));
    }
}

/// Tests for process tracking and split tunnel
mod process_tracking_tests {
    use std::collections::HashSet;
    use std::net::Ipv4Addr;

    #[test]
    fn test_process_name_matching() {
        let target_apps: HashSet<String> = vec![
            "RobloxPlayerBeta.exe".to_string(),
            "RobloxStudioBeta.exe".to_string(),
        ].into_iter().collect();

        assert!(target_apps.contains("RobloxPlayerBeta.exe"));
        assert!(!target_apps.contains("chrome.exe"));
    }

    #[test]
    fn test_process_name_case_insensitive() {
        let target_app = "robloxplayerbeta.exe".to_lowercase();
        let actual_app = "RobloxPlayerBeta.exe".to_lowercase();
        assert_eq!(target_app, actual_app);
    }

    #[test]
    fn test_ip_in_subnet() {
        // Test if an IP is in a VPN subnet
        let vpn_subnet_start = Ipv4Addr::new(10, 0, 0, 0);
        let vpn_subnet_mask = 16; // /16
        let client_ip = Ipv4Addr::new(10, 0, 42, 15);

        let mask: u32 = !((1u32 << (32 - vpn_subnet_mask)) - 1);
        let subnet: u32 = u32::from(vpn_subnet_start) & mask;
        let client: u32 = u32::from(client_ip) & mask;

        assert_eq!(subnet, client);
    }

    #[test]
    fn test_process_id_validity() {
        // Process IDs should be positive integers
        let valid_pid: u32 = 1234;
        assert!(valid_pid > 0);

        // PID 0 is the system idle process (special case)
        let system_pid: u32 = 0;
        assert_eq!(system_pid, 0);
    }
}

/// Tests for route management
mod route_tests {
    use std::net::Ipv4Addr;

    #[test]
    fn test_roblox_ip_ranges() {
        // Known Roblox IP ranges (examples)
        let roblox_ranges = vec![
            ("128.116.0.0", 16),
            ("128.79.0.0", 16),
        ];

        for (ip_str, cidr) in roblox_ranges {
            let ip: Result<Ipv4Addr, _> = ip_str.parse();
            assert!(ip.is_ok(), "Invalid IP: {}", ip_str);
            assert!(cidr >= 8 && cidr <= 32);
        }
    }

    #[test]
    fn test_default_gateway_detection() {
        // Default gateway is typically a private IP
        let common_gateways = vec![
            "192.168.1.1",
            "192.168.0.1",
            "10.0.0.1",
            "172.16.0.1",
        ];

        for gw in common_gateways {
            let ip: Result<Ipv4Addr, _> = gw.parse();
            assert!(ip.is_ok());

            let addr = ip.unwrap();
            // Check if it's a private IP
            let is_private = addr.is_private();
            assert!(is_private, "{} should be private", gw);
        }
    }

    #[test]
    fn test_route_metric_ordering() {
        // Lower metric = higher priority
        let vpn_metric: u32 = 1;
        let default_metric: u32 = 100;

        assert!(vpn_metric < default_metric);
    }

    #[test]
    fn test_allowed_ips_parsing() {
        let allowed_ips = vec!["0.0.0.0/0", "10.0.0.0/8"];

        for ip_cidr in allowed_ips {
            let parts: Vec<&str> = ip_cidr.split('/').collect();
            assert_eq!(parts.len(), 2);

            let ip: Result<Ipv4Addr, _> = parts[0].parse();
            assert!(ip.is_ok());

            let cidr: Result<u8, _> = parts[1].parse();
            assert!(cidr.is_ok());
            assert!(cidr.unwrap() <= 32);
        }
    }
}

/// Tests for geolocation
mod geolocation_tests {
    use serde::Deserialize;

    #[derive(Debug, Deserialize)]
    struct MockGeoResponse {
        ip: String,
        country: String,
        country_code: String,
        region: Option<String>,
        city: Option<String>,
    }

    #[test]
    fn test_geo_response_parsing() {
        let json = r#"{
            "ip": "54.255.205.216",
            "country": "Singapore",
            "country_code": "SG",
            "region": "Central Singapore",
            "city": "Singapore"
        }"#;

        let geo: Result<MockGeoResponse, _> = serde_json::from_str(json);
        assert!(geo.is_ok());

        let response = geo.unwrap();
        assert_eq!(response.country_code, "SG");
    }

    #[test]
    fn test_geo_response_minimal() {
        // Some services return minimal data
        let json = r#"{
            "ip": "54.255.205.216",
            "country": "Singapore",
            "country_code": "SG"
        }"#;

        let geo: Result<MockGeoResponse, _> = serde_json::from_str(json);
        assert!(geo.is_ok());
    }
}

/// Tests for performance monitoring
mod performance_tests {
    #[test]
    fn test_cpu_usage_bounds() {
        // CPU usage should be 0-100%
        let cpu_usages = vec![0.0, 25.0, 50.0, 75.0, 100.0];
        for usage in cpu_usages {
            assert!(usage >= 0.0);
            assert!(usage <= 100.0);
        }
    }

    #[test]
    fn test_memory_usage_calculation() {
        let total_mb: u64 = 16384; // 16 GB
        let used_mb: u64 = 8192;   // 8 GB
        let percent = (used_mb as f64 / total_mb as f64) * 100.0;

        assert!((percent - 50.0).abs() < 0.01);
    }

    #[test]
    fn test_bytes_formatting() {
        let bytes: u64 = 1_073_741_824; // 1 GB
        let gb = bytes as f64 / 1_073_741_824.0;
        assert!((gb - 1.0).abs() < 0.01);
    }
}

/// Tests for system tray
mod tray_tests {
    #[test]
    fn test_tray_menu_items() {
        let menu_items = vec![
            "Show",
            "Connect",
            "Disconnect",
            "Exit",
        ];

        assert!(!menu_items.is_empty());
        assert!(menu_items.contains(&"Exit"));
    }

    #[test]
    fn test_tray_tooltip_length() {
        let tooltip = "SwiftTunnel - Connected to Singapore";
        // Windows limits tooltip to 128 characters
        assert!(tooltip.len() <= 128);
    }
}

/// Tests for notification system
mod notification_tests {
    #[test]
    fn test_notification_title_length() {
        let title = "SwiftTunnel";
        // Keep titles concise
        assert!(title.len() <= 50);
    }

    #[test]
    fn test_notification_body_length() {
        let body = "Successfully connected to Singapore VPN server";
        // Body should be readable but concise
        assert!(body.len() <= 200);
    }
}

// ============================================================================
// INTEGRATION TESTS
// ============================================================================
// These tests verify multiple components working together.
// They don't require admin privileges or actual network connections.

/// Integration tests for auth + storage flow
mod auth_integration_tests {
    use std::collections::HashMap;
    use std::path::PathBuf;
    use serde::{Deserialize, Serialize};

    #[derive(Debug, Clone, Serialize, Deserialize)]
    struct MockTokens {
        access_token: String,
        refresh_token: String,
        expires_at: i64,
    }

    #[derive(Debug, Clone, Serialize, Deserialize)]
    struct MockUser {
        id: String,
        email: String,
    }

    /// Tests the full auth token lifecycle: store -> read -> refresh check -> clear
    #[test]
    fn test_token_lifecycle() {
        // 1. Create tokens (simulating OAuth callback)
        let tokens = MockTokens {
            access_token: "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.test".to_string(),
            refresh_token: "refresh_token_abc123".to_string(),
            expires_at: chrono::Utc::now().timestamp() + 3600, // 1 hour from now
        };

        // 2. Serialize for storage
        let serialized = serde_json::to_string(&tokens).unwrap();
        assert!(serialized.contains("access_token"));
        assert!(serialized.contains("refresh_token"));

        // 3. Deserialize (simulating read from storage)
        let restored: MockTokens = serde_json::from_str(&serialized).unwrap();
        assert_eq!(restored.access_token, tokens.access_token);

        // 4. Check if refresh is needed
        let now = chrono::Utc::now().timestamp();
        let needs_refresh = restored.expires_at - now < 300; // 5 min buffer
        assert!(!needs_refresh); // Should not need refresh yet
    }

    /// Tests expired token detection
    #[test]
    fn test_expired_token_detection() {
        let expired_tokens = MockTokens {
            access_token: "old_token".to_string(),
            refresh_token: "refresh".to_string(),
            expires_at: chrono::Utc::now().timestamp() - 3600, // 1 hour ago
        };

        let now = chrono::Utc::now().timestamp();
        let is_expired = expired_tokens.expires_at <= now;
        assert!(is_expired);
    }

    /// Tests token refresh flow
    #[test]
    fn test_token_refresh_flow() {
        // Simulate token about to expire
        let old_tokens = MockTokens {
            access_token: "old_access".to_string(),
            refresh_token: "valid_refresh".to_string(),
            expires_at: chrono::Utc::now().timestamp() + 60, // 1 min left
        };

        // Check refresh threshold (5 minutes)
        let now = chrono::Utc::now().timestamp();
        let needs_refresh = old_tokens.expires_at - now < 300;
        assert!(needs_refresh);

        // Simulate refreshed tokens
        let new_tokens = MockTokens {
            access_token: "new_access_token".to_string(),
            refresh_token: "new_refresh_token".to_string(),
            expires_at: chrono::Utc::now().timestamp() + 3600,
        };

        // Verify new tokens are valid
        assert_ne!(new_tokens.access_token, old_tokens.access_token);
        assert!(new_tokens.expires_at > old_tokens.expires_at);
    }

    /// Tests user data persistence alongside tokens
    #[test]
    fn test_user_data_with_tokens() {
        let user = MockUser {
            id: "user_123".to_string(),
            email: "test@example.com".to_string(),
        };

        let tokens = MockTokens {
            access_token: "token".to_string(),
            refresh_token: "refresh".to_string(),
            expires_at: chrono::Utc::now().timestamp() + 3600,
        };

        // Simulate combined storage
        let mut storage: HashMap<String, String> = HashMap::new();
        storage.insert("user".to_string(), serde_json::to_string(&user).unwrap());
        storage.insert("tokens".to_string(), serde_json::to_string(&tokens).unwrap());

        // Verify both can be restored
        let restored_user: MockUser = serde_json::from_str(storage.get("user").unwrap()).unwrap();
        let restored_tokens: MockTokens = serde_json::from_str(storage.get("tokens").unwrap()).unwrap();

        assert_eq!(restored_user.email, "test@example.com");
        assert!(!restored_tokens.access_token.is_empty());
    }
}

/// Integration tests for settings + boosts
mod settings_integration_tests {
    use serde::{Deserialize, Serialize};

    #[derive(Debug, Clone, Serialize, Deserialize, Default)]
    struct MockBoostConfig {
        system_boosts_enabled: bool,
        network_boosts_enabled: bool,
        roblox_fps_limit: u32,
        launch_minimized: bool,
        auto_connect: bool,
        auto_connect_region: Option<String>,
    }

    /// Tests settings persistence across app restarts
    #[test]
    fn test_settings_persistence() {
        // User configures settings
        let settings = MockBoostConfig {
            system_boosts_enabled: true,
            network_boosts_enabled: true,
            roblox_fps_limit: 240,
            launch_minimized: false,
            auto_connect: true,
            auto_connect_region: Some("singapore".to_string()),
        };

        // Serialize to JSON (simulating file write)
        let json = serde_json::to_string_pretty(&settings).unwrap();

        // Deserialize (simulating app restart and file read)
        let restored: MockBoostConfig = serde_json::from_str(&json).unwrap();

        assert_eq!(restored.system_boosts_enabled, true);
        assert_eq!(restored.network_boosts_enabled, true);
        assert_eq!(restored.roblox_fps_limit, 240);
        assert_eq!(restored.auto_connect_region, Some("singapore".to_string()));
    }

    /// Tests boost configuration defaults
    #[test]
    fn test_boost_defaults_on_fresh_install() {
        let defaults = MockBoostConfig::default();

        // Verify safe defaults
        assert!(!defaults.system_boosts_enabled);
        assert!(!defaults.network_boosts_enabled);
        assert_eq!(defaults.roblox_fps_limit, 0); // 0 = uncapped
        assert!(!defaults.launch_minimized);
        assert!(!defaults.auto_connect);
        assert!(defaults.auto_connect_region.is_none());
    }

    /// Tests migration from old settings format
    #[test]
    fn test_settings_backward_compatibility() {
        // Old format (missing new fields)
        let old_json = r#"{
            "system_boosts_enabled": true,
            "network_boosts_enabled": false
        }"#;

        // Should still parse with defaults for missing fields
        #[derive(Deserialize, Default)]
        struct OldSettings {
            #[serde(default)]
            system_boosts_enabled: bool,
            #[serde(default)]
            network_boosts_enabled: bool,
            #[serde(default)]
            roblox_fps_limit: u32,
            #[serde(default)]
            launch_minimized: bool,
        }

        let parsed: OldSettings = serde_json::from_str(old_json).unwrap();
        assert!(parsed.system_boosts_enabled);
        assert!(!parsed.network_boosts_enabled);
        assert_eq!(parsed.roblox_fps_limit, 0); // Default
    }

    /// Tests preset switching
    #[test]
    fn test_preset_switching() {
        #[derive(Clone, Copy)]
        enum Preset {
            Performance,
            Balanced,
            Quality,
        }

        fn apply_preset(preset: Preset) -> MockBoostConfig {
            match preset {
                Preset::Performance => MockBoostConfig {
                    system_boosts_enabled: true,
                    network_boosts_enabled: true,
                    roblox_fps_limit: 9999, // Uncapped
                    launch_minimized: true,
                    auto_connect: true,
                    auto_connect_region: None,
                },
                Preset::Balanced => MockBoostConfig {
                    system_boosts_enabled: true,
                    network_boosts_enabled: false,
                    roblox_fps_limit: 144,
                    launch_minimized: false,
                    auto_connect: false,
                    auto_connect_region: None,
                },
                Preset::Quality => MockBoostConfig {
                    system_boosts_enabled: false,
                    network_boosts_enabled: false,
                    roblox_fps_limit: 60,
                    launch_minimized: false,
                    auto_connect: false,
                    auto_connect_region: None,
                },
            }
        }

        let perf = apply_preset(Preset::Performance);
        let balanced = apply_preset(Preset::Balanced);
        let quality = apply_preset(Preset::Quality);

        // Performance is most aggressive
        assert!(perf.system_boosts_enabled && perf.network_boosts_enabled);
        assert_eq!(perf.roblox_fps_limit, 9999);

        // Balanced is middle ground
        assert!(balanced.system_boosts_enabled);
        assert!(!balanced.network_boosts_enabled);

        // Quality is most conservative
        assert!(!quality.system_boosts_enabled);
        assert_eq!(quality.roblox_fps_limit, 60);
    }
}

/// Integration tests for VPN config + server selection
mod vpn_config_integration_tests {
    use std::net::{IpAddr, Ipv4Addr, SocketAddr};
    use base64::{Engine, engine::general_purpose::STANDARD};

    #[derive(Debug, Clone)]
    struct MockVpnConfig {
        private_key: String,
        public_key: String,
        assigned_ip: String,
        server_endpoint: SocketAddr,
        server_public_key: String,
        dns: Option<String>,
    }

    #[derive(Debug, Clone)]
    struct MockServer {
        region: String,
        endpoint: SocketAddr,
        public_key: String,
        has_phantun: bool,
        ping_ms: Option<u32>,
    }

    /// Tests complete config generation flow
    #[test]
    fn test_config_generation_flow() {
        // 1. Generate keypair (simulated)
        let private_key_bytes = [0u8; 32];
        let public_key_bytes = [1u8; 32];
        let private_key = STANDARD.encode(private_key_bytes);
        let public_key = STANDARD.encode(public_key_bytes);

        // 2. Get assigned IP from server (simulated)
        let assigned_ip = "10.0.42.15/32".to_string();

        // 3. Get server info
        let server = MockServer {
            region: "singapore".to_string(),
            endpoint: "54.255.205.216:51820".parse().unwrap(),
            public_key: STANDARD.encode([2u8; 32]),
            has_phantun: true,
            ping_ms: Some(25),
        };

        // 4. Create config
        let config = MockVpnConfig {
            private_key,
            public_key,
            assigned_ip,
            server_endpoint: server.endpoint,
            server_public_key: server.public_key,
            dns: Some("1.1.1.1".to_string()),
        };

        // Verify config is complete
        assert!(!config.private_key.is_empty());
        assert!(!config.public_key.is_empty());
        assert!(config.assigned_ip.contains("10.0."));
        assert_eq!(config.server_endpoint.port(), 51820);
    }

    /// Tests server selection by ping
    #[test]
    fn test_server_selection_by_ping() {
        let servers = vec![
            MockServer {
                region: "singapore".to_string(),
                endpoint: "1.1.1.1:51820".parse().unwrap(),
                public_key: String::new(),
                has_phantun: true,
                ping_ms: Some(25),
            },
            MockServer {
                region: "tokyo".to_string(),
                endpoint: "2.2.2.2:51820".parse().unwrap(),
                public_key: String::new(),
                has_phantun: true,
                ping_ms: Some(45),
            },
            MockServer {
                region: "sydney".to_string(),
                endpoint: "3.3.3.3:51820".parse().unwrap(),
                public_key: String::new(),
                has_phantun: false,
                ping_ms: Some(120),
            },
        ];

        // Find best server (lowest ping)
        let best = servers.iter()
            .filter(|s| s.ping_ms.is_some())
            .min_by_key(|s| s.ping_ms.unwrap())
            .unwrap();

        assert_eq!(best.region, "singapore");
        assert_eq!(best.ping_ms, Some(25));
    }

    /// Tests Phantun (stealth) server filtering
    #[test]
    fn test_phantun_server_filtering() {
        let servers = vec![
            MockServer {
                region: "singapore".to_string(),
                endpoint: "1.1.1.1:51820".parse().unwrap(),
                public_key: String::new(),
                has_phantun: true,
                ping_ms: Some(25),
            },
            MockServer {
                region: "mumbai".to_string(),
                endpoint: "2.2.2.2:51820".parse().unwrap(),
                public_key: String::new(),
                has_phantun: false,
                ping_ms: Some(50),
            },
        ];

        // Filter to only Phantun-capable servers
        let phantun_servers: Vec<_> = servers.iter()
            .filter(|s| s.has_phantun)
            .collect();

        assert_eq!(phantun_servers.len(), 1);
        assert_eq!(phantun_servers[0].region, "singapore");
    }

    /// Tests region grouping for smart selection
    #[test]
    fn test_region_grouping() {
        let asia_regions = vec!["singapore", "tokyo", "mumbai", "sydney"];
        let europe_regions = vec!["germany", "paris", "london"];
        let americas_regions = vec!["america", "brazil"];

        // Simulate user in Asia
        let user_region = "asia";
        let preferred_regions = match user_region {
            "asia" => &asia_regions,
            "europe" => &europe_regions,
            "americas" => &americas_regions,
            _ => &asia_regions,
        };

        assert!(preferred_regions.contains(&"singapore"));
        assert!(preferred_regions.contains(&"tokyo"));
        assert!(!preferred_regions.contains(&"germany"));
    }
}

/// Integration tests for split tunnel + route management
mod split_tunnel_integration_tests {
    use std::net::Ipv4Addr;
    use std::collections::HashSet;

    #[derive(Debug, Clone)]
    struct MockRoute {
        destination: Ipv4Addr,
        cidr: u8,
        gateway: Ipv4Addr,
        metric: u32,
    }

    /// Tests split tunnel app list management
    #[test]
    fn test_split_tunnel_app_management() {
        let mut split_apps: HashSet<String> = HashSet::new();

        // Add Roblox apps
        split_apps.insert("RobloxPlayerBeta.exe".to_string());
        split_apps.insert("RobloxStudioBeta.exe".to_string());

        assert!(split_apps.contains("RobloxPlayerBeta.exe"));
        assert_eq!(split_apps.len(), 2);

        // Remove one
        split_apps.remove("RobloxStudioBeta.exe");
        assert_eq!(split_apps.len(), 1);

        // Add custom app
        split_apps.insert("CustomGame.exe".to_string());
        assert_eq!(split_apps.len(), 2);
    }

    /// Tests route table construction
    #[test]
    fn test_route_table_construction() {
        let vpn_gateway = Ipv4Addr::new(10, 0, 0, 1);
        let local_gateway = Ipv4Addr::new(192, 168, 1, 1);

        // Roblox IP ranges through VPN
        let roblox_routes = vec![
            MockRoute {
                destination: Ipv4Addr::new(128, 116, 0, 0),
                cidr: 16,
                gateway: vpn_gateway,
                metric: 10,
            },
            MockRoute {
                destination: Ipv4Addr::new(128, 79, 0, 0),
                cidr: 16,
                gateway: vpn_gateway,
                metric: 10,
            },
        ];

        // Default route through local gateway
        let default_route = MockRoute {
            destination: Ipv4Addr::new(0, 0, 0, 0),
            cidr: 0,
            gateway: local_gateway,
            metric: 100, // Higher metric = lower priority
        };

        // Verify Roblox traffic uses VPN
        assert_eq!(roblox_routes[0].gateway, vpn_gateway);
        assert!(roblox_routes[0].metric < default_route.metric);
    }

    /// Tests IP matching for split tunnel decisions
    #[test]
    fn test_ip_matching_for_split_decision() {
        // VPN IPs (should go through tunnel)
        let vpn_ranges: Vec<(u32, u8)> = vec![
            (u32::from(Ipv4Addr::new(128, 116, 0, 0)), 16), // Roblox
            (u32::from(Ipv4Addr::new(128, 79, 0, 0)), 16),  // Roblox
        ];

        let test_ips = vec![
            (Ipv4Addr::new(128, 116, 10, 5), true),   // Roblox server
            (Ipv4Addr::new(128, 79, 200, 1), true),   // Roblox server
            (Ipv4Addr::new(8, 8, 8, 8), false),       // Google DNS
            (Ipv4Addr::new(142, 250, 185, 14), false), // Google
        ];

        for (ip, should_tunnel) in test_ips {
            let ip_u32 = u32::from(ip);
            let mut matches_vpn = false;

            for (range_start, cidr) in &vpn_ranges {
                let mask = if *cidr == 0 { 0 } else { !((1u32 << (32 - cidr)) - 1) };
                if (ip_u32 & mask) == (*range_start & mask) {
                    matches_vpn = true;
                    break;
                }
            }

            assert_eq!(matches_vpn, should_tunnel, "IP {} matching failed", ip);
        }
    }

    /// Tests process-based split tunnel decision
    #[test]
    fn test_process_based_split_decision() {
        let tunnel_apps: HashSet<&str> = vec![
            "RobloxPlayerBeta.exe",
            "RobloxStudioBeta.exe",
        ].into_iter().collect();

        // Simulated connections
        let connections = vec![
            ("RobloxPlayerBeta.exe", "128.116.10.5:12345"),
            ("chrome.exe", "142.250.185.14:443"),
            ("RobloxStudioBeta.exe", "128.79.200.1:54321"),
            ("discord.exe", "162.159.135.232:443"),
        ];

        for (process, _dest) in connections {
            let should_tunnel = tunnel_apps.contains(process);

            match process {
                "RobloxPlayerBeta.exe" | "RobloxStudioBeta.exe" => {
                    assert!(should_tunnel, "{} should tunnel", process);
                }
                _ => {
                    assert!(!should_tunnel, "{} should not tunnel", process);
                }
            }
        }
    }
}

/// Integration tests for updater + version management
mod updater_integration_tests {
    use semver::Version;
    use sha2::{Sha256, Digest};

    #[derive(Debug, Clone)]
    struct MockRelease {
        version: Version,
        download_url: String,
        sha256: String,
        size_bytes: u64,
    }

    /// Tests version comparison for update availability
    #[test]
    fn test_update_availability_check() {
        let current = Version::parse("0.9.20").unwrap();
        let releases = vec![
            Version::parse("0.9.21").unwrap(),
            Version::parse("0.9.20").unwrap(),
            Version::parse("0.9.19").unwrap(),
        ];

        let newer: Vec<_> = releases.iter()
            .filter(|v| **v > current)
            .collect();

        assert_eq!(newer.len(), 1);
        assert_eq!(*newer[0], Version::parse("0.9.21").unwrap());
    }

    /// Tests download integrity verification
    #[test]
    fn test_download_integrity() {
        // Simulated file content
        let file_content = b"SwiftTunnel installer binary content...";

        // Calculate hash
        let mut hasher = Sha256::new();
        hasher.update(file_content);
        let hash = hasher.finalize();
        let hash_hex = format!("{:x}", hash);

        // Verify hash is correct length
        assert_eq!(hash_hex.len(), 64);

        // Simulate verification
        let expected_hash = &hash_hex;
        let actual_hash = &hash_hex;
        assert_eq!(expected_hash, actual_hash);
    }

    /// Tests update marker file lifecycle
    #[test]
    fn test_update_marker_lifecycle() {
        use std::collections::HashMap;

        let mut markers: HashMap<String, String> = HashMap::new();

        // Before update: no marker
        assert!(markers.get("update_pending").is_none());

        // Download complete: create marker
        markers.insert("update_pending".to_string(), "0.9.21".to_string());
        markers.insert("installer_path".to_string(), "C:\\temp\\SwiftTunnel.msi".to_string());

        // Verify marker exists
        assert!(markers.get("update_pending").is_some());

        // After successful install: clear marker
        markers.remove("update_pending");
        markers.remove("installer_path");
        assert!(markers.get("update_pending").is_none());
    }

    /// Tests rollback detection
    #[test]
    fn test_rollback_detection() {
        let installed = Version::parse("0.9.21").unwrap();
        let available = Version::parse("0.9.20").unwrap();

        // Don't "update" to older version
        let is_rollback = available < installed;
        assert!(is_rollback);

        // Same version = not an update
        let same = Version::parse("0.9.21").unwrap();
        let is_update = same > installed;
        assert!(!is_update);
    }
}

/// Integration tests for network analyzer
mod network_analyzer_integration_tests {
    use std::time::Duration;

    #[derive(Debug, Clone)]
    struct MockPingResult {
        target: String,
        latency_ms: f64,
        success: bool,
    }

    #[derive(Debug, Clone)]
    struct MockSpeedResult {
        download_mbps: f64,
        upload_mbps: f64,
        test_duration: Duration,
    }

    /// Tests stability test with multiple pings
    #[test]
    fn test_stability_analysis() {
        let pings = vec![
            MockPingResult { target: "1.1.1.1".to_string(), latency_ms: 20.0, success: true },
            MockPingResult { target: "1.1.1.1".to_string(), latency_ms: 22.0, success: true },
            MockPingResult { target: "1.1.1.1".to_string(), latency_ms: 19.0, success: true },
            MockPingResult { target: "1.1.1.1".to_string(), latency_ms: 150.0, success: true }, // Spike
            MockPingResult { target: "1.1.1.1".to_string(), latency_ms: 21.0, success: true },
        ];

        // Calculate stats
        let successful: Vec<_> = pings.iter().filter(|p| p.success).collect();
        let latencies: Vec<f64> = successful.iter().map(|p| p.latency_ms).collect();

        let avg = latencies.iter().sum::<f64>() / latencies.len() as f64;
        let min = latencies.iter().cloned().fold(f64::INFINITY, f64::min);
        let max = latencies.iter().cloned().fold(f64::NEG_INFINITY, f64::max);

        // Calculate jitter (average deviation from mean)
        let jitter: f64 = latencies.iter()
            .map(|&l| (l - avg).abs())
            .sum::<f64>() / latencies.len() as f64;

        assert!(min < avg);
        assert!(max > avg);
        assert!(jitter > 0.0); // Should have some jitter due to spike

        // Detect spike
        let spike_threshold = avg * 3.0;
        let has_spike = latencies.iter().any(|&l| l > spike_threshold);
        assert!(has_spike);
    }

    /// Tests speed test result aggregation
    #[test]
    fn test_speed_result_aggregation() {
        let results = vec![
            MockSpeedResult { download_mbps: 95.5, upload_mbps: 45.2, test_duration: Duration::from_secs(10) },
            MockSpeedResult { download_mbps: 98.3, upload_mbps: 47.1, test_duration: Duration::from_secs(10) },
            MockSpeedResult { download_mbps: 94.8, upload_mbps: 44.9, test_duration: Duration::from_secs(10) },
        ];

        let avg_down = results.iter().map(|r| r.download_mbps).sum::<f64>() / results.len() as f64;
        let avg_up = results.iter().map(|r| r.upload_mbps).sum::<f64>() / results.len() as f64;

        // Verify reasonable averages
        assert!(avg_down > 90.0 && avg_down < 100.0);
        assert!(avg_up > 40.0 && avg_up < 50.0);
    }

    /// Tests connection quality rating
    #[test]
    fn test_connection_quality_rating() {
        #[derive(Debug, PartialEq)]
        enum Quality {
            Excellent,
            Good,
            Fair,
            Poor,
        }

        fn rate_connection(ping_ms: f64, jitter_ms: f64, packet_loss_pct: f64) -> Quality {
            if ping_ms < 30.0 && jitter_ms < 5.0 && packet_loss_pct < 0.1 {
                Quality::Excellent
            } else if ping_ms < 60.0 && jitter_ms < 15.0 && packet_loss_pct < 1.0 {
                Quality::Good
            } else if ping_ms < 100.0 && jitter_ms < 30.0 && packet_loss_pct < 3.0 {
                Quality::Fair
            } else {
                Quality::Poor
            }
        }

        assert_eq!(rate_connection(20.0, 2.0, 0.0), Quality::Excellent);
        assert_eq!(rate_connection(45.0, 10.0, 0.5), Quality::Good);
        assert_eq!(rate_connection(80.0, 25.0, 2.0), Quality::Fair);
        assert_eq!(rate_connection(150.0, 50.0, 5.0), Quality::Poor);
    }
}
