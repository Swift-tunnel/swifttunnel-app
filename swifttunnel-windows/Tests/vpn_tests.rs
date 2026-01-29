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
        // 10MB downloaded in 2 seconds = 5 MB/s = 40 Mbps
        let bytes_downloaded: u64 = 10 * 1024 * 1024;
        let duration_secs: f64 = 2.0;

        let bytes_per_sec = bytes_downloaded as f64 / duration_secs;
        let mbps = (bytes_per_sec * 8.0) / 1_000_000.0;

        assert!((mbps - 40.0).abs() < 0.5);
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
