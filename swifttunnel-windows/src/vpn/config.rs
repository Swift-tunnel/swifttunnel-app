//! VPN Configuration fetching from API
//!
//! Handles fetching VPN configuration from the SwiftTunnel API,
//! including WireGuard keys, server endpoints, and assigned IPs.

use serde::{Deserialize, Serialize};
use crate::auth::types::VpnConfig;
use super::{VpnError, VpnResult};

/// API base URL for SwiftTunnel
const API_BASE_URL: &str = "https://swifttunnel.net";

/// Request body for generating VPN config
#[derive(Debug, Clone, Serialize)]
pub struct VpnConfigRequest {
    pub region: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub public_key: Option<String>,
}

/// API response wrapper
#[derive(Debug, Deserialize)]
struct ApiResponse<T> {
    #[serde(default)]
    success: bool,
    /// VPN config data (API returns this as "config", not "data")
    #[serde(default)]
    config: Option<T>,
    #[serde(default)]
    error: Option<String>,
}

/// Fetch VPN configuration from the API
///
/// # Arguments
/// * `access_token` - Bearer token for authentication
/// * `region` - Server region (e.g., "singapore", "mumbai")
///
/// # Returns
/// * `VpnConfig` containing all necessary connection parameters
pub async fn fetch_vpn_config(
    access_token: &str,
    region: &str,
) -> VpnResult<VpnConfig> {
    let client = reqwest::Client::new();
    let url = format!("{}/api/vpn/generate-config", API_BASE_URL);

    let request = VpnConfigRequest {
        region: region.to_string(),
        public_key: None, // Server will generate if not provided
    };

    log::info!("Fetching VPN config for region: {}", region);

    let response = client
        .post(&url)
        .header("Authorization", format!("Bearer {}", access_token))
        .header("Content-Type", "application/json")
        .json(&request)
        .send()
        .await
        .map_err(|e| VpnError::ConfigFetch(e.to_string()))?;

    let status = response.status();
    if !status.is_success() {
        let error_text = response.text().await.unwrap_or_default();
        log::error!("API error {}: {}", status, error_text);
        return Err(VpnError::ConfigFetch(format!(
            "HTTP {}: {}",
            status, error_text
        )));
    }

    let api_response: ApiResponse<VpnConfig> = response
        .json()
        .await
        .map_err(|e| VpnError::ConfigFetch(format!("Failed to parse response: {}", e)))?;

    match api_response.config {
        Some(config) => {
            log::info!("Successfully fetched VPN config for {}", region);
            Ok(config)
        }
        None => {
            let error = api_response.error.unwrap_or_else(|| "Unknown error".to_string());
            Err(VpnError::ConfigFetch(error))
        }
    }
}

/// Generate a new WireGuard keypair locally
///
/// The private key stays on the device, only public key is sent to server.
pub fn generate_keypair() -> (String, String) {
    use x25519_dalek::{StaticSecret, PublicKey};
    use base64::{Engine as _, engine::general_purpose::STANDARD};
    use rand::rngs::OsRng;

    let private_key = StaticSecret::random_from_rng(OsRng);
    let public_key = PublicKey::from(&private_key);

    let private_key_b64 = STANDARD.encode(private_key.as_bytes());
    let public_key_b64 = STANDARD.encode(public_key.as_bytes());

    (private_key_b64, public_key_b64)
}

/// Parse WireGuard key from Base64 to bytes
pub fn parse_key(key_b64: &str) -> VpnResult<[u8; 32]> {
    use base64::{Engine as _, engine::general_purpose::STANDARD};

    let bytes = STANDARD
        .decode(key_b64)
        .map_err(|e| VpnError::InvalidConfig(format!("Invalid Base64 key: {}", e)))?;

    if bytes.len() != 32 {
        return Err(VpnError::InvalidConfig(format!(
            "Key must be 32 bytes, got {}",
            bytes.len()
        )));
    }

    let mut arr = [0u8; 32];
    arr.copy_from_slice(&bytes);
    Ok(arr)
}

/// Parse IP address with optional CIDR notation
pub fn parse_ip_cidr(ip_str: &str) -> VpnResult<(std::net::IpAddr, u8)> {
    if let Some((ip, cidr)) = ip_str.split_once('/') {
        let ip: std::net::IpAddr = ip
            .parse()
            .map_err(|e| VpnError::InvalidConfig(format!("Invalid IP: {}", e)))?;
        let cidr: u8 = cidr
            .parse()
            .map_err(|e| VpnError::InvalidConfig(format!("Invalid CIDR: {}", e)))?;
        Ok((ip, cidr))
    } else {
        let ip: std::net::IpAddr = ip_str
            .parse()
            .map_err(|e| VpnError::InvalidConfig(format!("Invalid IP: {}", e)))?;
        // Default to /32 for IPv4, /128 for IPv6
        let cidr = if ip.is_ipv4() { 32 } else { 128 };
        Ok((ip, cidr))
    }
}

/// Parse server endpoint string into SocketAddr
pub fn parse_endpoint(endpoint: &str) -> VpnResult<std::net::SocketAddr> {
    endpoint
        .parse()
        .map_err(|e| VpnError::InvalidConfig(format!("Invalid endpoint '{}': {}", endpoint, e)))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_generate_keypair() {
        let (private, public) = generate_keypair();

        // Both should be valid Base64
        assert!(parse_key(&private).is_ok());
        assert!(parse_key(&public).is_ok());

        // They should be different
        assert_ne!(private, public);
    }

    #[test]
    fn test_parse_ip_cidr() {
        let (ip, cidr) = parse_ip_cidr("10.0.42.15/32").unwrap();
        assert_eq!(ip.to_string(), "10.0.42.15");
        assert_eq!(cidr, 32);

        let (ip, cidr) = parse_ip_cidr("192.168.1.1").unwrap();
        assert_eq!(ip.to_string(), "192.168.1.1");
        assert_eq!(cidr, 32);
    }

    #[test]
    fn test_parse_endpoint() {
        let addr = parse_endpoint("54.255.205.216:51820").unwrap();
        assert_eq!(addr.port(), 51820);
    }
}
