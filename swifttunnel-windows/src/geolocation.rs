//! IP Geolocation module
//!
//! Uses ipinfo.io to get location information for game server IPs.
//! Similar to Bloxstrap's server location feature.

use serde::Deserialize;
use std::collections::HashMap;
use std::net::Ipv4Addr;
use std::sync::{Arc, Mutex};
use tokio::sync::Semaphore;

/// Cache for server locations to avoid repeated API calls
static LOCATION_CACHE: std::sync::OnceLock<Arc<Mutex<HashMap<Ipv4Addr, String>>>> = std::sync::OnceLock::new();

/// Semaphore to limit concurrent API requests
static API_SEMAPHORE: std::sync::OnceLock<Semaphore> = std::sync::OnceLock::new();

fn get_cache() -> Arc<Mutex<HashMap<Ipv4Addr, String>>> {
    LOCATION_CACHE.get_or_init(|| Arc::new(Mutex::new(HashMap::new()))).clone()
}

fn get_semaphore() -> &'static Semaphore {
    API_SEMAPHORE.get_or_init(|| Semaphore::new(2))
}

/// Response from ipinfo.io API
#[derive(Debug, Deserialize)]
pub struct IpInfoResponse {
    pub city: Option<String>,
    pub region: Option<String>,
    pub country: Option<String>,
}

/// Get location for an IP address
/// Returns a formatted string like "Singapore, SG" or "Virginia, VA, US"
pub async fn get_ip_location(ip: Ipv4Addr) -> Option<String> {
    // Check cache first
    {
        let cache = get_cache();
        if let Ok(cache) = cache.lock() {
            if let Some(location) = cache.get(&ip) {
                log::debug!("Cache hit for IP {}: {}", ip, location);
                return Some(location.clone());
            }
        };
    }

    // Acquire semaphore to limit concurrent requests
    let _permit = get_semaphore().acquire().await.ok()?;

    // Query ipinfo.io
    let url = format!("https://ipinfo.io/{}/json", ip);
    log::info!("Querying location for IP: {}", ip);

    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(5))
        .build()
        .ok()?;

    let response = client.get(&url).send().await.ok()?;

    if !response.status().is_success() {
        log::warn!("ipinfo.io returned status {}", response.status());
        return None;
    }

    let info: IpInfoResponse = response.json().await.ok()?;

    // Format location string (like Bloxstrap)
    let location = format_location(&info)?;

    // Cache the result
    {
        let cache = get_cache();
        if let Ok(mut cache) = cache.lock() {
            cache.insert(ip, location.clone());
            log::info!("Cached location for {}: {}", ip, location);
        };
    }

    Some(location)
}

/// Format location from IpInfo response
fn format_location(info: &IpInfoResponse) -> Option<String> {
    let city = info.city.as_ref()?;
    let country = info.country.as_ref()?;

    // If city equals region (or no region), use shorter format
    if let Some(region) = &info.region {
        if city == region {
            Some(format!("{}, {}", city, country))
        } else {
            Some(format!("{}, {}, {}", city, region, country))
        }
    } else {
        Some(format!("{}, {}", city, country))
    }
}

/// Check if an IP is likely a Roblox game server
/// Based on known Roblox IP ranges from AS22697/AS11281
///
/// Sources:
/// - https://devforum.roblox.com/t/all-of-robloxs-ip-ranges-ipv4-ipv6-2023/2527578
/// - https://devforum.roblox.com/t/roblox-server-region-a-list-of-roblox-ip-ranges/3094401
pub fn is_roblox_game_server_ip(ip: Ipv4Addr) -> bool {
    let ip_u32 = u32::from(ip);

    // Roblox IP ranges (network, mask)
    // Note: 128.116.0.0/17 covers ALL regional game servers
    const ROBLOX_RANGES: &[(u32, u32)] = &[
        // Primary game servers (all regions)
        (0x80740000, 0xFFFF8000), // 128.116.0.0/17
        // Secondary (San Jose)
        (0xD1CE2800, 0xFFFFF800), // 209.206.40.0/21
        // Asia-Pacific
        (0x678C1C00, 0xFFFFFE00), // 103.140.28.0/23
        // China (Luobu)
        (0x678EDC00, 0xFFFFFE00), // 103.142.220.0/23
        // API/Matchmaking
        (0x17ADC000, 0xFFFFFF00), // 23.173.192.0/24
        (0x8DC10300, 0xFFFFFF00), // 141.193.3.0/24
        (0xCDC93E00, 0xFFFFFF00), // 205.201.62.0/24
        // Infrastructure
        (0xCC09B800, 0xFFFFFF00), // 204.9.184.0/24
        (0xCC0DA800, 0xFFFFFC00), // 204.13.168.0/22
        (0xCC0DAC00, 0xFFFFFE00), // 204.13.172.0/23
    ];

    for &(network, mask) in ROBLOX_RANGES {
        if (ip_u32 & mask) == network {
            return true;
        }
    }

    false
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_is_roblox_game_server() {
        // Should match - in Roblox range
        assert!(is_roblox_game_server_ip(Ipv4Addr::new(128, 116, 50, 100)));
        assert!(is_roblox_game_server_ip(Ipv4Addr::new(209, 206, 42, 10)));

        // Should not match - outside ranges
        assert!(!is_roblox_game_server_ip(Ipv4Addr::new(1, 1, 1, 1)));
        assert!(!is_roblox_game_server_ip(Ipv4Addr::new(8, 8, 8, 8)));
    }

    #[test]
    fn test_format_location() {
        // City equals region
        let info = IpInfoResponse {
            city: Some("Singapore".to_string()),
            region: Some("Singapore".to_string()),
            country: Some("SG".to_string()),
        };
        assert_eq!(format_location(&info), Some("Singapore, SG".to_string()));

        // City differs from region
        let info = IpInfoResponse {
            city: Some("Ashburn".to_string()),
            region: Some("Virginia".to_string()),
            country: Some("US".to_string()),
        };
        assert_eq!(format_location(&info), Some("Ashburn, Virginia, US".to_string()));
    }
}
