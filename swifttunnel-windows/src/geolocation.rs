//! IP Geolocation module
//!
//! Uses ip-api.com to get location information for game server IPs.
//! Similar to Bloxstrap's server location feature.
//!
//! Note: ip-api.com free tier has 45 requests/minute limit and requires HTTP (not HTTPS).

use serde::Deserialize;
use std::collections::HashMap;
use std::net::Ipv4Addr;
use std::sync::{Arc, Mutex};
use tokio::sync::Semaphore;

/// Cache for server locations to avoid repeated API calls
static LOCATION_CACHE: std::sync::OnceLock<Arc<Mutex<HashMap<Ipv4Addr, String>>>> = std::sync::OnceLock::new();

/// Semaphore to limit concurrent API requests (ip-api.com: 45 req/min)
static API_SEMAPHORE: std::sync::OnceLock<Semaphore> = std::sync::OnceLock::new();

fn get_cache() -> Arc<Mutex<HashMap<Ipv4Addr, String>>> {
    LOCATION_CACHE.get_or_init(|| Arc::new(Mutex::new(HashMap::new()))).clone()
}

fn get_semaphore() -> &'static Semaphore {
    // Limit to 2 concurrent requests to stay well under rate limit
    API_SEMAPHORE.get_or_init(|| Semaphore::new(2))
}

/// Response from ip-api.com API
/// Free tier returns city, regionName, country without authentication
#[derive(Debug, Deserialize)]
pub struct IpApiResponse {
    pub status: String,
    pub city: Option<String>,
    #[serde(rename = "regionName")]
    pub region_name: Option<String>,
    pub country: Option<String>,
    #[serde(rename = "countryCode")]
    pub country_code: Option<String>,
    pub message: Option<String>,
}

/// Get location for an IP address
/// Returns a formatted string like "Singapore, SG" or "Ashburn, Virginia, US"
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

    // Query ip-api.com (free tier requires HTTP, not HTTPS)
    // Fields: city, regionName, country, countryCode
    let url = format!("http://ip-api.com/json/{}?fields=status,message,city,regionName,country,countryCode", ip);
    log::info!("Querying location for IP: {}", ip);

    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(5))
        .build()
        .ok()?;

    let response = client.get(&url).send().await.ok()?;

    if !response.status().is_success() {
        log::warn!("ip-api.com returned HTTP status {}", response.status());
        return None;
    }

    let info: IpApiResponse = response.json().await.ok()?;

    // Check API status
    if info.status != "success" {
        log::warn!("ip-api.com query failed: {:?}", info.message);
        return None;
    }

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

/// Format location from ip-api.com response
fn format_location(info: &IpApiResponse) -> Option<String> {
    let city = info.city.as_ref()?;
    let country_code = info.country_code.as_ref().or(info.country.as_ref())?;

    // If city equals region (or no region), use shorter format
    if let Some(region) = &info.region_name {
        if city == region || region.is_empty() {
            Some(format!("{}, {}", city, country_code))
        } else {
            Some(format!("{}, {}, {}", city, region, country_code))
        }
    } else {
        Some(format!("{}, {}", city, country_code))
    }
}

/// Check if an IP is likely a Roblox game server
/// Based on known Roblox IP ranges
pub fn is_roblox_game_server_ip(ip: Ipv4Addr) -> bool {
    let ip_u32 = u32::from(ip);

    // Roblox IP ranges
    const ROBLOX_RANGES: &[(u32, u32)] = &[
        (0x80740000, 0xFFFF8000), // 128.116.0.0/17
        (0xD1CE2800, 0xFFFFF800), // 209.206.40.0/21
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
        let info = IpApiResponse {
            status: "success".to_string(),
            city: Some("Singapore".to_string()),
            region_name: Some("Singapore".to_string()),
            country: Some("Singapore".to_string()),
            country_code: Some("SG".to_string()),
            message: None,
        };
        assert_eq!(format_location(&info), Some("Singapore, SG".to_string()));

        // City differs from region
        let info = IpApiResponse {
            status: "success".to_string(),
            city: Some("Ashburn".to_string()),
            region_name: Some("Virginia".to_string()),
            country: Some("United States".to_string()),
            country_code: Some("US".to_string()),
            message: None,
        };
        assert_eq!(format_location(&info), Some("Ashburn, Virginia, US".to_string()));
    }
}
