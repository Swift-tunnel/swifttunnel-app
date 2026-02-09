//! IP Geolocation module
//!
//! Uses ipinfo.io to get location information for game server IPs.
//! Similar to Bloxstrap's server location feature.

use crate::dns::CloudflareDns;
use serde::Deserialize;
use std::collections::HashMap;
use std::net::Ipv4Addr;
use std::sync::{Arc, Mutex};
use tokio::sync::Semaphore;

/// Shared HTTP client with 5s timeout for geolocation lookups
fn geo_http_client() -> &'static reqwest::Client {
    static CLIENT: std::sync::OnceLock<reqwest::Client> = std::sync::OnceLock::new();
    CLIENT.get_or_init(|| {
        reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(5))
            .dns_resolver(CloudflareDns::shared())
            .build()
            .expect("Failed to build geolocation HTTP client")
    })
}

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

    let client = geo_http_client();

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

/// Roblox game server region detected from IP address
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum RobloxRegion {
    Singapore,
    Tokyo,
    Mumbai,
    Sydney,
    London,
    Amsterdam,
    Paris,
    Frankfurt,
    Warsaw,
    UsEast,      // Ashburn, NYC, Atlanta, Miami
    UsCentral,   // Chicago, Dallas
    UsWest,      // LA, Seattle
    Brazil,
    Unknown,
}

impl RobloxRegion {
    /// Get the best SwiftTunnel gaming region for this Roblox region
    pub fn best_swifttunnel_region(&self) -> Option<&'static str> {
        match self {
            RobloxRegion::Unknown => None,
            RobloxRegion::Singapore => Some("singapore"),
            RobloxRegion::Tokyo => Some("tokyo"),
            RobloxRegion::Mumbai => Some("mumbai"),
            RobloxRegion::Sydney => Some("sydney"),
            RobloxRegion::London => Some("london"),
            RobloxRegion::Amsterdam => Some("amsterdam"),
            RobloxRegion::Paris => Some("paris"),
            RobloxRegion::Frankfurt => Some("germany"),
            RobloxRegion::Warsaw => Some("germany"),  // Closest SwiftTunnel region
            RobloxRegion::UsEast => Some("america"),
            RobloxRegion::UsCentral => Some("america"),
            RobloxRegion::UsWest => Some("america"),
            RobloxRegion::Brazil => Some("brazil"),
        }
    }

    pub fn display_name(&self) -> &'static str {
        match self {
            RobloxRegion::Singapore => "Singapore",
            RobloxRegion::Tokyo => "Tokyo",
            RobloxRegion::Mumbai => "Mumbai",
            RobloxRegion::Sydney => "Sydney",
            RobloxRegion::London => "London",
            RobloxRegion::Amsterdam => "Amsterdam",
            RobloxRegion::Paris => "Paris",
            RobloxRegion::Frankfurt => "Frankfurt",
            RobloxRegion::Warsaw => "Warsaw",
            RobloxRegion::UsEast => "US East",
            RobloxRegion::UsCentral => "US Central",
            RobloxRegion::UsWest => "US West",
            RobloxRegion::Brazil => "Brazil",
            RobloxRegion::Unknown => "Unknown",
        }
    }
}

impl std::fmt::Display for RobloxRegion {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.display_name())
    }
}

/// Determine Roblox game server region from ipinfo.io city/country fields.
///
/// This is the runtime counterpart to the hardcoded `roblox_ip_to_region()` table.
/// Used by auto-routing and toast notifications for accurate region detection.
pub fn ipinfo_to_roblox_region(city: &str, country: &str) -> RobloxRegion {
    match country {
        "SG" => RobloxRegion::Singapore,
        "JP" => RobloxRegion::Tokyo,
        "IN" => RobloxRegion::Mumbai,
        "AU" => RobloxRegion::Sydney,
        "BR" => RobloxRegion::Brazil,
        "GB" => RobloxRegion::London,
        "NL" => RobloxRegion::Amsterdam,
        "FR" => RobloxRegion::Paris,
        "PL" => RobloxRegion::Warsaw,
        "DE" => RobloxRegion::Frankfurt,
        "US" => {
            // Determine US sub-region from city name
            let city_lower = city.to_lowercase();
            if city_lower.contains("chicago") || city_lower.contains("elk grove")
                || city_lower.contains("dallas") || city_lower.contains("houston")
            {
                RobloxRegion::UsCentral
            } else if city_lower.contains("ashburn") || city_lower.contains("leesburg")
                || city_lower.contains("sterling") || city_lower.contains("reston")
                || city_lower.contains("new york") || city_lower.contains("secaucus")
                || city_lower.contains("newark") || city_lower.contains("atlanta")
                || city_lower.contains("miami") || city_lower.contains("jacksonville")
                || city_lower.contains("fort lauderdale")
            {
                RobloxRegion::UsEast
            } else {
                // Default US to West (LA, San Jose, Seattle, San Mateo all West Coast)
                RobloxRegion::UsWest
            }
        }
        _ => RobloxRegion::Unknown,
    }
}

/// Look up a game server IP's region via ipinfo.io (async).
///
/// Returns `(RobloxRegion, location_string)` where location_string is like "Singapore, SG".
/// Used by auto-routing for accurate runtime region detection.
pub async fn lookup_game_server_region(ip: Ipv4Addr) -> Option<(RobloxRegion, String)> {
    let _permit = get_semaphore().acquire().await.ok()?;

    // Check cache first
    let cached_location = {
        let cache = get_cache();
        cache.lock().ok().and_then(|c| c.get(&ip).cloned())
    };

    let (city, country, location) = if let Some(loc) = cached_location {
        // Parse cached "City, Country" or "City, Region, Country" string
        let parts: Vec<&str> = loc.split(", ").collect();
        let city = parts.first().unwrap_or(&"").to_string();
        let country = parts.last().unwrap_or(&"").to_string();
        (city, country, loc)
    } else {
        let url = format!("https://ipinfo.io/{}/json", ip);
        let client = geo_http_client();
        let response = client.get(&url).send().await.ok()?;
        if !response.status().is_success() {
            log::warn!("ipinfo.io returned status {} for {}", response.status(), ip);
            return None;
        }
        let info: IpInfoResponse = response.json().await.ok()?;
        let city = info.city.clone().unwrap_or_default();
        let country = info.country.clone().unwrap_or_default();
        let location = format_location(&info)?;

        // Cache the result
        if let Ok(mut cache) = get_cache().lock() {
            cache.insert(ip, location.clone());
        }

        (city, country, location)
    };

    let region = ipinfo_to_roblox_region(&city, &country);
    log::info!("Geo lookup: {} -> {} ({})", ip, location, region.display_name());
    Some((region, location))
}

/// Map a Roblox game server IP to its geographic region.
///
/// Uses hard-coded /24 subnet mappings based on Roblox's AS22697 infrastructure.
/// Primary source: BTRoblox extension (most widely-used, community-validated).
/// Cross-referenced with ipinfo.io geolocation and DevForum posts.
///
/// Sources:
/// - BTRoblox extension (background.js) - complete 0-127 octet mapping
/// - https://devforum.roblox.com/t/roblox-server-region-a-list-of-roblox-ip-ranges/3094401
/// - ipinfo.io AS22697 geolocation lookups
pub fn roblox_ip_to_region(ip: Ipv4Addr) -> RobloxRegion {
    let octets = ip.octets();

    // Only 128.116.0.0/17 contains regional game servers
    if octets[0] != 128 || octets[1] != 116 {
        return RobloxRegion::Unknown;
    }

    // Map by third octet (/24 blocks)
    match octets[2] {
        // ── Asia-Pacific ──────────────────────────────────────────────
        50 | 79 | 97 => RobloxRegion::Singapore,
        6 | 55 | 58 | 59 | 60 | 82 | 83 | 120 => RobloxRegion::Tokyo,
        7 | 9 | 104 => RobloxRegion::Mumbai,
        51 => RobloxRegion::Sydney,

        // ── Europe ────────────────────────────────────────────────────
        33 | 35 | 36 | 72 | 73 | 89 | 119 => RobloxRegion::London,
        13 | 21 | 54 | 121 => RobloxRegion::Amsterdam,
        4 | 19 | 20 | 26 | 122 => RobloxRegion::Paris,
        5 | 8 | 39 | 40 | 41 | 42 | 43 | 44 | 123 => RobloxRegion::Frankfurt,
        2 | 3 | 31 | 124 => RobloxRegion::Warsaw,

        // ── US East ──────────────────────────────────────────────────
        // Ashburn / Virginia
        10 | 11 | 52 | 53 | 56 | 70 | 71 | 74 | 75 | 76 | 77 | 78
        | 80 | 87 | 96 | 102 | 114 => RobloxRegion::UsEast,
        // NYC / Secaucus NJ
        15 | 16 | 17 | 23 | 32 | 65 | 66 | 126 => RobloxRegion::UsEast,
        // Atlanta
        22 | 24 | 25 | 99 => RobloxRegion::UsEast,
        // Miami
        18 | 37 | 38 | 45 | 85 | 127 => RobloxRegion::UsEast,

        // ── US Central ───────────────────────────────────────────────
        // Chicago / Elk Grove Village
        27 | 28 | 29 | 34 | 46 | 47 | 48 | 84 | 88 | 101 | 112 | 113
            => RobloxRegion::UsCentral,
        // Dallas
        95 => RobloxRegion::UsCentral,

        // ── US West ──────────────────────────────────────────────────
        // Los Angeles
        1 | 49 | 63 | 116 => RobloxRegion::UsWest,
        // Seattle
        62 | 115 => RobloxRegion::UsWest,
        // San Jose / Santa Clara
        57 | 67 | 68 | 69 | 81 | 105 | 117 => RobloxRegion::UsWest,
        // San Mateo (Roblox HQ area - may be infra but in Bay Area)
        12 | 61 | 64 | 86 | 90 | 91 | 92 | 93 | 94 | 98 | 100 | 103
        | 106 | 107 | 108 | 109 | 110 | 111 | 125 => RobloxRegion::UsWest,

        _ => RobloxRegion::Unknown,
    }
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

    #[test]
    fn test_roblox_ip_to_region_singapore() {
        assert_eq!(roblox_ip_to_region(Ipv4Addr::new(128, 116, 50, 100)), RobloxRegion::Singapore);
        assert_eq!(roblox_ip_to_region(Ipv4Addr::new(128, 116, 79, 50)), RobloxRegion::Singapore);
        assert_eq!(roblox_ip_to_region(Ipv4Addr::new(128, 116, 97, 50)), RobloxRegion::Singapore);
    }

    #[test]
    fn test_roblox_ip_to_region_tokyo() {
        assert_eq!(roblox_ip_to_region(Ipv4Addr::new(128, 116, 6, 1)), RobloxRegion::Tokyo);
        assert_eq!(roblox_ip_to_region(Ipv4Addr::new(128, 116, 55, 1)), RobloxRegion::Tokyo);
        assert_eq!(roblox_ip_to_region(Ipv4Addr::new(128, 116, 82, 1)), RobloxRegion::Tokyo);
        assert_eq!(roblox_ip_to_region(Ipv4Addr::new(128, 116, 120, 1)), RobloxRegion::Tokyo);
    }

    #[test]
    fn test_roblox_ip_to_region_europe() {
        // London
        assert_eq!(roblox_ip_to_region(Ipv4Addr::new(128, 116, 33, 1)), RobloxRegion::London);
        assert_eq!(roblox_ip_to_region(Ipv4Addr::new(128, 116, 35, 1)), RobloxRegion::London);
        assert_eq!(roblox_ip_to_region(Ipv4Addr::new(128, 116, 119, 1)), RobloxRegion::London);
        // Amsterdam
        assert_eq!(roblox_ip_to_region(Ipv4Addr::new(128, 116, 21, 1)), RobloxRegion::Amsterdam);
        assert_eq!(roblox_ip_to_region(Ipv4Addr::new(128, 116, 54, 1)), RobloxRegion::Amsterdam);
        // Frankfurt
        assert_eq!(roblox_ip_to_region(Ipv4Addr::new(128, 116, 5, 1)), RobloxRegion::Frankfurt);
        assert_eq!(roblox_ip_to_region(Ipv4Addr::new(128, 116, 44, 1)), RobloxRegion::Frankfurt);
        // Warsaw
        assert_eq!(roblox_ip_to_region(Ipv4Addr::new(128, 116, 31, 1)), RobloxRegion::Warsaw);
        assert_eq!(roblox_ip_to_region(Ipv4Addr::new(128, 116, 124, 1)), RobloxRegion::Warsaw);
    }

    #[test]
    fn test_roblox_ip_to_region_us_east() {
        // Ashburn
        assert_eq!(roblox_ip_to_region(Ipv4Addr::new(128, 116, 102, 1)), RobloxRegion::UsEast);
        assert_eq!(roblox_ip_to_region(Ipv4Addr::new(128, 116, 80, 1)), RobloxRegion::UsEast);
        // NYC
        assert_eq!(roblox_ip_to_region(Ipv4Addr::new(128, 116, 32, 200)), RobloxRegion::UsEast);
        assert_eq!(roblox_ip_to_region(Ipv4Addr::new(128, 116, 65, 1)), RobloxRegion::UsEast);
        // Atlanta
        assert_eq!(roblox_ip_to_region(Ipv4Addr::new(128, 116, 22, 1)), RobloxRegion::UsEast);
        // Miami
        assert_eq!(roblox_ip_to_region(Ipv4Addr::new(128, 116, 45, 1)), RobloxRegion::UsEast);
        assert_eq!(roblox_ip_to_region(Ipv4Addr::new(128, 116, 127, 1)), RobloxRegion::UsEast);
    }

    #[test]
    fn test_roblox_ip_to_region_us_central() {
        // Chicago
        assert_eq!(roblox_ip_to_region(Ipv4Addr::new(128, 116, 48, 1)), RobloxRegion::UsCentral);
        assert_eq!(roblox_ip_to_region(Ipv4Addr::new(128, 116, 101, 1)), RobloxRegion::UsCentral);
        assert_eq!(roblox_ip_to_region(Ipv4Addr::new(128, 116, 84, 1)), RobloxRegion::UsCentral);
        // Dallas
        assert_eq!(roblox_ip_to_region(Ipv4Addr::new(128, 116, 95, 1)), RobloxRegion::UsCentral);
    }

    #[test]
    fn test_roblox_ip_to_region_us_west() {
        // LA
        assert_eq!(roblox_ip_to_region(Ipv4Addr::new(128, 116, 1, 1)), RobloxRegion::UsWest);
        assert_eq!(roblox_ip_to_region(Ipv4Addr::new(128, 116, 63, 1)), RobloxRegion::UsWest);
        // Seattle
        assert_eq!(roblox_ip_to_region(Ipv4Addr::new(128, 116, 115, 1)), RobloxRegion::UsWest);
        // San Jose
        assert_eq!(roblox_ip_to_region(Ipv4Addr::new(128, 116, 57, 1)), RobloxRegion::UsWest);
        assert_eq!(roblox_ip_to_region(Ipv4Addr::new(128, 116, 105, 1)), RobloxRegion::UsWest);
    }

    #[test]
    fn test_roblox_ip_to_region_unknown() {
        assert_eq!(roblox_ip_to_region(Ipv4Addr::new(1, 1, 1, 1)), RobloxRegion::Unknown);
        assert_eq!(roblox_ip_to_region(Ipv4Addr::new(128, 116, 200, 1)), RobloxRegion::Unknown);
        // Decommissioned Hong Kong ranges → Unknown
        assert_eq!(roblox_ip_to_region(Ipv4Addr::new(128, 116, 0, 1)), RobloxRegion::Unknown);
        assert_eq!(roblox_ip_to_region(Ipv4Addr::new(128, 116, 14, 1)), RobloxRegion::Unknown);
    }

    #[test]
    fn test_roblox_region_best_swifttunnel() {
        assert_eq!(RobloxRegion::Singapore.best_swifttunnel_region(), Some("singapore"));
        assert_eq!(RobloxRegion::UsEast.best_swifttunnel_region(), Some("america"));
        assert_eq!(RobloxRegion::Frankfurt.best_swifttunnel_region(), Some("germany"));
        assert_eq!(RobloxRegion::Unknown.best_swifttunnel_region(), None);
    }
}
