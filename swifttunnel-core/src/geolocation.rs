//! IP Geolocation module
//!
//! Uses a hardcoded IP table (sourced from BTRoblox) as the primary region
//! lookup, with ipinfo.io as a fallback for unknown IPs. This two-tier
//! approach avoids the known inaccuracy of geo-IP services for Roblox's
//! 128.116.0.0/17 range (they often return Roblox's HQ city "San Mateo"
//! instead of the actual server location).

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
            .build()
            .expect("Failed to build geolocation HTTP client")
    })
}

/// Cache for server locations to avoid repeated API calls
static LOCATION_CACHE: std::sync::OnceLock<Arc<Mutex<HashMap<Ipv4Addr, String>>>> =
    std::sync::OnceLock::new();

/// Semaphore to limit concurrent API requests
static API_SEMAPHORE: std::sync::OnceLock<Semaphore> = std::sync::OnceLock::new();

fn get_cache() -> Arc<Mutex<HashMap<Ipv4Addr, String>>> {
    LOCATION_CACHE
        .get_or_init(|| Arc::new(Mutex::new(HashMap::new())))
        .clone()
}

fn get_semaphore() -> &'static Semaphore {
    API_SEMAPHORE.get_or_init(|| Semaphore::new(2))
}

/// Response from ipinfo.io API
#[derive(Debug, Deserialize, Clone)]
pub struct IpInfoResponse {
    pub city: Option<String>,
    pub region: Option<String>,
    pub country: Option<String>,
    /// Latitude,Longitude string e.g. "37.3860,-122.0838"
    pub loc: Option<String>,
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
    UsEast,    // Ashburn, NYC, Atlanta, Miami
    UsCentral, // Chicago, Dallas
    UsWest,    // LA, Seattle
    Brazil,
    Unknown,
}

impl RobloxRegion {
    /// All game-server regions (excluding Unknown) for UI display
    pub fn all_regions() -> &'static [RobloxRegion] {
        &[
            RobloxRegion::Singapore,
            RobloxRegion::Tokyo,
            RobloxRegion::Mumbai,
            RobloxRegion::Sydney,
            RobloxRegion::London,
            RobloxRegion::Amsterdam,
            RobloxRegion::Paris,
            RobloxRegion::Frankfurt,
            RobloxRegion::Warsaw,
            RobloxRegion::UsEast,
            RobloxRegion::UsCentral,
            RobloxRegion::UsWest,
            RobloxRegion::Brazil,
        ]
    }

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
            RobloxRegion::Warsaw => Some("germany"), // Closest SwiftTunnel region
            RobloxRegion::UsEast => Some("us-east"),
            RobloxRegion::UsCentral => Some("us-central"),
            RobloxRegion::UsWest => Some("us-west"),
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

/// Determine Roblox game server region from an ipinfo.io response.
///
/// Uses a multi-tier fallback for US sub-region classification:
/// 1. City name matching (most specific)
/// 2. Coordinate-based longitude classification (from `loc` field)
/// 3. US state/region name matching (from `region` field)
/// 4. Default to UsEast (majority of Roblox US servers are East Coast)
///
/// For non-US countries, the country code alone determines the region.
pub fn ipinfo_to_roblox_region(info: &IpInfoResponse) -> RobloxRegion {
    let country = match info.country.as_deref() {
        Some(c) => c,
        None => return RobloxRegion::Unknown,
    };
    let city = info.city.as_deref().unwrap_or("");

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
        "US" => us_region_from_ipinfo(city, info),
        _ => RobloxRegion::Unknown,
    }
}

/// Classify a US IP into East/Central/West using a multi-tier fallback.
fn us_region_from_ipinfo(city: &str, info: &IpInfoResponse) -> RobloxRegion {
    // Tier 1: City name matching
    let city_lower = city.to_lowercase();

    // US Central cities
    if city_lower.contains("chicago")
        || city_lower.contains("elk grove")
        || city_lower.contains("dallas")
        || city_lower.contains("houston")
        || city_lower.contains("kansas city")
        || city_lower.contains("san antonio")
        || city_lower.contains("minneapolis")
        || city_lower.contains("columbus")
        || city_lower.contains("indianapolis")
        || city_lower.contains("nashville")
        || city_lower.contains("memphis")
        || city_lower.contains("st. louis")
        || city_lower.contains("omaha")
    {
        return RobloxRegion::UsCentral;
    }

    // US East cities
    if city_lower.contains("ashburn")
        || city_lower.contains("leesburg")
        || city_lower.contains("sterling")
        || city_lower.contains("reston")
        || city_lower.contains("manassas")
        || city_lower.contains("herndon")
        || city_lower.contains("chantilly")
        || city_lower.contains("dulles")
        || city_lower.contains("new york")
        || city_lower.contains("secaucus")
        || city_lower.contains("newark")
        || city_lower.contains("atlanta")
        || city_lower.contains("miami")
        || city_lower.contains("jacksonville")
        || city_lower.contains("fort lauderdale")
        || city_lower.contains("charlotte")
        || city_lower.contains("philadelphia")
        || city_lower.contains("washington")
        || city_lower.contains("boston")
        || city_lower.contains("tampa")
        || city_lower.contains("orlando")
    {
        return RobloxRegion::UsEast;
    }

    // US West cities (explicit match to avoid false-positive from default)
    if city_lower.contains("los angeles")
        || city_lower.contains("san jose")
        || city_lower.contains("santa clara")
        || city_lower.contains("san mateo")
        || city_lower.contains("fremont")
        || city_lower.contains("san francisco")
        || city_lower.contains("seattle")
        || city_lower.contains("portland")
        || city_lower.contains("boardman")
        || city_lower.contains("phoenix")
        || city_lower.contains("las vegas")
        || city_lower.contains("salt lake")
        || city_lower.contains("denver")
    {
        return RobloxRegion::UsWest;
    }

    // Tier 2: Coordinate-based classification using ipinfo `loc` field
    if let Some(region) = us_region_from_coordinates(info) {
        return region;
    }

    // Tier 3: US state/region name matching
    if let Some(state) = info.region.as_deref() {
        if let Some(region) = us_region_from_state(state) {
            return region;
        }
    }

    // Tier 4: Default to UsEast (majority of Roblox US servers are East Coast)
    log::warn!(
        "ipinfo US region fallback: city={:?}, region={:?}, loc={:?} — defaulting to UsEast",
        info.city,
        info.region,
        info.loc,
    );
    RobloxRegion::UsEast
}

/// Classify US sub-region from ipinfo.io `loc` field (lat,lon).
///
/// Longitude boundaries:
/// - East: longitude >= -82 (east of roughly Atlanta/Pittsburgh)
/// - Central: longitude between -105 and -82
/// - West: longitude < -105
fn us_region_from_coordinates(info: &IpInfoResponse) -> Option<RobloxRegion> {
    let loc = info.loc.as_deref()?;
    let mut parts = loc.split(',');
    let _lat: f64 = parts.next()?.trim().parse().ok()?;
    let lon: f64 = parts.next()?.trim().parse().ok()?;

    Some(if lon >= -82.0 {
        RobloxRegion::UsEast
    } else if lon >= -105.0 {
        RobloxRegion::UsCentral
    } else {
        RobloxRegion::UsWest
    })
}

/// Classify US sub-region from ipinfo.io `region` field (US state name).
fn us_region_from_state(state: &str) -> Option<RobloxRegion> {
    match state {
        // East Coast
        "Virginia"
        | "New York"
        | "New Jersey"
        | "Georgia"
        | "Florida"
        | "Pennsylvania"
        | "Massachusetts"
        | "Maryland"
        | "Connecticut"
        | "Delaware"
        | "District of Columbia"
        | "Maine"
        | "New Hampshire"
        | "North Carolina"
        | "South Carolina"
        | "Rhode Island"
        | "Vermont"
        | "West Virginia" => Some(RobloxRegion::UsEast),

        // Central
        "Illinois" | "Texas" | "Ohio" | "Indiana" | "Tennessee" | "Minnesota" | "Missouri"
        | "Iowa" | "Kansas" | "Nebraska" | "Oklahoma" | "Wisconsin" | "Michigan" | "Arkansas"
        | "Louisiana" | "Mississippi" | "Alabama" | "Kentucky" | "North Dakota"
        | "South Dakota" => Some(RobloxRegion::UsCentral),

        // West Coast
        "California" | "Washington" | "Oregon" | "Arizona" | "Nevada" | "Utah" | "Colorado"
        | "Idaho" | "Montana" | "Wyoming" | "New Mexico" | "Hawaii" | "Alaska" => {
            Some(RobloxRegion::UsWest)
        }

        _ => None,
    }
}

/// Look up a game server IP's region.
///
/// Uses a two-tier strategy:
/// 1. **Hardcoded IP table** (from BTRoblox verified data) — instant, no network.
///    Used as the primary source for 128.116.x.x IPs with known /24 mappings.
/// 2. **ipinfo.io API** — fallback for unknown IPs or for the display location string.
///
/// Returns `(RobloxRegion, location_string)` where location_string is like "Singapore, SG".
pub async fn lookup_game_server_region(ip: Ipv4Addr) -> Option<(RobloxRegion, String)> {
    // Tier 1: Try hardcoded IP table first (instant, no network needed)
    let ip_table_region = roblox_ip_to_region(ip);

    if ip_table_region != RobloxRegion::Unknown {
        // We have a verified region from the IP table. Still fetch ipinfo for the
        // display location string, but don't block on it for the region decision.
        let location = match fetch_ipinfo(ip).await {
            Some(info) => {
                // Log if ipinfo disagrees with the IP table (helps detect stale entries)
                let ipinfo_region = ipinfo_to_roblox_region(&info);
                if ipinfo_region != RobloxRegion::Unknown && ipinfo_region != ip_table_region {
                    log::warn!(
                        "Region disagreement for {}: IP table={}, ipinfo={} (city={:?}, country={:?})",
                        ip,
                        ip_table_region.display_name(),
                        ipinfo_region.display_name(),
                        info.city,
                        info.country,
                    );
                }
                format_location(&info).unwrap_or_else(|| ip_table_region.display_name().to_string())
            }
            None => {
                // ipinfo unavailable — use region display name as location
                ip_table_region.display_name().to_string()
            }
        };

        log::info!(
            "Geo lookup: {} -> {} ({}) [IP table]",
            ip,
            location,
            ip_table_region.display_name()
        );
        return Some((ip_table_region, location));
    }

    // Tier 2: IP not in hardcoded table — fall back to ipinfo.io
    let info = fetch_ipinfo(ip).await?;
    let location = format_location(&info)?;
    let region = ipinfo_to_roblox_region(&info);

    log::info!(
        "Geo lookup: {} -> {} ({}) [ipinfo fallback]",
        ip,
        location,
        region.display_name()
    );
    Some((region, location))
}

/// Fetch ipinfo.io data for an IP, using the cache and semaphore.
async fn fetch_ipinfo(ip: Ipv4Addr) -> Option<IpInfoResponse> {
    let _permit = get_semaphore().acquire().await.ok()?;

    // Check cache for a previously fetched location string
    let cached_location = {
        let cache = get_cache();
        cache.lock().ok().and_then(|c| c.get(&ip).cloned())
    };

    if let Some(loc) = cached_location {
        // Parse cached "City, Country" or "City, Region, Country" string back
        let parts: Vec<&str> = loc.split(", ").collect();
        let city = parts.first().unwrap_or(&"").to_string();
        let region = if parts.len() == 3 {
            Some(parts[1].to_string())
        } else {
            None
        };
        let country = parts.last().unwrap_or(&"").to_string();
        return Some(IpInfoResponse {
            city: Some(city),
            region,
            country: Some(country),
            loc: None, // not available from cache
        });
    }

    let url = format!("https://ipinfo.io/{}/json", ip);
    let client = geo_http_client();
    let response = client.get(&url).send().await.ok()?;
    if !response.status().is_success() {
        log::warn!("ipinfo.io returned status {} for {}", response.status(), ip);
        return None;
    }
    let info: IpInfoResponse = response.json().await.ok()?;

    // Cache the formatted location string
    if let Some(location) = format_location(&info) {
        if let Ok(mut cache) = get_cache().lock() {
            cache.insert(ip, location);
        }
    }

    Some(info)
}

/// Map a Roblox game server IP to its geographic region.
///
/// Uses hard-coded /24 subnet mappings based on BTRoblox's verified
/// `serverRegionsByIp` table (the most widely-used, community-validated source).
///
/// Only includes octets that BTRoblox has explicitly verified. Unverified octets
/// return `Unknown` to avoid silent misrouting — the caller should fall back to
/// ipinfo.io for those IPs.
///
/// Sources:
/// - BTRoblox extension (js/feat/serverdetails.js) `serverRegionsByIp`
/// - https://devforum.roblox.com/t/roblox-server-region-a-list-of-roblox-ip-ranges/3094401
pub fn roblox_ip_to_region(ip: Ipv4Addr) -> RobloxRegion {
    let octets = ip.octets();

    // Only 128.116.0.0/17 contains regional game servers
    if octets[0] != 128 || octets[1] != 116 {
        return RobloxRegion::Unknown;
    }

    // Map by third octet (/24 blocks) — BTRoblox verified entries only
    match octets[2] {
        // ── Asia-Pacific ──────────────────────────────────────────────
        46 | 50 | 54 | 97 => RobloxRegion::Singapore,
        55 | 120 => RobloxRegion::Tokyo,
        104 => RobloxRegion::Mumbai,
        51 => RobloxRegion::Sydney,

        // ── Europe ────────────────────────────────────────────────────
        33 | 35 | 119 => RobloxRegion::London,
        21 => RobloxRegion::Amsterdam,
        13 => RobloxRegion::Paris,
        5 | 44 | 123 => RobloxRegion::Frankfurt,

        // ── Americas ──────────────────────────────────────────────────
        86 => RobloxRegion::Brazil,

        // US East (Ashburn, NYC, Atlanta, Miami)
        0 | 11 | 22 | 32 | 45 | 53 | 56 | 74 | 80 | 87 | 99 | 102 | 127 => RobloxRegion::UsEast,

        // US Central (Chicago, Dallas)
        48 | 84 | 88 | 95 => RobloxRegion::UsCentral,

        // US West (LA, Seattle, San Jose)
        1 | 57 | 63 | 67 | 81 | 105 | 115 | 116 | 117 => RobloxRegion::UsWest,

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
            loc: None,
        };
        assert_eq!(format_location(&info), Some("Singapore, SG".to_string()));

        // City differs from region
        let info = IpInfoResponse {
            city: Some("Ashburn".to_string()),
            region: Some("Virginia".to_string()),
            country: Some("US".to_string()),
            loc: None,
        };
        assert_eq!(
            format_location(&info),
            Some("Ashburn, Virginia, US".to_string())
        );
    }

    // ── roblox_ip_to_region tests (BTRoblox verified entries) ─────────

    #[test]
    fn test_roblox_ip_to_region_singapore() {
        assert_eq!(
            roblox_ip_to_region(Ipv4Addr::new(128, 116, 50, 100)),
            RobloxRegion::Singapore
        );
        assert_eq!(
            roblox_ip_to_region(Ipv4Addr::new(128, 116, 46, 1)),
            RobloxRegion::Singapore,
            "Octet 46 is Singapore per BTRoblox (was incorrectly UsCentral)"
        );
        assert_eq!(
            roblox_ip_to_region(Ipv4Addr::new(128, 116, 54, 1)),
            RobloxRegion::Singapore,
            "Octet 54 is Singapore per BTRoblox (was incorrectly Amsterdam)"
        );
        assert_eq!(
            roblox_ip_to_region(Ipv4Addr::new(128, 116, 97, 50)),
            RobloxRegion::Singapore
        );
    }

    #[test]
    fn test_roblox_ip_to_region_tokyo() {
        assert_eq!(
            roblox_ip_to_region(Ipv4Addr::new(128, 116, 55, 1)),
            RobloxRegion::Tokyo
        );
        assert_eq!(
            roblox_ip_to_region(Ipv4Addr::new(128, 116, 120, 1)),
            RobloxRegion::Tokyo
        );
    }

    #[test]
    fn test_roblox_ip_to_region_europe() {
        // London
        assert_eq!(
            roblox_ip_to_region(Ipv4Addr::new(128, 116, 33, 1)),
            RobloxRegion::London
        );
        assert_eq!(
            roblox_ip_to_region(Ipv4Addr::new(128, 116, 35, 1)),
            RobloxRegion::London
        );
        assert_eq!(
            roblox_ip_to_region(Ipv4Addr::new(128, 116, 119, 1)),
            RobloxRegion::London
        );
        // Amsterdam
        assert_eq!(
            roblox_ip_to_region(Ipv4Addr::new(128, 116, 21, 1)),
            RobloxRegion::Amsterdam
        );
        // Frankfurt
        assert_eq!(
            roblox_ip_to_region(Ipv4Addr::new(128, 116, 5, 1)),
            RobloxRegion::Frankfurt
        );
        assert_eq!(
            roblox_ip_to_region(Ipv4Addr::new(128, 116, 44, 1)),
            RobloxRegion::Frankfurt
        );
        assert_eq!(
            roblox_ip_to_region(Ipv4Addr::new(128, 116, 123, 1)),
            RobloxRegion::Frankfurt
        );
        // Paris
        assert_eq!(
            roblox_ip_to_region(Ipv4Addr::new(128, 116, 13, 1)),
            RobloxRegion::Paris
        );
    }

    #[test]
    fn test_roblox_ip_to_region_brazil() {
        assert_eq!(
            roblox_ip_to_region(Ipv4Addr::new(128, 116, 86, 1)),
            RobloxRegion::Brazil,
            "Octet 86 is São Paulo/Brazil per BTRoblox (was incorrectly UsWest)"
        );
    }

    #[test]
    fn test_roblox_ip_to_region_us_east() {
        // Ashburn
        assert_eq!(
            roblox_ip_to_region(Ipv4Addr::new(128, 116, 0, 1)),
            RobloxRegion::UsEast,
            "Octet 0 is Ashburn/UsEast per BTRoblox (was incorrectly Unknown)"
        );
        assert_eq!(
            roblox_ip_to_region(Ipv4Addr::new(128, 116, 102, 1)),
            RobloxRegion::UsEast
        );
        assert_eq!(
            roblox_ip_to_region(Ipv4Addr::new(128, 116, 80, 1)),
            RobloxRegion::UsEast
        );
        // NYC
        assert_eq!(
            roblox_ip_to_region(Ipv4Addr::new(128, 116, 32, 200)),
            RobloxRegion::UsEast
        );
        // Atlanta
        assert_eq!(
            roblox_ip_to_region(Ipv4Addr::new(128, 116, 22, 1)),
            RobloxRegion::UsEast
        );
        // Miami
        assert_eq!(
            roblox_ip_to_region(Ipv4Addr::new(128, 116, 45, 1)),
            RobloxRegion::UsEast
        );
        assert_eq!(
            roblox_ip_to_region(Ipv4Addr::new(128, 116, 127, 1)),
            RobloxRegion::UsEast
        );
    }

    #[test]
    fn test_roblox_ip_to_region_us_central() {
        // Chicago
        assert_eq!(
            roblox_ip_to_region(Ipv4Addr::new(128, 116, 48, 1)),
            RobloxRegion::UsCentral
        );
        assert_eq!(
            roblox_ip_to_region(Ipv4Addr::new(128, 116, 84, 1)),
            RobloxRegion::UsCentral
        );
        // Dallas
        assert_eq!(
            roblox_ip_to_region(Ipv4Addr::new(128, 116, 95, 1)),
            RobloxRegion::UsCentral
        );
    }

    #[test]
    fn test_roblox_ip_to_region_us_west() {
        // LA
        assert_eq!(
            roblox_ip_to_region(Ipv4Addr::new(128, 116, 1, 1)),
            RobloxRegion::UsWest
        );
        assert_eq!(
            roblox_ip_to_region(Ipv4Addr::new(128, 116, 63, 1)),
            RobloxRegion::UsWest
        );
        // Seattle
        assert_eq!(
            roblox_ip_to_region(Ipv4Addr::new(128, 116, 115, 1)),
            RobloxRegion::UsWest
        );
        // San Jose
        assert_eq!(
            roblox_ip_to_region(Ipv4Addr::new(128, 116, 57, 1)),
            RobloxRegion::UsWest
        );
        assert_eq!(
            roblox_ip_to_region(Ipv4Addr::new(128, 116, 105, 1)),
            RobloxRegion::UsWest
        );
    }

    #[test]
    fn test_roblox_ip_to_region_unknown_for_unverified_octets() {
        // Non-Roblox IPs
        assert_eq!(
            roblox_ip_to_region(Ipv4Addr::new(1, 1, 1, 1)),
            RobloxRegion::Unknown
        );
        // Above /17 range
        assert_eq!(
            roblox_ip_to_region(Ipv4Addr::new(128, 116, 200, 1)),
            RobloxRegion::Unknown
        );
        // Unverified octets within /17 (not in BTRoblox table) → Unknown
        assert_eq!(
            roblox_ip_to_region(Ipv4Addr::new(128, 116, 14, 1)),
            RobloxRegion::Unknown
        );
        assert_eq!(
            roblox_ip_to_region(Ipv4Addr::new(128, 116, 30, 1)),
            RobloxRegion::Unknown,
            "Octets not in BTRoblox should return Unknown"
        );
    }

    #[test]
    fn test_roblox_region_best_swifttunnel() {
        assert_eq!(
            RobloxRegion::Singapore.best_swifttunnel_region(),
            Some("singapore")
        );
        assert_eq!(
            RobloxRegion::UsEast.best_swifttunnel_region(),
            Some("us-east")
        );
        assert_eq!(
            RobloxRegion::UsCentral.best_swifttunnel_region(),
            Some("us-central")
        );
        assert_eq!(
            RobloxRegion::UsWest.best_swifttunnel_region(),
            Some("us-west")
        );
        assert_eq!(
            RobloxRegion::Frankfurt.best_swifttunnel_region(),
            Some("germany")
        );
        assert_eq!(RobloxRegion::Unknown.best_swifttunnel_region(), None);
    }

    // ── ipinfo_to_roblox_region tests ─────────────────────────────────

    fn make_ipinfo(city: &str, region: &str, country: &str, loc: Option<&str>) -> IpInfoResponse {
        IpInfoResponse {
            city: Some(city.to_string()),
            region: Some(region.to_string()),
            country: Some(country.to_string()),
            loc: loc.map(|s| s.to_string()),
        }
    }

    #[test]
    fn test_ipinfo_non_us_countries() {
        assert_eq!(
            ipinfo_to_roblox_region(&make_ipinfo("Singapore", "Singapore", "SG", None)),
            RobloxRegion::Singapore
        );
        assert_eq!(
            ipinfo_to_roblox_region(&make_ipinfo("Tokyo", "Tokyo", "JP", None)),
            RobloxRegion::Tokyo
        );
        assert_eq!(
            ipinfo_to_roblox_region(&make_ipinfo("São Paulo", "São Paulo", "BR", None)),
            RobloxRegion::Brazil
        );
    }

    #[test]
    fn test_ipinfo_us_city_matching() {
        // Known US East cities
        assert_eq!(
            ipinfo_to_roblox_region(&make_ipinfo("Ashburn", "Virginia", "US", None)),
            RobloxRegion::UsEast
        );
        assert_eq!(
            ipinfo_to_roblox_region(&make_ipinfo("Manassas", "Virginia", "US", None)),
            RobloxRegion::UsEast,
            "Manassas should match UsEast (new city)"
        );
        assert_eq!(
            ipinfo_to_roblox_region(&make_ipinfo("Atlanta", "Georgia", "US", None)),
            RobloxRegion::UsEast
        );

        // Known US Central cities
        assert_eq!(
            ipinfo_to_roblox_region(&make_ipinfo("Chicago", "Illinois", "US", None)),
            RobloxRegion::UsCentral
        );
        assert_eq!(
            ipinfo_to_roblox_region(&make_ipinfo("Dallas", "Texas", "US", None)),
            RobloxRegion::UsCentral
        );

        // Known US West cities
        assert_eq!(
            ipinfo_to_roblox_region(&make_ipinfo("San Mateo", "California", "US", None)),
            RobloxRegion::UsWest,
            "San Mateo (Roblox HQ) should explicitly match UsWest"
        );
        assert_eq!(
            ipinfo_to_roblox_region(&make_ipinfo("Los Angeles", "California", "US", None)),
            RobloxRegion::UsWest
        );
    }

    #[test]
    fn test_ipinfo_us_coordinate_fallback() {
        // Unknown city, but coordinates place it in US East (Ashburn area, lon ~-77.5)
        assert_eq!(
            ipinfo_to_roblox_region(&make_ipinfo(
                "SomeUnknownCity",
                "Virginia",
                "US",
                Some("39.0438,-77.4874")
            )),
            RobloxRegion::UsEast
        );

        // Unknown city, coordinates in US Central (Chicago area, lon ~-87.6)
        assert_eq!(
            ipinfo_to_roblox_region(&make_ipinfo(
                "SomeUnknownCity",
                "Illinois",
                "US",
                Some("41.8781,-87.6298")
            )),
            RobloxRegion::UsCentral
        );

        // Unknown city, coordinates in US West (LA area, lon ~-118.2)
        assert_eq!(
            ipinfo_to_roblox_region(&make_ipinfo(
                "SomeUnknownCity",
                "California",
                "US",
                Some("34.0522,-118.2437")
            )),
            RobloxRegion::UsWest
        );
    }

    #[test]
    fn test_ipinfo_us_state_fallback() {
        // Unknown city, no coordinates, but state is known
        assert_eq!(
            ipinfo_to_roblox_region(&make_ipinfo("SomeCity", "Virginia", "US", None)),
            RobloxRegion::UsEast
        );
        assert_eq!(
            ipinfo_to_roblox_region(&make_ipinfo("SomeCity", "Illinois", "US", None)),
            RobloxRegion::UsCentral
        );
        assert_eq!(
            ipinfo_to_roblox_region(&make_ipinfo("SomeCity", "California", "US", None)),
            RobloxRegion::UsWest
        );
    }

    #[test]
    fn test_ipinfo_us_defaults_to_east() {
        // No city, no coordinates, unknown state → defaults to UsEast
        let info = IpInfoResponse {
            city: None,
            region: None,
            country: Some("US".to_string()),
            loc: None,
        };
        assert_eq!(
            ipinfo_to_roblox_region(&info),
            RobloxRegion::UsEast,
            "Default US should be UsEast, not UsWest"
        );
    }
}
