//! IP Geolocation module
//!
//! Uses the SwiftTunnel web resolver for region lookup. The resolver keeps the
//! IPinfo token server-side, caches provider responses, and applies central
//! overrides. Auto-routing only switches relays when the resolver returns a
//! structured Roblox or SwiftTunnel region id.

use parking_lot::Mutex;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::net::Ipv4Addr;
use std::sync::Arc;
use tokio::sync::Semaphore;

const GAME_SERVER_REGION_API_URL: &str = "https://www.swifttunnel.net/api/vpn/game-server-region";

/// Shared HTTP client with a short timeout for geolocation lookups
fn geo_http_client() -> &'static reqwest::Client {
    static CLIENT: std::sync::OnceLock<reqwest::Client> = std::sync::OnceLock::new();
    CLIENT.get_or_init(|| {
        reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(2))
            .build()
            .expect("Failed to build geolocation HTTP client")
    })
}

/// Semaphore to limit concurrent API requests
static API_SEMAPHORE: std::sync::OnceLock<Semaphore> = std::sync::OnceLock::new();

fn get_semaphore() -> &'static Semaphore {
    API_SEMAPHORE.get_or_init(|| Semaphore::new(2))
}

/// Cache of resolved game-server regions. A region maps to a fixed Roblox data
/// center, so a resolved IP→region answer is stable — caching it avoids
/// re-hitting the web resolver for the same server across reconnects. The
/// resolver already caches server-side, but every client call still costs a
/// backend request (and counts toward hosting limits), so this trims real load.
const REGION_CACHE_TTL: std::time::Duration = std::time::Duration::from_secs(6 * 3600);
const REGION_CACHE_MAX_ENTRIES: usize = 4096;
/// Cached region lookups keyed by game-server IP, with the time each was
/// resolved so entries can age out.
type RegionCache = Arc<Mutex<HashMap<Ipv4Addr, (GameServerRegionLookup, std::time::Instant)>>>;

static REGION_CACHE: std::sync::OnceLock<RegionCache> = std::sync::OnceLock::new();

fn get_region_cache() -> Arc<Mutex<HashMap<Ipv4Addr, (GameServerRegionLookup, std::time::Instant)>>>
{
    REGION_CACHE
        .get_or_init(|| Arc::new(Mutex::new(HashMap::new())))
        .clone()
}

#[derive(Debug, Serialize)]
struct GameServerRegionRequest {
    ip: String,
}

#[derive(Debug, Deserialize, Clone)]
struct GameServerRegionLocation {
    city: Option<String>,
    region: Option<String>,
    country: Option<String>,
    #[allow(dead_code)]
    loc: Option<String>,
}

#[derive(Debug, Deserialize, Clone)]
struct GameServerRegionResponse {
    provider: Option<String>,
    location: Option<GameServerRegionLocation>,
    roblox_region_id: Option<String>,
    swifttunnel_region_id: Option<String>,
    confidence: Option<String>,
}

fn format_api_location(location: &GameServerRegionLocation) -> Option<String> {
    let city = location.city.as_ref()?;
    let country = location.country.as_ref()?;

    if let Some(region) = &location.region {
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

    // Roblox regional game-server IP ranges (network, mask).
    //
    // Keep this list scoped to game-server ranges only. Roblox-owned API,
    // matchmaking, and infrastructure CIDRs also resolve through IPinfo, but
    // they are not valid auto-routing signals and can pull an in-game session
    // toward San Mateo/US West when contacted mid-session.
    const ROBLOX_RANGES: &[(u32, u32)] = &[
        // Primary game servers (all regions)
        (0x80740000, 0xFFFF8000), // 128.116.0.0/17
        // Secondary (San Jose)
        (0xD1CE2800, 0xFFFFF800), // 209.206.40.0/21
        // Asia-Pacific
        (0x678C1C00, 0xFFFFFE00), // 103.140.28.0/23
        // China (Luobu)
        (0x678EDC00, 0xFFFFFE00), // 103.142.220.0/23
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
    Jakarta,
    TelAviv,
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
            RobloxRegion::Jakarta,
            RobloxRegion::TelAviv,
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
            RobloxRegion::Jakarta => Some("jakarta"),
            RobloxRegion::TelAviv => Some("israel"),
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
            RobloxRegion::Jakarta => "Jakarta",
            RobloxRegion::TelAviv => "Tel Aviv",
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

fn roblox_region_from_id(id: &str) -> Option<RobloxRegion> {
    match id {
        "singapore" => Some(RobloxRegion::Singapore),
        "tokyo" => Some(RobloxRegion::Tokyo),
        "mumbai" => Some(RobloxRegion::Mumbai),
        "sydney" => Some(RobloxRegion::Sydney),
        "london" => Some(RobloxRegion::London),
        "amsterdam" => Some(RobloxRegion::Amsterdam),
        "paris" => Some(RobloxRegion::Paris),
        "frankfurt" => Some(RobloxRegion::Frankfurt),
        "warsaw" => Some(RobloxRegion::Warsaw),
        "us-east" => Some(RobloxRegion::UsEast),
        "us-central" => Some(RobloxRegion::UsCentral),
        "us-west" => Some(RobloxRegion::UsWest),
        "brazil" => Some(RobloxRegion::Brazil),
        _ => None,
    }
}

fn roblox_region_from_swifttunnel_region_id(id: &str) -> Option<RobloxRegion> {
    match id {
        "germany" => Some(RobloxRegion::Frankfurt),
        other => roblox_region_from_id(other),
    }
}

async fn resolve_game_server_region_from_api(ip: Ipv4Addr) -> Option<GameServerRegionResponse> {
    let _permit = get_semaphore().acquire().await.ok()?;
    let client = geo_http_client();
    let response = client
        .post(GAME_SERVER_REGION_API_URL)
        .json(&GameServerRegionRequest { ip: ip.to_string() })
        .send()
        .await
        .ok()?;
    if !response.status().is_success() {
        log::warn!(
            "SwiftTunnel game-server resolver returned status {} for {}",
            response.status(),
            ip
        );
        return None;
    }
    crate::http_body::read_json_bounded(response, 64 * 1024, "server location")
        .await
        .ok()
}

fn resolve_api_response(
    ip: Ipv4Addr,
    response: Option<GameServerRegionResponse>,
) -> Option<(RobloxRegion, String)> {
    let response = match response {
        Some(response) => response,
        None => {
            log::warn!(
                "Geo lookup: SwiftTunnel resolver failed for {}; no region selected",
                ip
            );
            return None;
        }
    };

    let api_region = response
        .swifttunnel_region_id
        .as_deref()
        .and_then(roblox_region_from_swifttunnel_region_id)
        .or_else(|| {
            response
                .roblox_region_id
                .as_deref()
                .and_then(roblox_region_from_id)
        });
    let location = response
        .location
        .as_ref()
        .and_then(format_api_location)
        .or_else(|| api_region.as_ref().map(|r| r.display_name().to_string()))
        .unwrap_or_else(|| "Unknown".to_string());
    let confidence = response.confidence.as_deref().unwrap_or("unknown");

    if let Some(region) = api_region {
        log::info!(
            "Geo lookup: {} -> {} ({}) [SwiftTunnel resolver: provider={:?}, confidence={}, swifttunnel_region={:?}]",
            ip,
            location,
            region.display_name(),
            response.provider,
            confidence,
            response.swifttunnel_region_id
        );
        return Some((region, location));
    }

    log::warn!(
        "Geo lookup: SwiftTunnel resolver returned no usable region for {} [location={}, provider={:?}, confidence={}, roblox_region={:?}, swifttunnel_region={:?}]",
        ip,
        location,
        response.provider,
        confidence,
        response.roblox_region_id,
        response.swifttunnel_region_id
    );
    None
}

/// Outcome of a game-server region lookup, split so callers can tell a
/// retryable transport failure apart from a definitive "resolver answered
/// but cannot classify this IP" (retrying the latter won't help — the
/// resolver caches its answer).
#[derive(Debug, Clone, PartialEq)]
pub enum GameServerRegionLookup {
    /// Resolver returned a recognized structured region id.
    Resolved(RobloxRegion, String),
    /// Resolver answered, but without a usable structured region id.
    /// Diagnostic-only: not a retry target.
    NoRegion,
    /// Transport-level failure (timeout, connection error, non-2xx, bad
    /// body). Retryable.
    Failed,
}

/// Look up a game server IP's region.
///
/// Uses the SwiftTunnel web resolver. The resolver is IPinfo-primary and owns
/// the provider token/cache/overrides. Auto-routing only receives a region when
/// the resolver returns a recognized structured region id.
pub async fn lookup_game_server_region(ip: Ipv4Addr) -> GameServerRegionLookup {
    if let Some(game) = crate::vpn::game_destination::details(ip)
        && let Some(location) = game.location
    {
        return GameServerRegionLookup::Resolved(
            game.region.unwrap_or(RobloxRegion::Unknown),
            location,
        );
    }
    // Serve a fresh cached answer if we have one — regions are stable, so this
    // avoids re-resolving the same server on reconnects/new sessions.
    {
        let cache = get_region_cache();
        let guard = cache.lock();
        if let Some((cached, at)) = guard.get(&ip)
            && at.elapsed() < REGION_CACHE_TTL
        {
            return cached.clone();
        }
    }

    let result = match resolve_game_server_region_from_api(ip).await {
        None => GameServerRegionLookup::Failed,
        Some(response) => match resolve_api_response(ip, Some(response)) {
            Some((region, location)) => GameServerRegionLookup::Resolved(region, location),
            None => GameServerRegionLookup::NoRegion,
        },
    };

    // Cache definitive answers only; a transport-level Failed is worth retrying,
    // so it is never cached.
    if !matches!(result, GameServerRegionLookup::Failed) {
        let cache = get_region_cache();
        let mut guard = cache.lock();
        if guard.len() >= REGION_CACHE_MAX_ENTRIES {
            guard.clear();
        }
        guard.insert(ip, (result.clone(), std::time::Instant::now()));
    }

    result
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_is_roblox_game_server() {
        // Should match - in Roblox range
        assert!(is_roblox_game_server_ip(Ipv4Addr::new(128, 116, 50, 100)));
        assert!(is_roblox_game_server_ip(Ipv4Addr::new(209, 206, 42, 10)));
        assert!(is_roblox_game_server_ip(Ipv4Addr::new(103, 140, 28, 10)));

        // Should not match - outside game-server ranges
        assert!(!is_roblox_game_server_ip(Ipv4Addr::new(1, 1, 1, 1)));
        assert!(!is_roblox_game_server_ip(Ipv4Addr::new(8, 8, 8, 8)));
        assert!(!is_roblox_game_server_ip(Ipv4Addr::new(23, 173, 192, 10)));
        assert!(!is_roblox_game_server_ip(Ipv4Addr::new(204, 9, 184, 10)));
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

    #[test]
    fn test_resolver_response_returns_structured_region_when_confident() {
        let response = GameServerRegionResponse {
            provider: Some("ipinfo".to_string()),
            location: Some(GameServerRegionLocation {
                city: Some("Tokyo".to_string()),
                region: Some("Tokyo".to_string()),
                country: Some("JP".to_string()),
                loc: None,
            }),
            roblox_region_id: Some("tokyo".to_string()),
            swifttunnel_region_id: Some("tokyo".to_string()),
            confidence: Some("high".to_string()),
        };

        let resolved = resolve_api_response(Ipv4Addr::new(128, 116, 50, 10), Some(response));
        assert_eq!(
            resolved,
            Some((RobloxRegion::Tokyo, "Tokyo, JP".to_string()))
        );
    }

    #[test]
    fn test_resolver_swifttunnel_region_id_takes_precedence() {
        let response = GameServerRegionResponse {
            provider: Some("manual_override".to_string()),
            location: Some(GameServerRegionLocation {
                city: Some("Dallas".to_string()),
                region: Some("Texas".to_string()),
                country: Some("US".to_string()),
                loc: None,
            }),
            roblox_region_id: Some("us-east".to_string()),
            swifttunnel_region_id: Some("us-central".to_string()),
            confidence: Some("high".to_string()),
        };

        let resolved = resolve_api_response(Ipv4Addr::new(128, 116, 102, 10), Some(response));
        assert_eq!(
            resolved,
            Some((RobloxRegion::UsCentral, "Dallas, Texas, US".to_string()))
        );
    }

    #[test]
    fn test_low_confidence_resolver_uses_structured_region_without_local_override() {
        let response = GameServerRegionResponse {
            provider: Some("ipinfo".to_string()),
            location: Some(GameServerRegionLocation {
                city: None,
                region: None,
                country: Some("US".to_string()),
                loc: None,
            }),
            roblox_region_id: Some("us-east".to_string()),
            swifttunnel_region_id: Some("us-east".to_string()),
            confidence: Some("low".to_string()),
        };

        let resolved = resolve_api_response(Ipv4Addr::new(128, 116, 55, 10), Some(response));
        assert_eq!(
            resolved,
            Some((RobloxRegion::UsEast, "US East".to_string()))
        );
    }

    #[test]
    fn test_resolver_failure_returns_none_without_local_fallback() {
        let resolved = resolve_api_response(Ipv4Addr::new(128, 116, 95, 10), None);
        assert_eq!(resolved, None);
    }

    #[test]
    fn test_resolver_response_without_structured_region_returns_none() {
        let response = GameServerRegionResponse {
            provider: Some("ipinfo".to_string()),
            location: Some(GameServerRegionLocation {
                city: Some("Dallas".to_string()),
                region: Some("Texas".to_string()),
                country: Some("US".to_string()),
                loc: None,
            }),
            roblox_region_id: None,
            swifttunnel_region_id: None,
            confidence: Some("high".to_string()),
        };

        let resolved = resolve_api_response(Ipv4Addr::new(128, 116, 95, 10), Some(response));
        assert_eq!(resolved, None);
    }
}
