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
use std::sync::LazyLock;
use std::time::{Duration, Instant};
use tokio::sync::Semaphore;

const GAME_SERVER_REGION_API_URL: &str = "https://www.swifttunnel.net/api/vpn/game-server-region";

/// Shared HTTP client with a short timeout for geolocation lookups
fn geo_http_client() -> Result<&'static reqwest::Client, reqwest::Error> {
    static CLIENT: std::sync::OnceLock<reqwest::Client> = std::sync::OnceLock::new();
    crate::http_client::cached_client(&CLIENT, || {
        reqwest::Client::builder().timeout(std::time::Duration::from_secs(2))
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
const REGION_CACHE_TTL: Duration = Duration::from_secs(6 * 3600);
const REGION_CACHE_MAX_ENTRIES: usize = 4096;
const REGION_REQUEST_MAX_ENTRIES: usize = 32;
#[derive(Default)]
struct RegionCache {
    entries: HashMap<Ipv4Addr, (GameServerRegionLookup, Instant)>,
    requests: crate::http_client::RequestSlots<Ipv4Addr>,
}
impl RegionCache {
    fn get(&mut self, ip: Ipv4Addr, now: Instant) -> Option<GameServerRegionLookup> {
        match self.entries.get(&ip) {
            Some((value, at)) if now.saturating_duration_since(*at) < REGION_CACHE_TTL => {
                Some(value.clone())
            }
            Some(_) => {
                self.entries.remove(&ip);
                None
            }
            None => None,
        }
    }

    fn put(&mut self, ip: Ipv4Addr, result: GameServerRegionLookup, now: Instant) {
        if !matches!(result, GameServerRegionLookup::Failed) {
            self.entries
                .retain(|_, (_, at)| now.saturating_duration_since(*at) < REGION_CACHE_TTL);
            if self.entries.len() >= REGION_CACHE_MAX_ENTRIES
                && !self.entries.contains_key(&ip)
                && let Some(oldest) = self
                    .entries
                    .iter()
                    .min_by_key(|(_, (_, at))| *at)
                    .map(|(ip, _)| *ip)
            {
                self.entries.remove(&oldest);
            }
            self.entries.insert(ip, (result, now));
        }
    }
}
static REGION_CACHE: LazyLock<Mutex<RegionCache>> = LazyLock::new(Default::default);
static RESOLVER_COOLDOWN: Mutex<Option<Instant>> = Mutex::new(None);

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
    Doha,
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
            RobloxRegion::Doha,
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
            RobloxRegion::Doha => Some("middle-east"),
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
            RobloxRegion::Doha => "Doha",
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
    let client = match geo_http_client() {
        Ok(client) => client,
        Err(error) => {
            log::warn!("Could not initialize the game-server location client: {error}");
            return None;
        }
    };
    let response = resolver_response(
        &RESOLVER_COOLDOWN,
        client
            .post(GAME_SERVER_REGION_API_URL)
            .json(&GameServerRegionRequest { ip: ip.to_string() })
            .send(),
    )
    .await?;
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

async fn resolver_response(
    cooldown: &Mutex<Option<Instant>>,
    fetch: impl std::future::Future<Output = Result<reqwest::Response, reqwest::Error>>,
) -> Option<reqwest::Response> {
    // Checked after the HTTP concurrency permit, so queued addresses also
    // respect a retry window announced while they were waiting.
    if cooldown.lock().is_some_and(|until| until > Instant::now()) {
        return None;
    }
    let response = fetch.await.ok()?;
    if matches!(response.status().as_u16(), 429 | 503) {
        let delay = crate::http_client::retry_delay(response.headers());
        let deadline = Instant::now() + delay;
        let mut until = cooldown.lock();
        *until = Some(until.map_or(deadline, |previous| previous.max(deadline)));
        log::warn!(
            "Game-server resolver returned {}; pausing location requests for {} seconds",
            response.status(),
            delay.as_secs()
        );
        // Headers are sufficient. Do not read a possibly broken error body.
        return None;
    }
    Some(response)
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
    cached_region_lookup(&REGION_CACHE, ip, async {
        match resolve_game_server_region_from_api(ip).await {
            None => GameServerRegionLookup::Failed,
            Some(response) => match resolve_api_response(ip, Some(response)) {
                Some((region, location)) => GameServerRegionLookup::Resolved(region, location),
                None => GameServerRegionLookup::NoRegion,
            },
        }
    })
    .await
}

async fn cached_region_lookup(
    cache: &Mutex<RegionCache>,
    ip: Ipv4Addr,
    fetch: impl std::future::Future<Output = GameServerRegionLookup>,
) -> GameServerRegionLookup {
    let request = {
        let mut cache = cache.lock();
        if let Some(cached) = cache.get(ip, Instant::now()) {
            return cached;
        }
        let Some(request) = cache.requests.request(ip, REGION_REQUEST_MAX_ENTRIES) else {
            return GameServerRegionLookup::Failed;
        };
        request
    };
    // Hold this IP's ownership through response publication. Other addresses
    // retain the existing two-request HTTP concurrency; cancellation or a
    // transport failure must leave the address retryable.
    let _request = request.lock().await;
    if let Some(cached) = cache.lock().get(ip, Instant::now()) {
        return cached;
    }
    let result = fetch.await;
    cache.lock().put(ip, result.clone(), Instant::now());
    result
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn resolver_throttling_blocks_retries_and_other_ips_until_expiry() {
        use std::io::{Read, Write};
        for status in [429, 503, 400, 200] {
            let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
            let address = listener.local_addr().unwrap();
            let server = std::thread::spawn(move || {
                let (mut socket, _) = listener.accept().unwrap();
                socket
                    .set_read_timeout(Some(Duration::from_secs(2)))
                    .unwrap();
                assert!(socket.read(&mut [0; 4096]).unwrap() > 0);
                write!(socket, "HTTP/1.1 {status} Fixture\r\nRetry-After: 67\r\nContent-Length: 100000\r\nConnection: close\r\n\r\n").unwrap();
            });
            let cooldown = Mutex::new(None);
            let client = reqwest::Client::builder()
                .no_proxy()
                .timeout(Duration::from_secs(2))
                .build()
                .unwrap();
            let response =
                resolver_response(&cooldown, client.post(format!("http://{address}")).send()).await;
            server.join().unwrap();
            if matches!(status, 429 | 503) {
                assert!(response.is_none());
                let remaining = cooldown
                    .lock()
                    .unwrap()
                    .saturating_duration_since(Instant::now());
                assert!(remaining > Duration::from_secs(66));
                assert!(remaining <= Duration::from_secs(67));
                let blocked = resolver_response(&cooldown, async {
                    panic!("another caller or address must not send during cooldown")
                })
                .await;
                assert!(blocked.is_none());

                // Cached successful locations bypass HTTP admission entirely.
                let cache = Mutex::new(RegionCache::default());
                let ip = Ipv4Addr::new(128, 116, 47, 33);
                let resolved =
                    GameServerRegionLookup::Resolved(RobloxRegion::Mumbai, "Mumbai".into());
                cache.lock().put(ip, resolved.clone(), Instant::now());
                assert_eq!(
                    cached_region_lookup(&cache, ip, async {
                        let _ = resolver_response(&cooldown, async {
                            panic!("a cached location must not require a resolver request")
                        })
                        .await;
                        GameServerRegionLookup::Failed
                    })
                    .await,
                    resolved
                );

                *cooldown.lock() = Some(Instant::now() - Duration::from_secs(1));
                let polled = std::sync::atomic::AtomicBool::new(false);
                let invalid_request = client.get("://invalid").build().unwrap_err();
                let _ = resolver_response(&cooldown, async {
                    polled.store(true, std::sync::atomic::Ordering::Relaxed);
                    Err(invalid_request)
                })
                .await;
                assert!(polled.load(std::sync::atomic::Ordering::Relaxed));
            } else {
                assert_eq!(response.unwrap().status().as_u16(), status);
                assert!(cooldown.lock().is_none());
            }
        }
    }

    #[tokio::test]
    async fn cancelled_or_failed_region_requests_remain_retryable() {
        use std::sync::Arc;
        let cache = Arc::new(Mutex::new(RegionCache::default()));
        let started = Arc::new(tokio::sync::Notify::new());
        let ip = Ipv4Addr::new(128, 116, 47, 33);
        let owner_cache = cache.clone();
        let owner_started = started.clone();
        let owner = tokio::spawn(async move {
            cached_region_lookup(&owner_cache, ip, async {
                owner_started.notify_one();
                std::future::pending().await
            })
            .await
        });
        tokio::time::timeout(Duration::from_secs(2), started.notified())
            .await
            .unwrap();
        owner.abort();
        assert!(owner.await.unwrap_err().is_cancelled());
        assert_eq!(
            tokio::time::timeout(
                Duration::from_secs(2),
                cached_region_lookup(&cache, ip, async { GameServerRegionLookup::Failed })
            )
            .await
            .unwrap(),
            GameServerRegionLookup::Failed
        );
        assert!(cache.lock().entries.is_empty());
        assert_eq!(
            cached_region_lookup(&cache, ip, async { GameServerRegionLookup::NoRegion }).await,
            GameServerRegionLookup::NoRegion
        );
        assert_eq!(
            cached_region_lookup(&cache, ip, async {
                panic!("definitive negative answers should be cached")
            })
            .await,
            GameServerRegionLookup::NoRegion
        );
    }

    #[tokio::test]
    async fn region_request_ownership_is_bounded_and_reclaims_finished_addresses() {
        let cache = Mutex::new(RegionCache::default());
        let mut held: Vec<_> = (1..=REGION_REQUEST_MAX_ENTRIES)
            .map(|index| {
                cache
                    .lock()
                    .requests
                    .request(Ipv4Addr::from(index as u32), REGION_REQUEST_MAX_ENTRIES)
                    .unwrap()
            })
            .collect();
        let new_ip = Ipv4Addr::from((REGION_REQUEST_MAX_ENTRIES + 1) as u32);
        assert_eq!(
            cached_region_lookup(&cache, new_ip, async {
                panic!("overload must not start HTTP work")
            })
            .await,
            GameServerRegionLookup::Failed
        );
        held.pop();
        assert_eq!(
            cached_region_lookup(&cache, new_ip, async { GameServerRegionLookup::NoRegion }).await,
            GameServerRegionLookup::NoRegion
        );
    }

    #[test]
    fn expired_region_answers_are_removed_without_turning_failures_into_long_lived_cache_entries() {
        let mut cache = RegionCache::default();
        let now = Instant::now();
        let ip = Ipv4Addr::new(128, 116, 47, 33);
        cache.put(ip, GameServerRegionLookup::NoRegion, now);
        assert!(
            cache
                .get(ip, now + REGION_CACHE_TTL - Duration::from_millis(1))
                .is_some()
        );
        assert!(cache.get(ip, now + REGION_CACHE_TTL).is_none());
        assert!(cache.entries.is_empty());
        cache.put(ip, GameServerRegionLookup::Failed, now);
        assert!(cache.entries.is_empty());
    }

    #[tokio::test]
    async fn concurrent_region_lookups_share_one_request_without_delaying_other_ips() {
        use std::sync::atomic::{AtomicUsize, Ordering};
        let cache = Mutex::new(RegionCache::default());
        let calls = AtomicUsize::new(0);
        let release = tokio::sync::Notify::new();
        let ip = Ipv4Addr::new(128, 116, 47, 33);
        let answer = GameServerRegionLookup::Resolved(RobloxRegion::Mumbai, "Mumbai".into());
        let (first, duplicate, other) = tokio::time::timeout(Duration::from_secs(2), async {
            tokio::join!(biased;
                cached_region_lookup(&cache, ip, async {
                    calls.fetch_add(1, Ordering::Relaxed);
                    release.notified().await;
                    answer.clone()
                }),
                cached_region_lookup(&cache, ip, async {
                    calls.fetch_add(1, Ordering::Relaxed);
                    GameServerRegionLookup::NoRegion
                }),
                async {
                    let value = cached_region_lookup(&cache, Ipv4Addr::new(128, 116, 46, 33), async {
                        GameServerRegionLookup::NoRegion
                    }).await;
                    release.notify_one();
                    value
                }
            )
        }).await.expect("another IP must not wait for this lookup");
        assert_eq!(first, answer);
        assert_eq!(duplicate, answer);
        assert_eq!(other, GameServerRegionLookup::NoRegion);
        assert_eq!(calls.load(Ordering::Relaxed), 1);
    }

    #[test]
    fn a_full_region_cache_evicts_one_old_answer_instead_of_clearing_every_location() {
        let mut cache = RegionCache::default();
        let now = Instant::now();
        for index in 1..=REGION_CACHE_MAX_ENTRIES {
            cache.put(
                Ipv4Addr::from(index as u32),
                GameServerRegionLookup::NoRegion,
                now + Duration::from_millis(index as u64),
            );
        }
        let added = Ipv4Addr::from((REGION_CACHE_MAX_ENTRIES + 1) as u32);
        cache.put(
            added,
            GameServerRegionLookup::NoRegion,
            now + Duration::from_secs(10),
        );
        assert_eq!(cache.entries.len(), REGION_CACHE_MAX_ENTRIES);
        assert!(
            cache
                .get(Ipv4Addr::from(1), now + Duration::from_secs(10))
                .is_none()
        );
        assert!(
            cache
                .get(Ipv4Addr::from(2), now + Duration::from_secs(10))
                .is_some()
        );
        cache.put(
            added,
            GameServerRegionLookup::NoRegion,
            now + Duration::from_secs(11),
        );
        assert_eq!(cache.entries.len(), REGION_CACHE_MAX_ENTRIES);
    }

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
