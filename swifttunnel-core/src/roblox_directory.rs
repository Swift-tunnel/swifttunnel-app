//! On-demand public server directory. No Roblox cookies or login tickets.
use crate::{
    http_body::read_bounded,
    http_client::retry_delay,
    roblox_library::{valid_job_id, valid_place_id},
};
use serde::{Deserialize, Serialize};
use std::{
    collections::HashMap,
    net::Ipv4Addr,
    sync::{Arc, LazyLock, Mutex},
    time::{Duration, Instant},
};

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Datacenter {
    pub id: u32,
    pub city: String,
    pub country: String,
    pub datacenter_ids: Vec<u32>,
    pub relay_region: Option<String>,
}
#[derive(Deserialize)]
struct CatalogEntry {
    location_id: u32,
    #[serde(rename = "dataCenterIds")]
    datacenter_ids: Vec<u32>,
    location: CatalogLocation,
    #[serde(default)]
    inactive: bool,
}
#[derive(Deserialize)]
struct CatalogLocation {
    city: String,
    country: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct GameServer {
    pub job_id: String,
    pub datacenter_id: u32,
    pub ip: Option<Ipv4Addr>,
    pub first_seen: String,
    pub playing: Option<u32>,
    pub capacity: Option<u32>,
    pub availability: Availability,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Availability {
    Available,
    Full,
    Unavailable,
    #[default]
    Unknown,
}
#[derive(Clone, Serialize)]
pub struct ServerPage {
    pub servers: Vec<GameServer>,
    pub next_cursor: Option<u32>,
    pub warning: Option<String>,
}
#[derive(Deserialize)]
struct DirectoryPage {
    place_id: String,
    status: String,
    servers: Vec<DirectoryServer>,
    next_cursor: Option<u32>,
}
#[derive(Deserialize)]
struct DirectoryServer {
    server_id: String,
    datacenter_id: u32,
    #[serde(default)]
    ip_address: Option<String>,
    #[serde(default)]
    first_seen: String,
}
#[derive(Deserialize)]
struct PublicPage {
    data: Vec<PublicServer>,
    #[serde(rename = "nextPageCursor")]
    next_cursor: Option<String>,
}
#[derive(Clone, Deserialize)]
struct PublicServer {
    id: String,
    playing: u32,
    #[serde(rename = "maxPlayers")]
    capacity: u32,
}

fn client() -> Result<&'static reqwest::Client, reqwest::Error> {
    static CLIENT: std::sync::OnceLock<reqwest::Client> = std::sync::OnceLock::new();
    crate::http_client::cached_client(&CLIENT, || {
        reqwest::Client::builder()
            .timeout(Duration::from_secs(4))
            .redirect(reqwest::redirect::Policy::none())
            .user_agent("SwiftTunnel/server-directory")
    })
}
/// RoValra's API terms: their responses stay the same for at least 60 seconds,
/// and apps must cache on their side instead of repeating identical requests.
/// Only RoValra's location data is kept. Roblox availability is always fresh.
const ROVALRA_CACHE_TTL: Duration = Duration::from_secs(60);
const ROVALRA_CACHE_ENTRIES: usize = 32;

#[derive(Default)]
struct ResponseCache {
    entries: HashMap<String, (Instant, Arc<[u8]>)>,
    requests: crate::http_client::RequestSlots<String>,
}
impl ResponseCache {
    fn get(&mut self, key: &str, now: Instant) -> Option<Arc<[u8]>> {
        match self.entries.get(key) {
            Some((at, body)) if now.duration_since(*at) < ROVALRA_CACHE_TTL => Some(body.clone()),
            Some(_) => {
                self.entries.remove(key);
                None
            }
            None => None,
        }
    }
    fn put(&mut self, key: String, body: Arc<[u8]>, now: Instant) {
        self.entries
            .retain(|_, (at, _)| now.duration_since(*at) < ROVALRA_CACHE_TTL);
        if self.entries.len() >= ROVALRA_CACHE_ENTRIES
            && !self.entries.contains_key(&key)
            && let Some(oldest) = self
                .entries
                .iter()
                .min_by_key(|(_, (at, _))| *at)
                .map(|(key, _)| key.clone())
        {
            self.entries.remove(&oldest);
        }
        self.entries.insert(key, (now, body));
    }

    fn request(&mut self, key: &str) -> Result<Arc<tokio::sync::Mutex<()>>, String> {
        self.requests
            .request(key.into(), ROVALRA_CACHE_ENTRIES)
            .ok_or_else(|| {
                "The server directory is busy. Wait a moment before searching again.".into()
            })
    }
}
static ROVALRA_RESPONSES: LazyLock<Mutex<ResponseCache>> = LazyLock::new(Default::default);

fn rovalra_cacheable(url: &reqwest::Url) -> bool {
    url.host_str() == Some("apis.rovalra.com")
}

fn parse_body<T: serde::de::DeserializeOwned>(bytes: &[u8]) -> Result<T, String> {
    serde_json::from_slice(bytes)
        .map_err(|_| "The server directory returned an unexpected response.".into())
}

#[derive(Clone, Copy)]
enum DirectoryService {
    Rovalra,
    Roblox,
}

impl DirectoryService {
    fn for_url(url: &reqwest::Url) -> Result<Self, String> {
        match url.host_str() {
            Some("apis.rovalra.com") => Ok(Self::Rovalra),
            Some("games.roblox.com") => Ok(Self::Roblox),
            _ => Err("Unexpected server directory address.".into()),
        }
    }
}

#[derive(Default)]
struct DirectoryCooldowns([Option<Instant>; 2]);

impl DirectoryCooldowns {
    fn check(&self, service: DirectoryService, now: Instant) -> Result<(), String> {
        if let Some(deadline) = self.0[service as usize] {
            let remaining = deadline.saturating_duration_since(now);
            if !remaining.is_zero() {
                let seconds = remaining.as_secs() + u64::from(remaining.subsec_nanos() > 0);
                let suffix = if seconds == 1 { "" } else { "s" };
                return Err(format!(
                    "Server search is busy. Try again in {seconds} second{suffix}."
                ));
            }
        }
        Ok(())
    }

    fn defer(&mut self, service: DirectoryService, now: Instant, delay: Duration) {
        let deadline = now + delay.clamp(Duration::from_secs(1), Duration::from_secs(300));
        let slot = &mut self.0[service as usize];
        *slot = Some(slot.map_or(deadline, |previous| previous.max(deadline)));
    }
}

async fn directory_response(
    cooldowns: &Mutex<DirectoryCooldowns>,
    service: DirectoryService,
    fetch: impl std::future::Future<Output = Result<reqwest::Response, reqwest::Error>>,
) -> Result<reqwest::Response, String> {
    cooldowns
        .lock()
        .unwrap_or_else(|p| p.into_inner())
        .check(service, Instant::now())?;
    let response = fetch
        .await
        .map_err(|_| "Could not reach the server directory. Try again shortly.".to_string())?;
    if matches!(response.status().as_u16(), 429 | 503) {
        // Record the cooldown before touching a potentially broken error body.
        // New searches and other pages share it; the other service is separate.
        let now = Instant::now();
        let mut cooldowns = cooldowns.lock().unwrap_or_else(|p| p.into_inner());
        cooldowns.defer(service, now, retry_delay(response.headers()));
        cooldowns.check(service, now)?;
    }
    response
        .error_for_status()
        .map_err(|_| "Server information is temporarily unavailable.".to_string())
}

async fn json<T: serde::de::DeserializeOwned>(url: reqwest::Url) -> Result<T, String> {
    if rovalra_cacheable(&url) {
        let key = url.as_str().to_string();
        cached_json(&ROVALRA_RESPONSES, &key, fetch_json_body(url)).await
    } else {
        parse_body(&fetch_json_body(url).await?)
    }
}

async fn cached_json<T: serde::de::DeserializeOwned>(
    responses: &Mutex<ResponseCache>,
    key: &str,
    fetch: impl std::future::Future<Output = Result<Vec<u8>, String>>,
) -> Result<T, String> {
    let request = {
        let mut cache = responses.lock().unwrap_or_else(|p| p.into_inner());
        if let Some(body) = cache.get(key, Instant::now()) {
            drop(cache);
            return parse_body(&body);
        }
        cache.request(key)?
    };
    // Keep each URL's admission until parsing and cache publication finish.
    // Another URL stays independent; a cancelled or failed fetch is retryable.
    let _request = request.lock().await;
    let cached = responses
        .lock()
        .unwrap_or_else(|p| p.into_inner())
        .get(key, Instant::now());
    if let Some(body) = cached {
        return parse_body(&body);
    }
    let bytes = fetch.await?;
    let value = parse_body(&bytes)?;
    responses.lock().unwrap_or_else(|p| p.into_inner()).put(
        key.into(),
        Arc::from(&bytes[..]),
        Instant::now(),
    );
    Ok(value)
}

async fn fetch_json_body(url: reqwest::Url) -> Result<Vec<u8>, String> {
    static COOLDOWNS: Mutex<DirectoryCooldowns> = Mutex::new(DirectoryCooldowns([None; 2]));
    let service = DirectoryService::for_url(&url)?;
    let response = directory_response(
        &COOLDOWNS,
        service,
        client()
            .map_err(|error| {
                log::warn!("Could not initialize the server-directory client: {error}");
                "Could not prepare the server search. Restart SwiftTunnel and try again."
                    .to_string()
            })?
            .get(url)
            .send(),
    )
    .await?;
    read_bounded(response, 512 * 1024, "server directory").await
}
fn relay_region(city: &str, country: &str) -> Option<&'static str> {
    match (city, country) {
        (_, "SG") => Some("singapore"),
        ("Mumbai", "IN") => Some("mumbai"),
        ("Tokyo" | "Osaka", "JP") => Some("tokyo"),
        ("Sydney", "AU") => Some("sydney"),
        ("Frankfurt am Main", "DE") => Some("germany"),
        ("London", "GB") => Some("london"),
        ("Amsterdam", "NL") => Some("amsterdam"),
        ("Paris", "FR") => Some("paris"),
        ("Jakarta", "ID") => Some("jakarta"),
        ("Tel Aviv", "IL") => Some("israel"),
        ("São Paulo", "BR") => Some("brazil"),
        ("Ashburn" | "Atlanta" | "Miami" | "New York City", "US") => Some("us-east"),
        ("Chicago" | "Dallas", "US") => Some("us-central"),
        ("Los Angeles" | "Seattle" | "San Jose" | "Boardman", "US") => Some("us-west"),
        _ => None,
    }
}
fn parse_catalog(rows: Vec<CatalogEntry>) -> Result<Vec<Datacenter>, String> {
    if rows.len() > 128 {
        return Err("The datacenter list is too large.".into());
    }
    let mut output = Vec::new();
    for row in rows.into_iter().filter(|row| !row.inactive) {
        let city = row.location.city.trim();
        let country = row.location.country.trim();
        if row.location_id == 0
            || city.is_empty()
            || city.len() > 80
            || city.chars().any(char::is_control)
            || country.len() != 2
            || !country.bytes().all(|b| b.is_ascii_uppercase())
            || row.datacenter_ids.is_empty()
            || row.datacenter_ids.len() > 128
        {
            continue;
        }
        if output
            .iter()
            .any(|old: &Datacenter| old.id == row.location_id)
        {
            return Err("The datacenter list contains duplicate locations.".into());
        }
        output.push(Datacenter {
            id: row.location_id,
            city: city.into(),
            country: country.into(),
            relay_region: relay_region(city, country).map(str::to_string),
            datacenter_ids: row.datacenter_ids,
        });
    }
    output.sort_by(|a, b| a.city.cmp(&b.city));
    Ok(output)
}
pub async fn datacenters() -> Result<Vec<Datacenter>, String> {
    static CACHE: tokio::sync::Mutex<Option<(Instant, Vec<Datacenter>)>> =
        tokio::sync::Mutex::const_new(None);
    let mut cache = CACHE.lock().await;
    if let Some((at, rows)) = &*cache
        && at.elapsed() < Duration::from_secs(600)
    {
        return Ok(rows.clone());
    }
    let rows = parse_catalog(
        json(reqwest::Url::parse("https://apis.rovalra.com/v1/datacenters/list").unwrap()).await?,
    )?;
    *cache = Some((Instant::now(), rows.clone()));
    Ok(rows)
}
pub fn public_game_ip(ip: Ipv4Addr) -> bool {
    let [a, b, _, _] = ip.octets();
    !(ip.is_unspecified()
        || ip.is_loopback()
        || ip.is_private()
        || ip.is_link_local()
        || ip.is_broadcast()
        || ip.is_multicast()
        || a == 0
        || a >= 240
        || a == 100 && (64..=127).contains(&b)
        || a == 198 && (18..=19).contains(&b))
}
fn parse_servers(
    page: DirectoryPage,
    place: &str,
    center: &Datacenter,
) -> Result<ServerPage, String> {
    if page.status != "success" || page.place_id != place || page.servers.len() > 50 {
        return Err("The directory response does not match this game.".into());
    }
    let mut servers = Vec::new();
    for mut row in page.servers {
        if !valid_job_id(&row.server_id)
            || !center.datacenter_ids.contains(&row.datacenter_id)
            || row.first_seen.len() > 80
            || row.first_seen.chars().any(char::is_control)
        {
            continue;
        }
        // Roblox job IDs are UUIDs. Directory/API/log letter casing must not
        // create duplicate choices or hide a public server's verified slots.
        row.server_id.make_ascii_lowercase();
        if servers
            .iter()
            .any(|old: &GameServer| old.job_id == row.server_id)
        {
            continue;
        }
        let ip = row
            .ip_address
            .and_then(|ip| ip.parse().ok())
            .filter(|ip| public_game_ip(*ip));
        servers.push(GameServer {
            job_id: row.server_id,
            datacenter_id: row.datacenter_id,
            ip,
            first_seen: row.first_seen,
            playing: None,
            capacity: None,
            availability: Availability::Unknown,
        });
    }
    Ok(ServerPage {
        servers,
        next_cursor: page.next_cursor,
        warning: None,
    })
}
async fn public_roster(place: &str) -> Result<(HashMap<String, PublicServer>, bool), String> {
    let mut cursor: Option<String> = None;
    let mut roster = HashMap::new();
    for _ in 0..3 {
        let mut url = reqwest::Url::parse(&format!(
            "https://games.roblox.com/v1/games/{place}/servers/Public"
        ))
        .unwrap();
        url.query_pairs_mut()
            .append_pair("sortOrder", "Desc")
            .append_pair("limit", "100");
        if let Some(cursor) = &cursor {
            url.query_pairs_mut().append_pair("cursor", cursor);
        }
        let page: PublicPage = json(url).await?;
        if page.data.len() > 100 || page.next_cursor.as_ref().is_some_and(|c| c.len() > 1024) {
            return Err("Unexpected Roblox server-list response.".into());
        }
        for mut row in page.data {
            if valid_job_id(&row.id) {
                row.id.make_ascii_lowercase();
                roster.insert(row.id.clone(), row);
            }
        }
        if page.next_cursor.is_none() {
            return Ok((roster, true));
        }
        if page.next_cursor == cursor {
            return Ok((roster, false));
        }
        cursor = page.next_cursor;
    }
    Ok((roster, false))
}
fn apply_availability(
    servers: &mut [GameServer],
    roster: &HashMap<String, PublicServer>,
    complete: bool,
) {
    for server in servers {
        if let Some(row) = roster.get(&server.job_id.to_ascii_lowercase()) {
            server.playing = Some(row.playing);
            server.capacity = Some(row.capacity);
            server.availability = if row.capacity > row.playing {
                Availability::Available
            } else {
                Availability::Full
            };
        } else if complete {
            // Absence from a public list is not proof that a private/reserved
            // server is dead. Only a positive public record verifies a slot.
            server.availability = Availability::Unknown;
        }
    }
}
pub async fn servers(
    place: &str,
    location: u32,
    cursor: Option<u32>,
) -> Result<ServerPage, String> {
    ServerLookup::new(place)?.servers(location, cursor).await
}

/// One public roster per on-demand search, shared across candidate locations.
/// It is discarded when the search ends. Final join checks still fetch fresh
/// availability, so a cross-search cache cannot keep full servers selectable.
pub struct ServerLookup {
    place: String,
    roster: Option<Result<(HashMap<String, PublicServer>, bool), String>>,
}
impl ServerLookup {
    pub fn new(place: &str) -> Result<Self, String> {
        if !valid_place_id(place) {
            return Err("Choose a valid Roblox game.".into());
        }
        Ok(Self {
            place: place.into(),
            roster: None,
        })
    }

    pub async fn servers(
        &mut self,
        location: u32,
        cursor: Option<u32>,
    ) -> Result<ServerPage, String> {
        let place = self.place.as_str();
        static SEARCH: tokio::sync::Semaphore = tokio::sync::Semaphore::const_new(2);
        let _slot = SEARCH.try_acquire().map_err(|_| {
            "Another server search is still running. Try again shortly.".to_string()
        })?;
        let center = datacenters()
            .await?
            .into_iter()
            .find(|row| row.id == location)
            .ok_or("This datacenter is no longer available. Refresh the location list.")?;
        let mut url = reqwest::Url::parse("https://apis.rovalra.com/v1/servers/region").unwrap();
        url.query_pairs_mut()
            .append_pair("place_id", place)
            .append_pair("limit", "50")
            .append_pair("city", &center.city)
            .append_pair("country", &center.country);
        if let Some(cursor) = cursor {
            url.query_pairs_mut()
                .append_pair("cursor", &cursor.to_string());
        }
        let directory = if self.roster.is_none() {
            let (directory, roster) = tokio::join!(json(url), public_roster(place));
            self.roster = Some(roster);
            directory
        } else {
            json(url).await
        };
        let mut page = parse_servers(directory?, place, &center)?;
        match self.roster.as_ref() {
        Some(Ok((roster, complete))) => apply_availability(&mut page.servers, roster, *complete),
        _ => page.warning = Some("Roblox could not verify current server availability. A listed server may be full or closed.".into()),
    }
        Ok(page)
    }
}
pub async fn availability(place: &str, job: &str) -> Result<Availability, String> {
    if !valid_place_id(place) || !valid_job_id(job) {
        return Err("Invalid Roblox game or server ID.".into());
    }
    let (roster, _) = public_roster(place).await?;
    Ok(match roster.get(&job.to_ascii_lowercase()) {
        Some(row) if row.playing < row.capacity => Availability::Available,
        Some(_) => Availability::Full,
        None => Availability::Unknown,
    })
}

/// Look up only this locally observed session. A directory address must match
/// both the job id and actual log destination before it supplies a city hint.
pub async fn resolve_session(place: &str, job: &str, ip: Ipv4Addr) -> Option<Datacenter> {
    if !valid_place_id(place) || !valid_job_id(job) || !public_game_ip(ip) {
        return None;
    }
    let catalog = datacenters().await.ok()?;
    let mut cursor: Option<u32> = None;
    for _ in 0..3 {
        let mut url = reqwest::Url::parse("https://apis.rovalra.com/v1/servers/region").ok()?;
        url.query_pairs_mut()
            .append_pair("place_id", place)
            .append_pair("limit", "50");
        if let Some(value) = cursor {
            url.query_pairs_mut()
                .append_pair("cursor", &value.to_string());
        }
        let page: DirectoryPage = json(url).await.ok()?;
        if page.place_id != place || page.status != "success" || page.servers.len() > 50 {
            return None;
        }
        if let Some(row) = page.servers.into_iter().find(|row| {
            row.server_id.eq_ignore_ascii_case(job)
                && row
                    .ip_address
                    .as_ref()
                    .and_then(|s| s.parse::<Ipv4Addr>().ok())
                    == Some(ip)
        }) {
            return catalog
                .into_iter()
                .find(|c| c.datacenter_ids.contains(&row.datacenter_id));
        }
        if page.next_cursor.is_none() || page.next_cursor == cursor {
            return None;
        }
        cursor = page.next_cursor;
    }
    None
}

#[cfg(test)]
mod tests {
    use super::{ROVALRA_CACHE_ENTRIES, ResponseCache, rovalra_cacheable};
    use std::{
        sync::Arc,
        time::{Duration, Instant},
    };

    #[test]
    fn directory_cooldowns_expire_without_blocking_the_other_service() {
        let now = Instant::now();
        let mut cooldowns = DirectoryCooldowns::default();
        cooldowns.defer(DirectoryService::Rovalra, now, Duration::from_secs(67));
        cooldowns.defer(DirectoryService::Rovalra, now, Duration::from_secs(2));
        assert!(
            cooldowns
                .check(DirectoryService::Rovalra, now)
                .unwrap_err()
                .contains("67 seconds")
        );
        assert!(cooldowns.check(DirectoryService::Roblox, now).is_ok());
        assert!(
            cooldowns
                .check(
                    DirectoryService::Rovalra,
                    now + Duration::from_millis(66_001)
                )
                .unwrap_err()
                .contains("1 second.")
        );
        assert!(
            cooldowns
                .check(DirectoryService::Rovalra, now + Duration::from_secs(67))
                .is_ok()
        );
        cooldowns.defer(DirectoryService::Roblox, now, Duration::MAX);
        assert!(
            cooldowns
                .check(DirectoryService::Roblox, now + Duration::from_secs(300))
                .is_ok()
        );
    }

    #[test]
    fn directory_retry_headers_support_seconds_and_http_dates_with_bounded_fallbacks() {
        use reqwest::header::{DATE, HeaderMap, RETRY_AFTER};
        let mut headers = HeaderMap::new();
        assert_eq!(retry_delay(&headers), Duration::from_secs(60));
        for (raw, seconds) in [
            ("67", 67),
            ("0", 1),
            ("18446744073709551615", 300),
            ("broken", 60),
        ] {
            headers.insert(RETRY_AFTER, raw.parse().unwrap());
            assert_eq!(retry_delay(&headers), Duration::from_secs(seconds));
        }
        headers.insert(DATE, "Wed, 21 Oct 2026 07:28:00 GMT".parse().unwrap());
        headers.insert(
            RETRY_AFTER,
            "Wed, 21 Oct 2026 07:29:07 GMT".parse().unwrap(),
        );
        assert_eq!(retry_delay(&headers), Duration::from_secs(67));
        headers.insert(
            RETRY_AFTER,
            "Wed, 21 Oct 2026 07:27:00 GMT".parse().unwrap(),
        );
        assert_eq!(retry_delay(&headers), Duration::from_secs(1));
    }

    #[tokio::test]
    async fn throttled_directory_responses_stop_subsequent_fetches_before_reading_the_body() {
        use std::io::{Read, Write};
        for status in [429, 503, 400, 200] {
            let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
            let address = listener.local_addr().unwrap();
            let server = std::thread::spawn(move || {
                let (mut socket, _) = listener.accept().unwrap();
                socket
                    .set_read_timeout(Some(Duration::from_secs(2)))
                    .unwrap();
                let mut request = [0; 4096];
                socket.read(&mut request).unwrap();
                // The error body is intentionally truncated, so classification
                // must use headers rather than waiting for/parsing its content.
                write!(socket, "HTTP/1.1 {status} Fixture\r\nRetry-After: 67\r\nContent-Length: 100000\r\nConnection: close\r\n\r\n").unwrap();
            });
            let cooldowns = Mutex::new(DirectoryCooldowns::default());
            let client = reqwest::Client::builder()
                .no_proxy()
                .timeout(Duration::from_secs(2))
                .build()
                .unwrap();
            let result = directory_response(
                &cooldowns,
                DirectoryService::Rovalra,
                client.get(format!("http://{address}")).send(),
            )
            .await;
            server.join().unwrap();
            if matches!(status, 429 | 503) {
                assert!(result.unwrap_err().contains("67 seconds"));
                let blocked = directory_response(&cooldowns, DirectoryService::Rovalra, async {
                    panic!("a new page/search must not repeat the request during cooldown")
                })
                .await;
                assert!(blocked.is_err());
                assert!(
                    cooldowns
                        .lock()
                        .unwrap()
                        .check(DirectoryService::Roblox, Instant::now())
                        .is_ok()
                );
            } else {
                assert_eq!(result.is_ok(), status == 200);
                assert!(
                    cooldowns
                        .lock()
                        .unwrap()
                        .check(DirectoryService::Rovalra, Instant::now())
                        .is_ok()
                );
            }
        }
    }

    #[tokio::test]
    async fn overlapping_directory_searches_share_a_fetch_without_blocking_other_urls() {
        use std::sync::atomic::{AtomicUsize, Ordering};
        let cache = Mutex::new(ResponseCache::default());
        let calls = AtomicUsize::new(0);
        let release = tokio::sync::Notify::new();
        let (first, second, independent) = tokio::time::timeout(Duration::from_secs(2), async {
            tokio::join!(biased;
            cached_json::<u32>(&cache, "same", async {
                calls.fetch_add(1, Ordering::Relaxed);
                release.notified().await;
                Ok(b"7".to_vec())
            }),
            cached_json::<u32>(&cache, "same", async {
                calls.fetch_add(1, Ordering::Relaxed);
                Ok(b"8".to_vec())
            }),
            async {
                let value = cached_json::<u32>(&cache, "other", async { Ok(b"9".to_vec()) }).await;
                release.notify_one();
                value
            },
            )
        })
        .await
        .expect("independent searches must keep progressing");
        assert_eq!(first, Ok(7));
        assert_eq!(second, Ok(7));
        assert_eq!(independent, Ok(9));
        assert_eq!(calls.load(Ordering::Relaxed), 1);
    }

    #[tokio::test]
    async fn failed_invalid_or_cancelled_directory_fetches_leave_the_url_retryable() {
        let cache = Arc::new(Mutex::new(ResponseCache::default()));
        assert!(
            cached_json::<u32>(&cache, "same", async { Err("offline".into()) })
                .await
                .is_err()
        );
        assert!(
            cached_json::<u32>(&cache, "same", async { Ok(b"invalid".to_vec()) })
                .await
                .is_err()
        );
        assert!(cache.lock().unwrap().entries.is_empty());

        let started = Arc::new(tokio::sync::Notify::new());
        let owner_cache = cache.clone();
        let owner_started = started.clone();
        let owner = tokio::spawn(async move {
            cached_json::<u32>(&owner_cache, "same", async {
                owner_started.notify_one();
                std::future::pending().await
            })
            .await
        });
        started.notified().await;
        owner.abort();
        assert!(owner.await.unwrap_err().is_cancelled());
        assert_eq!(
            cached_json::<u32>(&cache, "same", async { Ok(b"3".to_vec()) }).await,
            Ok(3)
        );
    }

    #[test]
    fn directory_request_ownership_is_bounded_and_reclaims_finished_urls() {
        let mut cache = ResponseCache::default();
        let mut held: Vec<_> = (0..ROVALRA_CACHE_ENTRIES)
            .map(|i| cache.request(&format!("page-{i}")).unwrap())
            .collect();
        assert!(Arc::ptr_eq(&held[0], &cache.request("page-0").unwrap()));
        assert!(cache.request("extra").is_err());
        held.pop();
        assert!(cache.request("extra").is_ok());
        drop(held);
        let _request = cache.request("next").unwrap();
        assert_eq!(cache.requests.len(), 1);
    }

    #[test]
    fn rovalra_responses_are_reused_for_sixty_seconds_then_fetched_again() {
        let start = Instant::now();
        let mut cache = ResponseCache::default();
        cache.put("page".into(), Arc::from(&b"one"[..]), start);
        assert_eq!(
            cache
                .get("page", start + Duration::from_secs(59))
                .as_deref(),
            Some(&b"one"[..])
        );
        assert!(cache.get("page", start + Duration::from_secs(60)).is_none());
        assert!(
            cache.entries.is_empty(),
            "an expired answer must be dropped"
        );
    }

    #[test]
    fn rovalra_cache_stays_bounded_by_dropping_the_oldest_answer() {
        let start = Instant::now();
        let mut cache = ResponseCache::default();
        for index in 0..=ROVALRA_CACHE_ENTRIES {
            cache.put(
                format!("page-{index}"),
                Arc::from(&b"x"[..]),
                start + Duration::from_millis(index as u64),
            );
        }
        assert_eq!(cache.entries.len(), ROVALRA_CACHE_ENTRIES);
        assert!(!cache.entries.contains_key("page-0"));
        assert!(
            cache
                .entries
                .contains_key(&format!("page-{ROVALRA_CACHE_ENTRIES}"))
        );
    }

    #[test]
    fn only_rovalra_location_data_is_cached_never_roblox_availability() {
        let rovalra =
            reqwest::Url::parse("https://apis.rovalra.com/v1/servers/region?place_id=1").unwrap();
        let roblox =
            reqwest::Url::parse("https://games.roblox.com/v1/games/1/servers/Public").unwrap();
        assert!(rovalra_cacheable(&rovalra));
        assert!(!rovalra_cacheable(&roblox));
    }
    use super::*;
    const JOB: &str = "550e8400-e29b-41d4-a716-446655440000";
    fn center() -> Datacenter {
        Datacenter {
            id: 7,
            city: "Mumbai".into(),
            country: "IN".into(),
            datacenter_ids: vec![1],
            relay_region: Some("mumbai".into()),
        }
    }
    #[test]
    fn rejects_a_different_game_and_filters_foreign_datacenters_and_private_ips() {
        let make = |place: &str, dc: u32, ip: &str| DirectoryPage {
            place_id: place.into(),
            status: "success".into(),
            next_cursor: None,
            servers: vec![DirectoryServer {
                server_id: JOB.into(),
                datacenter_id: dc,
                ip_address: Some(ip.into()),
                first_seen: String::new(),
            }],
        };
        assert!(parse_servers(make("2", 1, "128.116.47.33"), "1818", &center()).is_err());
        assert!(
            parse_servers(make("1818", 2, "128.116.47.33"), "1818", &center())
                .unwrap()
                .servers
                .is_empty()
        );
        assert!(
            parse_servers(make("1818", 1, "169.254.169.254"), "1818", &center())
                .unwrap()
                .servers[0]
                .ip
                .is_none()
        );
    }
    #[test]
    fn partial_rosters_do_not_falsely_label_servers_dead() {
        let mut page = parse_servers(
            DirectoryPage {
                place_id: "1818".into(),
                status: "success".into(),
                next_cursor: None,
                servers: vec![DirectoryServer {
                    server_id: JOB.into(),
                    datacenter_id: 1,
                    ip_address: None,
                    first_seen: String::new(),
                }],
            },
            "1818",
            &center(),
        )
        .unwrap();
        apply_availability(&mut page.servers, &HashMap::new(), false);
        assert_eq!(page.servers[0].availability, Availability::Unknown);
        apply_availability(&mut page.servers, &HashMap::new(), true);
        assert_eq!(page.servers[0].availability, Availability::Unknown);
    }

    #[test]
    fn public_availability_accepts_the_same_uuid_with_different_letter_casing() {
        let mut page = parse_servers(
            DirectoryPage {
                place_id: "1818".into(),
                status: "success".into(),
                next_cursor: None,
                servers: vec![DirectoryServer {
                    server_id: JOB.to_ascii_uppercase(),
                    datacenter_id: 1,
                    ip_address: None,
                    first_seen: String::new(),
                }],
            },
            "1818",
            &center(),
        )
        .unwrap();
        let roster = HashMap::from([(
            JOB.to_string(),
            PublicServer {
                id: JOB.into(),
                playing: 3,
                capacity: 10,
            },
        )]);
        apply_availability(&mut page.servers, &roster, true);
        assert_eq!(page.servers[0].availability, Availability::Available);
        assert_eq!(page.servers[0].playing, Some(3));
    }

    #[test]
    fn directory_deduplication_treats_uuid_casing_as_one_server() {
        let page = parse_servers(
            DirectoryPage {
                place_id: "1818".into(),
                status: "success".into(),
                next_cursor: None,
                servers: [JOB.to_string(), JOB.to_ascii_uppercase()]
                    .into_iter()
                    .map(|server_id| DirectoryServer {
                        server_id,
                        datacenter_id: 1,
                        ip_address: None,
                        first_seen: String::new(),
                    })
                    .collect(),
            },
            "1818",
            &center(),
        )
        .unwrap();
        assert_eq!(page.servers.len(), 1);
    }
    #[test]
    fn cloud_locations_map_without_pretending_other_cities_are_the_same_datacenter() {
        assert_eq!(relay_region("Jakarta", "ID"), Some("jakarta"));
        assert_eq!(relay_region("Tel Aviv", "IL"), Some("israel"));
        assert_eq!(relay_region("Istanbul", "TR"), None);
        assert_eq!(relay_region("Osaka", "JP"), Some("tokyo"));
    }
}
