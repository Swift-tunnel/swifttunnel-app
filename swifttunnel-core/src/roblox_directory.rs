//! On-demand public server directory. No Roblox cookies or login tickets.
use crate::{
    http_body::read_bounded,
    roblox_library::{valid_job_id, valid_place_id},
};
use serde::{Deserialize, Serialize};
use std::{
    collections::HashMap,
    net::Ipv4Addr,
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

fn client() -> &'static reqwest::Client {
    static CLIENT: std::sync::OnceLock<reqwest::Client> = std::sync::OnceLock::new();
    CLIENT.get_or_init(|| {
        reqwest::Client::builder()
            .timeout(Duration::from_secs(4))
            .redirect(reqwest::redirect::Policy::none())
            .user_agent("SwiftTunnel/server-directory")
            .build()
            .expect("server-directory HTTP client")
    })
}
async fn json<T: serde::de::DeserializeOwned>(url: reqwest::Url) -> Result<T, String> {
    let response = client()
        .get(url)
        .send()
        .await
        .map_err(|_| "Could not reach the server directory. Try again shortly.".to_string())?;
    if response.status().as_u16() == 429 {
        return Err("The server directory is busy. Wait a moment before searching again.".into());
    }
    let response = response
        .error_for_status()
        .map_err(|_| "Server information is temporarily unavailable.".to_string())?;
    let bytes = read_bounded(response, 512 * 1024, "server directory").await?;
    serde_json::from_slice(&bytes)
        .map_err(|_| "The server directory returned an unexpected response.".into())
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
    for row in page.servers {
        if !valid_job_id(&row.server_id)
            || !center.datacenter_ids.contains(&row.datacenter_id)
            || row.first_seen.len() > 80
            || row.first_seen.chars().any(char::is_control)
        {
            continue;
        }
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
        for row in page.data {
            if valid_job_id(&row.id) {
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
        if let Some(row) = roster.get(&server.job_id) {
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
    if !valid_place_id(place) {
        return Err("Choose a valid Roblox game.".into());
    }
    static SEARCH: tokio::sync::Semaphore = tokio::sync::Semaphore::const_new(2);
    let _slot = SEARCH
        .try_acquire()
        .map_err(|_| "Another server search is still running. Try again shortly.".to_string())?;
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
    let (directory, roster) = tokio::join!(json(url), public_roster(place));
    let mut page = parse_servers(directory?, place, &center)?;
    match roster {
        Ok((roster, complete)) => apply_availability(&mut page.servers, &roster, complete),
        Err(_) => page.warning = Some("Roblox could not verify current server availability. A listed server may be full or closed.".into()),
    }
    Ok(page)
}
pub async fn availability(place: &str, job: &str) -> Result<Availability, String> {
    if !valid_place_id(place) || !valid_job_id(job) {
        return Err("Invalid Roblox game or server ID.".into());
    }
    let (roster, _) = public_roster(place).await?;
    Ok(match roster.get(job) {
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
    fn cloud_locations_map_without_pretending_other_cities_are_the_same_datacenter() {
        assert_eq!(relay_region("Jakarta", "ID"), Some("jakarta"));
        assert_eq!(relay_region("Tel Aviv", "IL"), Some("israel"));
        assert_eq!(relay_region("Istanbul", "TR"), None);
        assert_eq!(relay_region("Osaka", "JP"), Some("tokyo"));
    }
}
