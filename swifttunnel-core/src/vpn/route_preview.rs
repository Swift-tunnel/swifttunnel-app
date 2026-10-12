//! Read-only startup estimates. No relay tickets, tunnel, or quota reservation.
use super::route_measurements::RelayEstimate;
use serde::{Deserialize, Serialize};
use std::net::{Ipv4Addr, SocketAddr};
use std::time::{Duration, Instant};

#[derive(Debug, Clone, Serialize)]
pub struct ReferenceEstimate {
    #[serde(flatten)]
    pub estimate: RelayEstimate,
    pub location: String,
    pub target: Ipv4Addr,
    pub valid_for_ms: u64,
    #[serde(skip)]
    expires: Instant,
}
impl ReferenceEstimate {
    pub fn is_fresh(&self) -> bool {
        Instant::now() < self.expires
    }
}

#[derive(Deserialize)]
pub struct ReferenceSample {
    relay: String,
    address: SocketAddr,
    target: Ipv4Addr,
    location: String,
    rtt_ms: u32,
    age_ms: u64,
    samples: u32,
    #[serde(skip)]
    received: Option<Instant>,
}
#[derive(Deserialize)]
struct Response {
    method: String,
    generated_at_ms: u64,
    targets: Vec<ReferenceTarget>,
    routes: Vec<ReferenceSample>,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq)]
struct ReferenceTarget {
    ip: Ipv4Addr,
    location: String,
}

fn target_valid(target: &ReferenceTarget) -> bool {
    target.ip.octets()[..2] == [128, 116]
        && target.ip.octets()[3] == 3
        && !target.location.is_empty()
        && target.location.len() <= 80
        && !target.location.chars().any(char::is_control)
}

fn target_file() -> Option<std::path::PathBuf> {
    dirs::config_dir().map(|dir| dir.join("SwiftTunnel").join("last-game-datacenter.txt"))
}

/// Persist only the coarse datacenter name, never a game IP or game history.
/// The routing worker calls this only after it has identified a game region.
pub(crate) fn remember_location(location: &str) {
    if !crate::geolocation::RobloxRegion::all_regions()
        .iter()
        .any(|region| region.display_name() == location)
    {
        return;
    }
    #[cfg(not(test))]
    {
        static LAST: std::sync::Mutex<String> = std::sync::Mutex::new(String::new());
        let Ok(mut last) = LAST.lock() else { return };
        if *last == location {
            return;
        }
        if let Some(path) = target_file() {
            if let Some(parent) = path.parent() {
                let _ = std::fs::create_dir_all(parent);
            }
            if std::fs::write(path, location).is_ok() {
                *last = location.to_owned();
            }
        }
    }
}

fn select_target<'a>(
    targets: &'a [(ReferenceTarget, Option<u32>)],
    previous: Option<&str>,
) -> Option<&'a ReferenceTarget> {
    if let Some(previous) = previous {
        if let Some((target, _)) = targets
            .iter()
            .find(|(target, _)| target.location == previous)
        {
            return Some(target);
        }
    }
    targets
        .iter()
        .filter_map(|(target, ms)| ms.filter(|ms| *ms <= 2000).map(|ms| (target, ms)))
        .min_by_key(|(target, ms)| (*ms, target.ip))
        .map(|(target, _)| target)
}

async fn common_target(targets: &[ReferenceTarget]) -> Option<ReferenceTarget> {
    type DirectCache = Option<(Instant, Vec<(ReferenceTarget, Option<u32>)>)>;
    static DIRECT: tokio::sync::Mutex<DirectCache> = tokio::sync::Mutex::const_new(None);
    let mut cache = DIRECT.lock().await;
    let fresh = cache.as_ref().is_some_and(|(at, rows)| {
        at.elapsed() < Duration::from_secs(300)
            && rows.iter().map(|(target, _)| target).eq(targets.iter())
    });
    if !fresh {
        let mut tasks = tokio::task::JoinSet::new();
        let mut rows = Vec::new();
        for target in targets.iter().cloned() {
            if tasks.len() >= 8 {
                if let Some(Ok(row)) = tasks.join_next().await {
                    rows.push(row);
                }
            }
            tasks.spawn_blocking(move || {
                let ms = super::servers::measure_latency_icmp(&target.ip.to_string());
                (target, ms)
            });
        }
        while let Some(result) = tasks.join_next().await {
            if let Ok(row) = result {
                rows.push(row);
            }
        }
        // Preserve catalog order for the next cache comparison.
        rows.sort_by_key(|(target, _)| targets.iter().position(|item| item == target));
        *cache = Some((Instant::now(), rows));
    }
    let previous = target_file().and_then(|path| {
        if std::fs::metadata(&path).ok()?.len() > 80 {
            return None;
        }
        std::fs::read_to_string(path).ok()
    });
    select_target(&cache.as_ref()?.1, previous.as_deref()).cloned()
}

pub fn estimates(
    servers: &[(String, SocketAddr, Option<u32>)],
    rows: &[ReferenceSample],
) -> Vec<ReferenceEstimate> {
    servers
        .iter()
        .filter_map(|(id, address, first)| {
            let first = (*first).filter(|ms| *ms <= 2000)?;
            let mut matching = rows
                .iter()
                .filter(|row| row.relay == *id && row.address == *address);
            let row = matching.next()?;
            let age = row
                .age_ms
                .saturating_add(row.received?.elapsed().as_millis() as u64);
            if matching.next().is_some()
                || row.samples != 2
                || row.rtt_ms > 2000
                || age >= 300_000
                || row.location.is_empty()
                || row.location.len() > 80
                || row.location.chars().any(char::is_control)
                || row.target.octets()[..2] != [128, 116]
                || row.target.octets()[3] != 3
            {
                return None;
            }
            // The first leg must also be remeasured regularly, even with a warm cache.
            let valid_for_ms = (300_000 - age).min(45_000);
            Some(ReferenceEstimate {
                estimate: RelayEstimate {
                    relay: id.clone(),
                    address: *address,
                    relay_ms: first,
                    second_leg_ms: row.rtt_ms,
                    estimated_game_ms: first + row.rtt_ms,
                },
                location: row.location.clone(),
                target: row.target,
                valid_for_ms,
                expires: Instant::now() + Duration::from_millis(valid_for_ms),
            })
        })
        .collect()
}

pub async fn fetch() -> Vec<ReferenceSample> {
    static CLIENT: std::sync::OnceLock<reqwest::Client> = std::sync::OnceLock::new();
    let client = CLIENT.get_or_init(|| {
        reqwest::Client::builder()
            .timeout(Duration::from_millis(2500))
            .redirect(reqwest::redirect::Policy::none())
            .build()
            .expect("reference measurement client")
    });
    let started = Instant::now();
    let result = async {
        let mut response = client
            .get("https://www.swifttunnel.net/api/vpn/route-measurements/preview")
            .send()
            .await
            .ok()?;
        if !response.status().is_success() {
            return None;
        }
        // Include intermediary-cache age without trusting the PC's wall clock.
        let cache_age = response
            .headers()
            .get("age")
            .and_then(|value| value.to_str().ok())
            .and_then(|value| value.parse::<u64>().ok())
            .unwrap_or(0)
            .saturating_mul(1000);
        let server_time = response
            .headers()
            .get("date")
            .and_then(|value| value.to_str().ok())
            .and_then(|value| chrono::DateTime::parse_from_rfc2822(value).ok())
            .and_then(|value| u64::try_from(value.timestamp_millis()).ok());
        let mut bytes = Vec::new();
        while let Some(chunk) = response.chunk().await.ok()? {
            if bytes.len() + chunk.len() > 524_288 {
                return None;
            }
            bytes.extend_from_slice(&chunk);
        }
        let mut body: Response = serde_json::from_slice(&bytes).ok()?;
        if body.method != "icmp_reference_matrix"
            || body.routes.len() > 2048
            || body.targets.is_empty()
            || body.targets.len() > 16
            || body.targets.iter().any(|target| !target_valid(target))
            || body.targets.iter().enumerate().any(|(index, target)| {
                body.targets[..index]
                    .iter()
                    .any(|other| other.ip == target.ip || other.location == target.location)
            })
        {
            return None;
        }
        let common = common_target(&body.targets).await?;
        body.routes
            .retain(|row| row.target == common.ip && row.location == common.location);
        let origin_age = server_time?.saturating_sub(body.generated_at_ms);
        for row in &mut body.routes {
            row.age_ms = row
                .age_ms
                .saturating_add(started.elapsed().as_millis() as u64)
                .saturating_add(cache_age)
                .saturating_add(origin_age);
            row.received = Some(Instant::now());
        }
        Some(body.routes)
    }
    .await;
    result.unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use super::*;
    fn targets() -> Vec<(ReferenceTarget, Option<u32>)> {
        vec![
            (
                ReferenceTarget {
                    ip: "128.116.47.3".parse().unwrap(),
                    location: "Mumbai".into(),
                },
                Some(19),
            ),
            (
                ReferenceTarget {
                    ip: "128.116.46.3".parse().unwrap(),
                    location: "Singapore".into(),
                },
                Some(54),
            ),
        ]
    }
    #[test]
    fn startup_target_uses_direct_ping_instead_of_relay_city() {
        assert_eq!(select_target(&targets(), None).unwrap().location, "Mumbai");
    }
    #[test]
    fn previous_game_target_wins_and_removed_targets_fall_back_to_direct_measurement() {
        assert_eq!(
            select_target(&targets(), Some("Singapore"))
                .unwrap()
                .location,
            "Singapore"
        );
        assert_eq!(
            select_target(&targets(), Some("Removed")).unwrap().location,
            "Mumbai"
        );
        let mut targets = targets();
        for (_, ms) in &mut targets {
            *ms = None;
        }
        assert!(select_target(&targets, None).is_none());
        // A blocked direct path need not make a known relay path unavailable.
        assert_eq!(
            select_target(&targets, Some("Mumbai")).unwrap().location,
            "Mumbai"
        );
    }
    #[test]
    fn probe_catalog_rejects_non_roblox_addresses_and_control_characters() {
        let mut target = targets()[0].0.clone();
        assert!(target_valid(&target));
        target.ip = "127.0.0.3".parse().unwrap();
        assert!(!target_valid(&target));
        target.ip = "128.116.47.33".parse().unwrap();
        assert!(!target_valid(&target));
        target.ip = "128.116.47.3".parse().unwrap();
        target.location = "bad\nlabel".into();
        assert!(!target_valid(&target));
    }
    fn sample() -> ReferenceSample {
        ReferenceSample {
            relay: "mumbai-01".into(),
            address: "1.2.3.4:51821".parse().unwrap(),
            target: "128.116.47.3".parse().unwrap(),
            location: "Mumbai".into(),
            rtt_ms: 2,
            age_ms: 0,
            samples: 2,
            received: Some(Instant::now()),
        }
    }
    #[test]
    fn startup_estimate_needs_two_measured_legs_and_current_endpoint() {
        let mut servers = vec![(
            "mumbai-01".into(),
            "1.2.3.4:51821".parse().unwrap(),
            Some(20),
        )];
        assert_eq!(
            estimates(&servers, &[sample()])[0]
                .estimate
                .estimated_game_ms,
            22
        );
        servers[0].2 = None;
        assert!(estimates(&servers, &[sample()]).is_empty());
        servers[0].2 = Some(20);
        servers[0].1 = "5.6.7.8:51821".parse().unwrap();
        assert!(estimates(&servers, &[sample()]).is_empty());
    }
    #[test]
    fn rejects_old_failed_duplicate_or_malformed_reference_samples() {
        let servers = vec![(
            "mumbai-01".into(),
            "1.2.3.4:51821".parse().unwrap(),
            Some(20),
        )];
        assert!(estimates(&servers, &[sample(), sample()]).is_empty());
        for case in 0..5 {
            let mut row = sample();
            match case {
                0 => row.age_ms = 300_000,
                1 => row.samples = 1,
                2 => row.rtt_ms = 2001,
                3 => row.target = "127.0.0.3".parse().unwrap(),
                _ => row.location = "bad\nlabel".into(),
            }
            assert!(estimates(&servers, &[row]).is_empty());
        }
    }
}
