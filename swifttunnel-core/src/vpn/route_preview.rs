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

/// Resolve a picker region to its OWN datacenter label. Unknown regions have
/// no estimate until the public catalog supplies a matching reference.
pub fn reference_location(region: &str) -> Option<&'static str> {
    match region {
        "singapore" => Some("Singapore"),
        "mumbai" => Some("Mumbai"),
        "tokyo" => Some("Tokyo"),
        "sydney" => Some("Sydney"),
        "germany" => Some("Frankfurt"),
        "london" => Some("London"),
        "amsterdam" => Some("Amsterdam"),
        "paris" => Some("Paris"),
        "israel" => Some("Israel"),
        "jakarta" => Some("Jakarta"),
        "us-east" => Some("US East"),
        "us-central" => Some("US Central"),
        "us-west" => Some("US West"),
        "brazil" => Some("Brazil"),
        _ => None,
    }
}

pub fn estimates(
    servers: &[(String, SocketAddr, Option<u32>)],
    rows: &[ReferenceSample],
    regions: &[super::servers::DynamicGamingRegion],
) -> Vec<ReferenceEstimate> {
    servers
        .iter()
        .filter_map(|(id, address, first)| {
            let first = (*first).filter(|ms| *ms <= 2000)?;
            let mut memberships = regions.iter().filter(|region| region.servers.contains(id));
            let location = reference_location(&memberships.next()?.id)?;
            if memberships.next().is_some() {
                return None;
            }
            let mut matching = rows.iter().filter(|row| {
                row.relay == *id && row.address == *address && row.location == location
            });
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
        let response = client
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
        let mut body: Response =
            crate::http_body::read_json_bounded(response, 524_288, "route preview")
                .await
                .ok()?;
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
        body.routes.retain(|row| {
            body.targets
                .iter()
                .any(|target| row.target == target.ip && row.location == target.location)
        });
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
    fn regions() -> Vec<super::super::servers::DynamicGamingRegion> {
        vec![super::super::servers::DynamicGamingRegion {
            id: "mumbai".into(),
            name: "Mumbai".into(),
            description: String::new(),
            country_code: "IN".into(),
            servers: vec!["mumbai-01".into()],
        }]
    }
    #[test]
    fn region_references_never_substitute_other_datacenters() {
        assert_eq!(reference_location("mumbai"), Some("Mumbai"));
        assert_eq!(reference_location("singapore"), Some("Singapore"));
        assert_eq!(reference_location("germany"), Some("Frankfurt"));
        assert_eq!(reference_location("jakarta"), Some("Jakarta"));
        assert_eq!(reference_location("israel"), Some("Israel"));
        assert_eq!(reference_location("new-location"), None);
        let servers = vec![(
            "mumbai-01".into(),
            "1.2.3.4:51821".parse().unwrap(),
            Some(20),
        )];
        let mut wrong = sample();
        wrong.location = "Singapore".into();
        wrong.target = "128.116.46.3".parse().unwrap();
        assert!(estimates(&servers, &[wrong], &regions()).is_empty());
    }
    #[test]
    fn full_matrix_selects_mumbai_for_mumbai_and_singapore_for_singapore() {
        let servers = vec![
            (
                "mumbai-01".into(),
                "1.2.3.4:51821".parse().unwrap(),
                Some(20),
            ),
            (
                "singapore-01".into(),
                "1.2.3.5:51821".parse().unwrap(),
                Some(40),
            ),
        ];
        let mut regions = regions();
        regions.push(super::super::servers::DynamicGamingRegion {
            id: "singapore".into(),
            name: "Singapore".into(),
            description: String::new(),
            country_code: "SG".into(),
            servers: vec!["singapore-01".into()],
        });
        let mut singapore = sample();
        singapore.relay = "singapore-01".into();
        singapore.address = servers[1].1;
        singapore.location = "Singapore".into();
        singapore.target = "128.116.46.3".parse().unwrap();
        let mut foreign = sample();
        foreign.relay = "singapore-01".into();
        foreign.address = servers[1].1;
        foreign.rtt_ms = 59;
        let rows = estimates(&servers, &[sample(), singapore, foreign], &regions);
        assert_eq!(rows.len(), 2);
        assert_eq!(
            (&*rows[0].location, rows[0].estimate.estimated_game_ms),
            ("Mumbai", 22)
        );
        assert_eq!(
            (&*rows[1].location, rows[1].estimate.estimated_game_ms),
            ("Singapore", 42)
        );
    }
    #[test]
    fn missing_regional_targets_keep_jakarta_and_israel_on_relay_ping() {
        for region_id in ["jakarta", "israel", "london"] {
            let server_id = format!("{region_id}-01");
            let servers = vec![(
                server_id.clone(),
                "1.2.3.4:51821".parse().unwrap(),
                Some(20),
            )];
            let regions = vec![super::super::servers::DynamicGamingRegion {
                id: region_id.into(),
                name: region_id.into(),
                description: String::new(),
                country_code: String::new(),
                servers: vec![server_id.clone()],
            }];
            let mut other_city = sample();
            other_city.relay = server_id;
            other_city.location = "Singapore".into();
            other_city.target = "128.116.46.3".parse().unwrap();
            assert!(estimates(&servers, &[other_city], &regions).is_empty());
        }
    }
    #[test]
    fn probe_catalog_rejects_non_roblox_addresses_and_control_characters() {
        let mut target = ReferenceTarget {
            ip: "128.116.47.3".parse().unwrap(),
            location: "Mumbai".into(),
        };
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
            estimates(&servers, &[sample()], &regions())[0]
                .estimate
                .estimated_game_ms,
            22
        );
        servers[0].2 = None;
        assert!(estimates(&servers, &[sample()], &regions()).is_empty());
        servers[0].2 = Some(20);
        servers[0].1 = "5.6.7.8:51821".parse().unwrap();
        assert!(estimates(&servers, &[sample()], &regions()).is_empty());
    }
    #[test]
    fn rejects_old_failed_duplicate_or_malformed_reference_samples() {
        let servers = vec![(
            "mumbai-01".into(),
            "1.2.3.4:51821".parse().unwrap(),
            Some(20),
        )];
        assert!(estimates(&servers, &[sample(), sample()], &regions()).is_empty());
        for case in 0..5 {
            let mut row = sample();
            match case {
                0 => row.age_ms = 300_000,
                1 => row.samples = 1,
                2 => row.rtt_ms = 2001,
                3 => row.target = "127.0.0.3".parse().unwrap(),
                _ => row.location = "bad\nlabel".into(),
            }
            assert!(estimates(&servers, &[row], &regions()).is_empty());
        }
    }
}
