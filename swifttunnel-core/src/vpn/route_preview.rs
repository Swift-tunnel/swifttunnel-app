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
    routes: Vec<ReferenceSample>,
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

pub async fn fetch(access_token: &str) -> Vec<ReferenceSample> {
    static CLIENT: std::sync::OnceLock<reqwest::Client> = std::sync::OnceLock::new();
    let client = CLIENT.get_or_init(|| {
        reqwest::Client::builder()
            .timeout(Duration::from_millis(1500))
            .redirect(reqwest::redirect::Policy::none())
            .build()
            .expect("reference measurement client")
    });
    let started = Instant::now();
    let result = async {
        let mut response = client
            .get("https://www.swifttunnel.net/api/vpn/route-measurements/preview")
            .bearer_auth(access_token)
            .send()
            .await
            .ok()?;
        if !response.status().is_success() {
            return None;
        }
        let mut bytes = Vec::new();
        while let Some(chunk) = response.chunk().await.ok()? {
            if bytes.len() + chunk.len() > 65_536 {
                return None;
            }
            bytes.extend_from_slice(&chunk);
        }
        let mut body: Response = serde_json::from_slice(&bytes).ok()?;
        if body.method != "icmp_reference_two_leg" || body.routes.len() > 128 {
            return None;
        }
        for row in &mut body.routes {
            row.age_ms = row
                .age_ms
                .saturating_add(started.elapsed().as_millis() as u64);
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
