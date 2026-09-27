//! Join-time path estimates. Missing measurements never imply a fast route.
use serde::Deserialize;
use std::net::{Ipv4Addr, SocketAddr};
use std::time::{Duration, Instant};

#[derive(Debug, Deserialize)]
pub(crate) struct RouteSample {
    relay: String,
    rtt_ms: u32,
    age_ms: u64,
    samples: u32,
}

#[derive(Deserialize)]
struct Response {
    ip: Ipv4Addr,
    method: String,
    routes: Vec<RouteSample>,
}

#[derive(Debug, PartialEq)]
pub(crate) struct PathChoice {
    pub region: String,
    pub address: SocketAddr,
    pub total_ms: u32,
    pub improvement_ms: u32,
}

/// Every candidate must have both legs, and the current path must be measured
/// before we claim another path improves it. A city name is not a measurement.
pub(crate) fn choose_path(
    servers: &[(String, SocketAddr, Option<u32>)],
    samples: &[RouteSample],
    current: SocketAddr,
) -> Option<PathChoice> {
    let totals: Vec<_> = servers
        .iter()
        .filter_map(|(id, addr, first)| {
            let first = (*first).filter(|ms| *ms <= 2000)?;
            let mut rows = samples.iter().filter(|row| row.relay == *id);
            let row = rows.next()?;
            if rows.next().is_some()
                || row.samples != 2
                || row.age_ms > 330_000
                || row.rtt_ms > 2000
            {
                return None;
            }
            Some((id, *addr, first + row.rtt_ms))
        })
        .collect();
    let current_row = totals.iter().find(|(_, addr, _)| *addr == current)?;
    let best = totals
        .iter()
        .min_by_key(|(id, addr, ms)| (*ms, *addr != current, *id))?;
    let improvement = current_row.2.saturating_sub(best.2);
    // Require at least 10 ms and 10 percent, including cross-city changes.
    let chosen = if improvement >= 10.max(current_row.2.div_ceil(10)) {
        best
    } else {
        current_row
    };
    Some(PathChoice {
        region: chosen.0.clone(),
        address: chosen.1,
        total_ms: chosen.2,
        improvement_ms: current_row.2.saturating_sub(chosen.2),
    })
}

/// No per-packet HTTP, process spawning, DNS target input, or unbounded body.
pub(crate) async fn measure(ip: Ipv4Addr, access_token: &str) -> Vec<RouteSample> {
    static CLIENT: std::sync::OnceLock<reqwest::Client> = std::sync::OnceLock::new();
    let client = CLIENT.get_or_init(|| {
        reqwest::Client::builder()
            .timeout(Duration::from_millis(1200))
            .redirect(reqwest::redirect::Policy::none())
            .build()
            .expect("route measurement HTTP client")
    });
    let started = Instant::now();
    let result = async {
        let mut response = client
            .get("https://www.swifttunnel.net/api/vpn/route-measurements")
            .query(&[("ip", ip.to_string())])
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
        if body.ip != ip || body.method != "icmp_two_leg" || body.routes.len() > 128 {
            return None;
        }
        for row in &mut body.routes {
            if row.relay.len() > 64 {
                return None;
            }
            row.age_ms = row
                .age_ms
                .saturating_add(started.elapsed().as_millis() as u64);
        }
        Some(body.routes)
    }
    .await;
    result.unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use super::*;
    fn servers() -> Vec<(String, SocketAddr, Option<u32>)> {
        vec![
            ("singapore".into(), "127.0.0.1:1".parse().unwrap(), Some(80)),
            ("mumbai".into(), "127.0.0.1:2".parse().unwrap(), Some(10)),
        ]
    }
    fn sample(id: &str, ms: u32) -> RouteSample {
        RouteSample {
            relay: id.into(),
            rtt_ms: ms,
            age_ms: 0,
            samples: 2,
        }
    }
    #[test]
    fn singapore_game_can_be_faster_via_mumbai() {
        let servers = servers();
        let choice = choose_path(
            &servers,
            &[sample("singapore", 5), sample("mumbai", 40)],
            servers[0].1,
        )
        .unwrap();
        assert_eq!(
            (
                choice.region.as_str(),
                choice.total_ms,
                choice.improvement_ms
            ),
            ("mumbai", 50, 35)
        );
    }
    #[test]
    fn missing_current_leg_never_justifies_a_switch() {
        let mut servers = servers();
        assert!(choose_path(&servers, &[sample("mumbai", 4)], servers[0].1).is_none());
        servers[0].2 = None;
        assert!(
            choose_path(
                &servers,
                &[sample("mumbai", 4), sample("singapore", 5)],
                servers[0].1
            )
            .is_none()
        );
    }
    #[test]
    fn incomplete_stale_duplicate_and_unknown_rows_are_not_candidates() {
        for bad in [
            RouteSample {
                age_ms: 330_001,
                ..sample("mumbai", 0)
            },
            RouteSample {
                samples: 1,
                ..sample("mumbai", 0)
            },
            sample("untrusted-relay", 0),
        ] {
            let servers = servers();
            assert_eq!(
                choose_path(&servers, &[sample("singapore", 5), bad], servers[0].1)
                    .unwrap()
                    .address,
                servers[0].1
            );
        }
        let servers = servers();
        assert_eq!(
            choose_path(
                &servers,
                &[
                    sample("singapore", 5),
                    sample("mumbai", 0),
                    sample("mumbai", 0)
                ],
                servers[0].1
            )
            .unwrap()
            .address,
            servers[0].1
        );
    }
    #[test]
    fn small_improvements_and_ties_preserve_current_route() {
        let servers = servers();
        for ms in [66, 75, 100] {
            assert_eq!(
                choose_path(
                    &servers,
                    &[sample("singapore", 5), sample("mumbai", ms)],
                    servers[0].1
                )
                .unwrap()
                .address,
                servers[0].1
            );
        }
    }
}
