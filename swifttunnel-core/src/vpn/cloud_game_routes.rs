//! Cloud gameplay needs verified process ownership before its first delivery.
//! Decisions live for the interceptor lifetime: later log metadata cannot move
//! a direct UDP conversation onto a different source address.
use super::process_cache::ProcessSnapshot;
use super::process_tracker::{ConnectionKey, Protocol};
use ahash::{AHashMap, AHashSet};
use std::{
    net::Ipv4Addr,
    time::{Duration, Instant},
};

pub(super) const OWNER_WAIT: Duration = Duration::from_millis(750);
const MAX_FLOWS: usize = 4096;
const MAX_FRAGMENTS: usize = 2048;
const FRAGMENT_LIFETIME: Duration = Duration::from_secs(30);
type Flow = (Ipv4Addr, u16, Ipv4Addr, u16);
type Fragment = (Ipv4Addr, Ipv4Addr, u16);

#[inline]
pub(crate) fn is_cloud_game_ip(ip: Ipv4Addr) -> bool {
    let octets = ip.octets();
    octets[0] == 34 && octets[1] == 18
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum Route {
    Hold,
    Direct,
    Relay,
}

#[derive(Clone, Copy)]
enum Decision {
    Waiting(Instant),
    Direct,
    Relay(u32),
}

pub(super) struct CloudGameRoutes {
    flows: AHashMap<Flow, Decision>,
    fragments: AHashMap<Fragment, (Option<Flow>, Instant)>,
    preexisting: AHashSet<(Ipv4Addr, u16)>,
    saturated: bool,
}

impl CloudGameRoutes {
    fn remember_fragment(&mut self, key: Fragment, flow: Option<Flow>, now: Instant) {
        if self.fragments.len() >= MAX_FRAGMENTS {
            self.fragments.retain(|_, (_, until)| *until > now);
        }
        if self.fragments.len() < MAX_FRAGMENTS || self.fragments.contains_key(&key) {
            self.fragments.insert(key, (flow, now + FRAGMENT_LIFETIME));
        }
    }

    pub fn new(snapshot: &ProcessSnapshot) -> Self {
        let mut preexisting = AHashSet::new();
        let mut saturated = false;
        for key in snapshot
            .connections
            .keys()
            .filter(|key| key.protocol == Protocol::Udp)
        {
            if preexisting.len() == MAX_FLOWS {
                saturated = true;
                break;
            }
            preexisting.insert((key.local_ip, key.local_port));
        }
        Self {
            flows: AHashMap::new(),
            fragments: AHashMap::new(),
            preexisting,
            saturated,
        }
    }

    /// None leaves the existing non-cloud routing policy untouched.
    pub fn classify(
        &mut self,
        ip: &[u8],
        snapshot: &ProcessSnapshot,
        enabled: bool,
        now: Instant,
    ) -> Option<Route> {
        if ip.len() < 20 || ip[0] >> 4 != 4 || ip[9] != 17 {
            return None;
        }
        let src = Ipv4Addr::new(ip[12], ip[13], ip[14], ip[15]);
        let dst = Ipv4Addr::new(ip[16], ip[17], ip[18], ip[19]);
        if !is_cloud_game_ip(dst) {
            return None;
        }
        let ihl = usize::from(ip[0] & 15) * 4;
        if ihl < 20 || ip.len() < ihl {
            return Some(Route::Direct);
        }
        let bits = u16::from_be_bytes([ip[6], ip[7]]);
        let fragment = (src, dst, u16::from_be_bytes([ip[4], ip[5]]));
        let flow = if bits & 0x1fff != 0 {
            // Never leak a tail direct while its first fragment is held.
            match self
                .fragments
                .get(&fragment)
                .filter(|(_, until)| *until > now)
            {
                Some((Some(flow), _)) => *flow,
                Some((None, _)) => return None,
                None => return Some(Route::Hold),
            }
        } else {
            if ip.len() < ihl + 8 {
                return Some(Route::Direct);
            }
            let port = u16::from_be_bytes([ip[ihl + 2], ip[ihl + 3]]);
            if matches!(port, 53 | 443) {
                if bits & 0x2000 != 0 {
                    self.remember_fragment(fragment, None, now);
                }
                return None;
            }
            let flow = (src, u16::from_be_bytes([ip[ihl], ip[ihl + 1]]), dst, port);
            if bits & 0x2000 != 0 {
                self.remember_fragment(fragment, Some(flow), now);
            }
            flow
        };
        let exact = ConnectionKey::new(flow.0, flow.1, Protocol::Udp);
        let any = ConnectionKey::new(Ipv4Addr::UNSPECIFIED, flow.1, Protocol::Udp);
        let owner = snapshot
            .connections
            .get(&exact)
            .or_else(|| snapshot.connections.get(&any))
            .copied();
        let roblox_owner = owner.filter(|pid| {
            snapshot.is_tunnel_pid_public(*pid)
                && snapshot.pid_names.get(pid).is_some_and(|name| {
                    let basename = name.rsplit(['\\', '/']).next().unwrap_or(name);
                    crate::process_names::ROBLOX_PLAYER_PROCESS_NAMES
                        .iter()
                        .any(|candidate| basename.eq_ignore_ascii_case(candidate))
                })
        });
        let known_other = roblox_owner.is_none()
            && owner.is_some_and(|pid| snapshot.pid_names.contains_key(&pid));
        let previous = self.flows.get(&flow).copied();
        let decision = match previous {
            Some(Decision::Direct) => Decision::Direct,
            Some(Decision::Relay(pid)) => {
                // A published different owner denotes a reused local socket.
                // An incomplete snapshot must not change an established path.
                if owner.is_some_and(|owner| owner != pid) || known_other {
                    Decision::Direct
                } else {
                    Decision::Relay(pid)
                }
            }
            waiting => {
                if self.saturated && waiting.is_none() {
                    return Some(Route::Direct);
                }
                let since = match waiting {
                    Some(Decision::Waiting(since)) => since,
                    _ => now,
                };
                if !enabled
                    || self.preexisting.contains(&(flow.0, flow.1))
                    || self.preexisting.contains(&(Ipv4Addr::UNSPECIFIED, flow.1))
                {
                    Decision::Direct
                } else if let Some(pid) = roblox_owner {
                    Decision::Relay(pid)
                } else if known_other || now.saturating_duration_since(since) >= OWNER_WAIT {
                    Decision::Direct
                } else {
                    Decision::Waiting(since)
                }
            }
        };
        if !self.flows.contains_key(&flow) && self.flows.len() >= MAX_FLOWS {
            // Do not evict an active direct decision and later promote it.
            self.saturated = true;
            return Some(Route::Direct);
        }
        self.flows.insert(flow, decision);
        if let Decision::Relay(pid) = decision
            && !matches!(previous, Some(Decision::Relay(_)))
        {
            log::info!(
                "Cloud gameplay route selected: {}:{} -> {}:{} via relay, Roblox pid={pid}",
                flow.0,
                flow.1,
                flow.2,
                flow.3
            );
        }
        Some(match decision {
            Decision::Waiting(_) => Route::Hold,
            Decision::Direct => Route::Direct,
            Decision::Relay(_) => Route::Relay,
        })
    }

    pub fn keep_direct(&mut self, ip: &[u8]) {
        if ip.len() < 28 {
            return;
        }
        let ihl = usize::from(ip[0] & 15) * 4;
        if ihl < 20 || ip.len() < ihl + 8 {
            return;
        }
        let bits = u16::from_be_bytes([ip[6], ip[7]]);
        let src = Ipv4Addr::new(ip[12], ip[13], ip[14], ip[15]);
        let dst = Ipv4Addr::new(ip[16], ip[17], ip[18], ip[19]);
        let flow = if bits & 0x1fff != 0 {
            self.fragments
                .get(&(src, dst, u16::from_be_bytes([ip[4], ip[5]])))
                .and_then(|(flow, _)| *flow)
        } else {
            Some((
                src,
                u16::from_be_bytes([ip[ihl], ip[ihl + 1]]),
                dst,
                u16::from_be_bytes([ip[ihl + 2], ip[ihl + 3]]),
            ))
        };
        if let Some(flow) = flow
            && let Some(decision) = self.flows.get_mut(&flow)
        {
            *decision = Decision::Direct;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn packet() -> Vec<u8> {
        let mut ip = vec![0; 28];
        ip[0] = 0x45;
        ip[9] = 17;
        ip[12..16].copy_from_slice(&[192, 168, 1, 2]);
        ip[16..20].copy_from_slice(&[34, 18, 186, 248]);
        ip[20..22].copy_from_slice(&50000u16.to_be_bytes());
        ip[22..24].copy_from_slice(&56000u16.to_be_bytes());
        ip
    }
    fn snapshot(owner: Option<(u32, &str)>) -> ProcessSnapshot {
        let mut snapshot = ProcessSnapshot::empty(["roblox".into()].into_iter().collect());
        if let Some((pid, name)) = owner {
            snapshot.connections.insert(
                ConnectionKey::new(Ipv4Addr::UNSPECIFIED, 50000, Protocol::Udp),
                pid,
            );
            snapshot.pid_names.insert(pid, name.into());
            if name.starts_with("roblox") {
                snapshot.tunnel_pids.insert(pid);
            }
        }
        snapshot
    }
    #[test]
    fn cloud_first_delivery_waits_for_roblox_and_cannot_be_changed_by_log_metadata() {
        let empty = snapshot(None);
        let mut gate = CloudGameRoutes::new(&empty);
        let now = Instant::now();
        assert_eq!(
            gate.classify(&packet(), &empty, true, now),
            Some(Route::Hold)
        );
        assert_eq!(
            gate.classify(
                &packet(),
                &snapshot(Some((7, "robloxplayerbeta.exe"))),
                true,
                now
            ),
            Some(Route::Relay)
        );
        assert_eq!(
            gate.classify(&packet(), &empty, true, now + OWNER_WAIT),
            Some(Route::Relay)
        );
    }
    #[test]
    fn cloud_other_apps_and_preexisting_sockets_stay_direct() {
        let empty = snapshot(None);
        let now = Instant::now();
        let roblox = snapshot(Some((7, "robloxplayerbeta.exe")));
        let mut gate = CloudGameRoutes::new(&empty);
        assert_eq!(
            gate.classify(&packet(), &snapshot(Some((8, "browser.exe"))), true, now),
            Some(Route::Direct)
        );
        assert_eq!(
            gate.classify(&packet(), &roblox, true, now),
            Some(Route::Direct)
        );
        assert_eq!(
            CloudGameRoutes::new(&roblox).classify(&packet(), &roblox, true, now),
            Some(Route::Direct)
        );
    }
    #[test]
    fn cloud_owner_timeout_and_explicit_bypass_never_promote_a_live_direct_flow() {
        let empty = snapshot(None);
        let now = Instant::now();
        let mut gate = CloudGameRoutes::new(&empty);
        assert_eq!(
            gate.classify(&packet(), &empty, true, now),
            Some(Route::Hold)
        );
        assert_eq!(
            gate.classify(&packet(), &empty, true, now + OWNER_WAIT),
            Some(Route::Direct)
        );
        let roblox = snapshot(Some((7, "robloxplayerbeta.exe")));
        assert_eq!(
            gate.classify(&packet(), &roblox, true, now + OWNER_WAIT),
            Some(Route::Direct)
        );
        let mut gate = CloudGameRoutes::new(&empty);
        assert_eq!(
            gate.classify(&packet(), &roblox, true, now),
            Some(Route::Relay)
        );
        gate.keep_direct(&packet());
        assert_eq!(
            gate.classify(&packet(), &roblox, true, now),
            Some(Route::Direct)
        );
    }
    #[test]
    fn cloud_fragments_share_ownership_decision_and_other_ranges_are_untouched() {
        let empty = snapshot(None);
        let roblox = snapshot(Some((7, "robloxplayerbeta.exe")));
        let now = Instant::now();
        let mut gate = CloudGameRoutes::new(&empty);
        let mut first = packet();
        first[6] = 0x20;
        let mut tail = packet();
        tail[7] = 1;
        assert_eq!(gate.classify(&tail, &empty, true, now), Some(Route::Hold));
        assert_eq!(gate.classify(&first, &empty, true, now), Some(Route::Hold));
        assert_eq!(
            gate.classify(&first, &roblox, true, now),
            Some(Route::Relay)
        );
        assert_eq!(gate.classify(&tail, &roblox, true, now), Some(Route::Relay));
        first[16..20].copy_from_slice(&[34, 19, 186, 248]);
        assert_eq!(gate.classify(&first, &roblox, true, now), None);
    }

    #[test]
    fn cloud_routing_respects_disabled_mode_socket_ownership_and_reuse() {
        let empty = snapshot(None);
        let roblox = snapshot(Some((7, "robloxplayerbeta.exe")));
        let now = Instant::now();
        let mut gate = CloudGameRoutes::new(&empty);
        assert_eq!(
            gate.classify(&packet(), &roblox, false, now),
            Some(Route::Direct)
        );
        assert_eq!(
            gate.classify(&packet(), &roblox, true, now),
            Some(Route::Direct)
        );
        let mut gate = CloudGameRoutes::new(&empty);
        assert_eq!(
            gate.classify(&packet(), &roblox, true, now),
            Some(Route::Relay)
        );
        let browser = snapshot(Some((8, "browser.exe")));
        assert_eq!(
            gate.classify(&packet(), &browser, true, now),
            Some(Route::Direct)
        );
        // A tunnel-owned port at a different interface is not ownership of this flow.
        let mut other_interface = roblox.clone();
        other_interface.connections.clear();
        other_interface.connections.insert(
            ConnectionKey::new(Ipv4Addr::new(10, 0, 0, 1), 50000, Protocol::Udp),
            7,
        );
        let mut gate = CloudGameRoutes::new(&empty);
        assert_eq!(
            gate.classify(&packet(), &other_interface, true, now),
            Some(Route::Hold)
        );
    }

    #[test]
    fn cloud_http_fragments_keep_existing_policy_and_saturation_never_evicts_live_flows() {
        let empty = snapshot(None);
        let roblox = snapshot(Some((7, "robloxplayerbeta.exe")));
        let now = Instant::now();
        let mut gate = CloudGameRoutes::new(&empty);
        let mut first = packet();
        first[6] = 0x20;
        first[22..24].copy_from_slice(&443u16.to_be_bytes());
        let mut tail = first.clone();
        tail[6] = 0;
        tail[7] = 1;
        assert_eq!(gate.classify(&first, &roblox, true, now), None);
        assert_eq!(gate.classify(&tail, &roblox, true, now), None);
        assert_eq!(
            gate.classify(&packet(), &roblox, true, now),
            Some(Route::Relay)
        );
        for port in 1..MAX_FLOWS as u16 {
            let mut next = packet();
            next[22..24].copy_from_slice(&port.to_be_bytes());
            // Reserve explicit direct decisions in an otherwise empty fixture.
            let flow = (
                Ipv4Addr::new(192, 168, 1, 2),
                50000,
                Ipv4Addr::new(34, 18, 186, 248),
                port,
            );
            gate.flows.insert(flow, Decision::Direct);
        }
        let mut next = packet();
        next[22..24].copy_from_slice(&56001u16.to_be_bytes());
        assert_eq!(
            gate.classify(&next, &roblox, true, now),
            Some(Route::Direct)
        );
        assert_eq!(gate.flows.len(), MAX_FLOWS);
        assert_eq!(
            gate.classify(&packet(), &roblox, true, now),
            Some(Route::Relay)
        );
        assert!(!crate::geolocation::is_roblox_game_server_ip(
            Ipv4Addr::new(34, 18, 186, 248)
        ));
    }

    #[test]
    fn cloud_fragment_ids_can_be_reused_and_expired_entries_release_capacity() {
        let mut gate = CloudGameRoutes::new(&snapshot(None));
        let now = Instant::now();
        let src = Ipv4Addr::new(192, 168, 1, 2);
        let dst = Ipv4Addr::new(34, 18, 186, 248);
        let flow = (src, 50000, dst, 56000);
        for id in 0..MAX_FRAGMENTS as u16 {
            gate.remember_fragment((src, dst, id), Some(flow), now);
        }
        let replacement = (src, 50000, dst, 56001);
        gate.remember_fragment((src, dst, 0), Some(replacement), now);
        assert_eq!(
            gate.fragments.get(&(src, dst, 0)).unwrap().0,
            Some(replacement)
        );
        gate.remember_fragment((src, dst, 65000), Some(flow), now + FRAGMENT_LIFETIME);
        assert_eq!(gate.fragments.len(), 1);
        assert!(gate.fragments.contains_key(&(src, dst, 65000)));
    }
}
