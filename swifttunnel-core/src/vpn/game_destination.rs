//! A single short-lived, locally observed Roblox destination. This does not
//! widen speculative tunneling or the relay's destination policy.
use parking_lot::RwLock;
use std::{
    net::Ipv4Addr,
    sync::{
        OnceLock,
        atomic::{AtomicU32, AtomicU64, Ordering},
    },
    time::Instant,
};

#[derive(Clone)]
pub struct ObservedGame {
    pub ip: Ipv4Addr,
    pub job_id: String,
    pub location: Option<String>,
    pub region: Option<crate::geolocation::RobloxRegion>,
    pub prelaunch: bool,
}
const TTL_MS: u64 = 90_000;
static DESTINATION: Destination = Destination::new();

struct Destination {
    active: AtomicU32,
    until: AtomicU64,
    details: RwLock<Option<ObservedGame>>,
}

impl Destination {
    const fn new() -> Self {
        Self {
            active: AtomicU32::new(0),
            until: AtomicU64::new(0),
            details: RwLock::new(None),
        }
    }

    fn register(&self, game: ObservedGame, now: u64) -> bool {
        if !crate::roblox_directory::public_game_ip(game.ip)
            || !crate::roblox_library::valid_job_id(&game.job_id)
            || game
                .location
                .as_ref()
                .is_some_and(|s| s.len() > 80 || s.chars().any(char::is_control))
        {
            return false;
        }
        // Serialize the complete publication with clear/refresh. Publishing
        // just the details under the lock lets a concurrent clear interleave
        // with the address/expiry writes and leave a half-published session.
        let mut details = self.details.write();
        let ip = u32::from(game.ip);
        self.active.store(0, Ordering::Release);
        *details = Some(game);
        self.until
            .store(now.saturating_add(TTL_MS), Ordering::Release);
        self.active.store(ip, Ordering::Release);
        true
    }

    fn contains(&self, ip: Ipv4Addr, now: u64) -> bool {
        let active = self.active.load(Ordering::Acquire);
        active != 0 && active == u32::from(ip) && now < self.until.load(Ordering::Acquire)
    }

    fn details(&self, ip: Ipv4Addr, now: u64) -> Option<ObservedGame> {
        let details = self.details.read();
        details
            .as_ref()
            .filter(|g| g.ip == ip && self.contains(ip, now))
            .cloned()
    }

    fn routing_candidate(&self, ip: Ipv4Addr, now: u64) -> bool {
        // This runs on the packet path. Read the bit without cloning the
        // session's strings for every packet to an observed cloud address.
        if !self.contains(ip, now) {
            return false;
        }
        self.details
            .read()
            .as_ref()
            .is_some_and(|game| game.ip == ip && game.prelaunch && self.contains(ip, now))
    }

    fn refresh(&self, now: u64) {
        let details = self.details.read();
        if details.is_some() {
            self.until
                .store(now.saturating_add(TTL_MS), Ordering::Release);
        }
    }

    fn clear_session(&self, job_id: Option<&str>) -> bool {
        let mut details = self.details.write();
        if let Some(job_id) = job_id
            && !details
                .as_ref()
                .is_some_and(|game| game.job_id.eq_ignore_ascii_case(job_id))
        {
            return false;
        }
        self.active.store(0, Ordering::Release);
        self.until.store(0, Ordering::Release);
        *details = None;
        true
    }
}
fn tick() -> u64 {
    static START: OnceLock<Instant> = OnceLock::new();
    START.get_or_init(Instant::now).elapsed().as_millis() as u64
}

pub fn register(game: ObservedGame) -> bool {
    DESTINATION.register(game, tick())
}
pub fn contains(ip: Ipv4Addr) -> bool {
    DESTINATION.contains(ip, tick())
}
pub fn known_or_observed(ip: Ipv4Addr) -> bool {
    crate::geolocation::is_roblox_game_server_ip(ip) || contains(ip)
}
pub fn details(ip: Ipv4Addr) -> Option<ObservedGame> {
    DESTINATION.details(ip, tick())
}
pub fn routing_candidate(ip: Ipv4Addr) -> bool {
    crate::geolocation::is_roblox_game_server_ip(ip) || DESTINATION.routing_candidate(ip, tick())
}
pub fn refresh() {
    DESTINATION.refresh(tick());
}
pub fn clear() {
    DESTINATION.clear_session(None);
}

/// A late leave event must not erase a different game or a new prelaunch target.
pub fn clear_for_session(job_id: &str) -> bool {
    DESTINATION.clear_session(Some(job_id))
}

#[cfg(test)]
mod tests {
    use super::*;
    const FIRST: &str = "550e8400-e29b-41d4-a716-446655440000";
    const SECOND: &str = "550e8400-e29b-41d4-a716-446655440001";

    fn game(job: &str) -> ObservedGame {
        ObservedGame {
            ip: "34.1.2.3".parse().unwrap(),
            job_id: job.into(),
            location: None,
            region: None,
            prelaunch: false,
        }
    }

    #[test]
    fn a_late_leave_cannot_erase_a_new_game_even_at_the_same_ip() {
        let destination = Destination::new();
        assert!(destination.register(game(FIRST), 0));
        assert!(destination.register(game(SECOND), 10));
        assert!(!destination.clear_session(Some(FIRST)));
        assert_eq!(
            destination.details(game(SECOND).ip, 11).unwrap().job_id,
            SECOND
        );
        assert!(destination.clear_session(Some(&SECOND.to_ascii_uppercase())));
        assert!(!destination.contains(game(SECOND).ip, 12));
        assert!(destination.details(game(SECOND).ip, 12).is_none());
    }

    #[test]
    fn clear_never_turns_the_unspecified_address_into_an_observed_destination() {
        let destination = Destination::new();
        destination.register(game(FIRST), 100);
        destination.clear_session(None);
        destination.refresh(200);
        assert!(!destination.contains(Ipv4Addr::UNSPECIFIED, 201));
        assert!(!destination.contains(game(FIRST).ip, 201));
    }

    #[test]
    fn expiration_and_prelaunch_policy_remain_distinct() {
        let destination = Destination::new();
        let mut observed = game(FIRST);
        assert!(destination.register(observed.clone(), 0));
        assert!(destination.contains(observed.ip, 1));
        assert!(!destination.routing_candidate(observed.ip, 1));
        observed.prelaunch = true;
        destination.register(observed.clone(), 2);
        assert!(destination.routing_candidate(observed.ip, 3));
        assert!(!destination.routing_candidate(observed.ip, 2 + TTL_MS));
        assert!(destination.details(observed.ip, 2 + TTL_MS).is_none());
    }

    #[test]
    fn concurrent_publish_clear_and_refresh_leave_a_consistent_final_session() {
        let destination = std::sync::Arc::new(Destination::new());
        let workers: Vec<_> = (0..4)
            .map(|index| {
                let destination = destination.clone();
                std::thread::spawn(move || {
                    for now in 0..500 {
                        match index {
                            0 => {
                                destination.register(game(FIRST), now);
                            }
                            1 => {
                                destination.register(game(SECOND), now);
                            }
                            2 => {
                                destination.clear_session(Some(FIRST));
                            }
                            _ => destination.refresh(now),
                        }
                    }
                })
            })
            .collect();
        for worker in workers {
            worker.join().unwrap();
        }
        destination.register(game(SECOND), 1000);
        assert!(!destination.clear_session(Some(FIRST)));
        assert!(destination.contains(game(SECOND).ip, 1001));
        assert_eq!(
            destination.details(game(SECOND).ip, 1001).unwrap().job_id,
            SECOND
        );
        destination.clear_session(None);
        assert!(destination.details.read().is_none());
        assert_eq!(destination.active.load(Ordering::Acquire), 0);
        assert_eq!(destination.until.load(Ordering::Acquire), 0);
    }
    #[test]
    fn observed_destination_never_accepts_private_addresses_or_invalid_session_ids() {
        for ip in ["127.0.0.1", "169.254.169.254", "10.0.0.1"] {
            assert!(!register(ObservedGame {
                ip: ip.parse().unwrap(),
                job_id: "550e8400-e29b-41d4-a716-446655440000".into(),
                location: None,
                region: None,
                prelaunch: false
            }));
        }
        assert!(!register(ObservedGame {
            ip: "34.1.2.3".parse().unwrap(),
            job_id: "bad".into(),
            location: None,
            region: None,
            prelaunch: false
        }));
    }
}
