//! A single short-lived, locally observed Roblox destination. This does not
//! widen speculative tunneling or the relay's destination policy.
use parking_lot::RwLock;
use std::{
    net::Ipv4Addr,
    sync::{
        OnceLock,
        atomic::{AtomicU32, AtomicU64, Ordering},
    },
    time::{Duration, Instant},
};

#[derive(Clone)]
pub struct ObservedGame {
    pub ip: Ipv4Addr,
    pub job_id: String,
    pub location: Option<String>,
    pub region: Option<crate::geolocation::RobloxRegion>,
    pub prelaunch: bool,
}
static ACTIVE: AtomicU32 = AtomicU32::new(0);
static UNTIL: AtomicU64 = AtomicU64::new(0);
static DETAILS: RwLock<Option<ObservedGame>> = RwLock::new(None);
fn tick() -> u64 {
    static START: OnceLock<Instant> = OnceLock::new();
    START.get_or_init(Instant::now).elapsed().as_millis() as u64
}

pub fn register(game: ObservedGame) -> bool {
    if !crate::roblox_directory::public_game_ip(game.ip)
        || !crate::roblox_library::valid_job_id(&game.job_id)
        || game
            .location
            .as_ref()
            .is_some_and(|s| s.len() > 80 || s.chars().any(char::is_control))
    {
        return false;
    }
    ACTIVE.store(0, Ordering::Release);
    *DETAILS.write() = Some(game.clone());
    UNTIL.store(
        tick() + Duration::from_secs(90).as_millis() as u64,
        Ordering::Release,
    );
    ACTIVE.store(u32::from(game.ip), Ordering::Release);
    true
}
pub fn contains(ip: Ipv4Addr) -> bool {
    ACTIVE.load(Ordering::Acquire) == u32::from(ip) && tick() < UNTIL.load(Ordering::Acquire)
}
pub fn known_or_observed(ip: Ipv4Addr) -> bool {
    crate::geolocation::is_roblox_game_server_ip(ip) || contains(ip)
}
pub fn details(ip: Ipv4Addr) -> Option<ObservedGame> {
    if !contains(ip) {
        return None;
    }
    DETAILS.read().as_ref().filter(|g| g.ip == ip).cloned()
}
pub fn routing_candidate(ip: Ipv4Addr) -> bool {
    crate::geolocation::is_roblox_game_server_ip(ip) || details(ip).is_some_and(|g| g.prelaunch)
}
pub fn refresh() {
    if ACTIVE.load(Ordering::Acquire) != 0 {
        UNTIL.store(tick() + 90_000, Ordering::Release);
    }
}
pub fn clear() {
    ACTIVE.store(0, Ordering::Release);
    *DETAILS.write() = None;
}

#[cfg(test)]
mod tests {
    use super::*;
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
