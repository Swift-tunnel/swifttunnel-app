//! Auto Routing - Automatic relay server switching based on game server region
//!
//! Detects when a Roblox player gets teleported to a game server in a different
//! region and automatically switches the relay server for optimal latency.
//!
//! Similar to GearUp's AIR (Adaptive Intelligent Routing) and ExitLag's
//! automatic region detection.

use std::collections::{HashSet, VecDeque};
use std::net::{Ipv4Addr, SocketAddr};
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};
use parking_lot::RwLock;
use crate::geolocation::RobloxRegion;

/// Minimum time between relay switches to prevent flapping
const MIN_SWITCH_INTERVAL: Duration = Duration::from_secs(10);

/// Maximum switches per minute
const MAX_SWITCHES_PER_MINUTE: u32 = 3;

/// Auto-routing state
pub struct AutoRouter {
    /// Whether auto-routing is enabled
    enabled: AtomicBool,
    /// Current detected Roblox game server region
    current_game_region: RwLock<Option<RobloxRegion>>,
    /// Current relay server address
    current_relay_addr: RwLock<Option<SocketAddr>>,
    /// Current SwiftTunnel region name (e.g. "singapore")
    current_st_region: RwLock<String>,
    /// Last time a relay switch occurred
    last_switch_time: RwLock<Instant>,
    /// Number of switches in the current minute window
    switches_this_minute: RwLock<(u32, Instant)>,
    /// Game server IPs we've already routed (to detect new teleports)
    seen_game_servers: RwLock<HashSet<Ipv4Addr>>,
    /// Callback: list of (region_id, relay_addr) for available servers
    available_servers: RwLock<Vec<(String, SocketAddr)>>,
    /// Log of auto-routing events for UI display
    event_log: RwLock<VecDeque<AutoRoutingEvent>>,
    /// Channel to send game server IPs for async geolocation lookup
    lookup_sender: RwLock<Option<tokio::sync::mpsc::UnboundedSender<Ipv4Addr>>>,
}

/// An auto-routing event for the UI log
#[derive(Debug, Clone)]
pub struct AutoRoutingEvent {
    pub timestamp: Instant,
    pub from_region: String,
    pub to_region: String,
    pub game_server_region: String,
    pub reason: String,
}

/// Result of evaluating a game server IP for auto-routing
#[derive(Debug)]
pub enum AutoRoutingAction {
    /// No action needed - current relay is optimal or conditions not met
    NoAction,
    /// Switch to a different relay server
    SwitchRelay {
        new_addr: SocketAddr,
        new_region: String,
        game_region: RobloxRegion,
    },
}

impl AutoRouter {
    pub fn new(enabled: bool, initial_region: &str) -> Self {
        Self {
            enabled: AtomicBool::new(enabled),
            current_game_region: RwLock::new(None),
            current_relay_addr: RwLock::new(None),
            current_st_region: RwLock::new(initial_region.to_string()),
            last_switch_time: RwLock::new(Instant::now() - MIN_SWITCH_INTERVAL),
            switches_this_minute: RwLock::new((0, Instant::now())),
            seen_game_servers: RwLock::new(HashSet::new()),
            available_servers: RwLock::new(Vec::new()),
            event_log: RwLock::new(VecDeque::new()),
            lookup_sender: RwLock::new(None),
        }
    }

    /// Set the channel for sending game server IPs to the background lookup task
    pub fn set_lookup_channel(&self, sender: tokio::sync::mpsc::UnboundedSender<Ipv4Addr>) {
        *self.lookup_sender.write() = Some(sender);
    }

    /// Enable or disable auto-routing
    pub fn set_enabled(&self, enabled: bool) {
        self.enabled.store(enabled, Ordering::Release);
        log::info!("Auto-routing: {}", if enabled { "enabled" } else { "disabled" });
    }

    pub fn is_enabled(&self) -> bool {
        self.enabled.load(Ordering::Acquire)
    }

    /// Update the list of available relay servers
    /// Called when server list is fetched/refreshed
    pub fn set_available_servers(&self, servers: Vec<(String, SocketAddr)>) {
        log::info!("Auto-routing: Updated available servers ({} servers)", servers.len());
        *self.available_servers.write() = servers;
    }

    /// Set the current relay address (called on connect)
    pub fn set_current_relay(&self, addr: SocketAddr, region: &str) {
        *self.current_relay_addr.write() = Some(addr);
        *self.current_st_region.write() = region.to_string();
        log::info!("Auto-routing: Current relay set to {} ({})", addr, region);
    }

    /// Get the current detected game server region
    pub fn current_game_region(&self) -> Option<RobloxRegion> {
        self.current_game_region.read().clone()
    }

    /// Get the current SwiftTunnel region
    pub fn current_region(&self) -> String {
        self.current_st_region.read().clone()
    }

    /// Get recent auto-routing events for UI display
    pub fn recent_events(&self, max: usize) -> Vec<AutoRoutingEvent> {
        let events = self.event_log.read();
        events.iter().rev().take(max).cloned().collect()
    }

    /// Evaluate a detected game server IP and trigger an async region lookup.
    ///
    /// This is called from the packet processing hot path when a new Roblox game server
    /// IP is detected. It must be fast (no blocking). New IPs are sent to a background
    /// task that performs an ipinfo.io lookup and switches the relay if needed.
    ///
    /// Always returns NoAction — the actual relay switch happens asynchronously
    /// via `handle_region_lookup()` when the ipinfo.io response arrives.
    pub fn evaluate_game_server(&self, game_server_ip: Ipv4Addr) -> AutoRoutingAction {
        if !self.is_enabled() {
            return AutoRoutingAction::NoAction;
        }

        // Check if this is a new game server IP (teleport detection).
        // Use try_write() to avoid blocking the hot path — if the lock is
        // contended, fall through to NoAction and retry on the next packet.
        let is_new_ip = match self.seen_game_servers.try_write() {
            Some(mut seen) => seen.insert(game_server_ip),
            None => return AutoRoutingAction::NoAction,
        };

        if !is_new_ip {
            return AutoRoutingAction::NoAction;
        }

        // New IP detected — send to background lookup task for ipinfo.io resolution
        if let Some(sender) = self.lookup_sender.read().as_ref() {
            let _ = sender.send(game_server_ip);
            log::info!("Auto-routing: New game server {} detected, looking up region...", game_server_ip);
        }

        AutoRoutingAction::NoAction
    }

    /// Handle the result of an async region lookup (called from background task).
    ///
    /// Determines if we need to switch relays based on the looked-up region.
    /// Returns `Some((new_addr, new_region))` if a switch should happen.
    pub fn handle_region_lookup(&self, game_region: RobloxRegion) -> Option<(SocketAddr, String)> {
        if game_region == RobloxRegion::Unknown {
            return None;
        }

        let best_st_region = game_region.best_swifttunnel_region()?;
        let current_st_region = self.current_st_region.read().clone();

        // Check if we're already on the best region
        if current_st_region == best_st_region || current_st_region.starts_with(&format!("{}-", best_st_region)) {
            *self.current_game_region.write() = Some(game_region);
            return None;
        }

        // Find the best server in the target region
        let servers = self.available_servers.read();
        let best_server = servers.iter()
            .find(|(region, _)| region == best_st_region || region.starts_with(&format!("{}-", best_st_region)));

        if let Some((new_region, new_addr)) = best_server {
            let new_region = new_region.clone();
            let new_addr = *new_addr;
            drop(servers);

            // Record the switch (also performs rate-limit check atomically)
            if self.record_switch(&current_st_region, &new_region, &game_region, new_addr) {
                Some((new_addr, new_region))
            } else {
                None
            }
        } else {
            log::warn!(
                "Auto-routing: No server found for region '{}' (game region: {})",
                best_st_region, game_region
            );
            None
        }
    }

    /// Record a relay switch, atomically checking rate limits.
    /// Returns true if the switch was recorded, false if rate-limited or already switched.
    fn record_switch(&self, from_region: &str, to_region: &str, game_region: &RobloxRegion, new_addr: SocketAddr) -> bool {
        // Idempotency: another worker may have already switched to this region
        if *self.current_st_region.read() == to_region {
            return false;
        }

        let now = Instant::now();

        // Check minimum interval
        if now.duration_since(*self.last_switch_time.read()) < MIN_SWITCH_INTERVAL {
            log::debug!("Auto-routing: Rate limited (min interval), skipping switch");
            return false;
        }

        // Check per-minute limit under a single write lock
        let mut window = self.switches_this_minute.write();
        if now.duration_since(window.1) > Duration::from_secs(60) {
            // Reset minute window
            *window = (0, now);
        }
        if window.0 >= MAX_SWITCHES_PER_MINUTE {
            log::debug!("Auto-routing: Rate limited (max per minute), skipping switch");
            return false;
        }
        // Rate limit passed - increment counter while we still hold the lock
        window.0 += 1;
        drop(window);

        *self.last_switch_time.write() = now;
        *self.current_st_region.write() = to_region.to_string();
        *self.current_relay_addr.write() = Some(new_addr);
        *self.current_game_region.write() = Some(game_region.clone());

        // Add to event log (keep last 20 events)
        let event = AutoRoutingEvent {
            timestamp: now,
            from_region: from_region.to_string(),
            to_region: to_region.to_string(),
            game_server_region: game_region.display_name().to_string(),
            reason: format!(
                "Game server moved to {} - switching from {} to {}",
                game_region.display_name(), from_region, to_region
            ),
        };

        let mut log = self.event_log.write();
        log.push_back(event);
        if log.len() > 20 {
            log.pop_front();
        }

        log::info!(
            "Auto-routing: Switched {} -> {} (game server in {})",
            from_region, to_region, game_region.display_name()
        );

        true
    }

    /// Reset state (call on disconnect)
    pub fn reset(&self) {
        *self.current_game_region.write() = None;
        *self.current_relay_addr.write() = None;
        self.seen_game_servers.write().clear();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::geolocation::RobloxRegion;

    fn make_servers() -> Vec<(String, SocketAddr)> {
        vec![
            ("singapore".to_string(), "54.255.205.216:51821".parse().unwrap()),
            ("singapore-02".to_string(), "51.79.128.67:51821".parse().unwrap()),
            ("mumbai".to_string(), "3.111.230.152:51821".parse().unwrap()),
            ("america-01".to_string(), "54.225.245.114:51821".parse().unwrap()),
            ("tokyo-02".to_string(), "45.32.253.124:51821".parse().unwrap()),
            ("sydney".to_string(), "54.153.235.165:51821".parse().unwrap()),
            ("germany-01".to_string(), "63.181.160.158:51821".parse().unwrap()),
            ("london-01".to_string(), "172.237.119.240:51821".parse().unwrap()),
            ("brazil-02".to_string(), "172.233.20.214:51821".parse().unwrap()),
        ]
    }

    #[test]
    fn test_auto_router_disabled() {
        let router = AutoRouter::new(false, "singapore");
        router.set_available_servers(make_servers());

        // Should always return NoAction when disabled
        let action = router.evaluate_game_server(Ipv4Addr::new(128, 116, 102, 1));
        assert!(matches!(action, AutoRoutingAction::NoAction));
    }

    #[test]
    fn test_auto_router_evaluate_always_noaction() {
        // evaluate_game_server now always returns NoAction (async lookup handles switching)
        let router = AutoRouter::new(true, "singapore");
        router.set_available_servers(make_servers());
        router.set_current_relay("54.255.205.216:51821".parse().unwrap(), "singapore");

        let action = router.evaluate_game_server(Ipv4Addr::new(128, 116, 102, 1));
        assert!(matches!(action, AutoRoutingAction::NoAction));
    }

    #[test]
    fn test_handle_region_lookup_switches_relay() {
        let router = AutoRouter::new(true, "singapore");
        router.set_available_servers(make_servers());
        router.set_current_relay("54.255.205.216:51821".parse().unwrap(), "singapore");

        // Simulating ipinfo.io lookup result: game server is in US East
        let result = router.handle_region_lookup(RobloxRegion::UsEast);
        assert!(result.is_some());
        let (addr, region) = result.unwrap();
        assert_eq!(region, "america-01");
        assert_eq!(addr, "54.225.245.114:51821".parse::<SocketAddr>().unwrap());
    }

    #[test]
    fn test_handle_region_lookup_same_region_no_switch() {
        let router = AutoRouter::new(true, "singapore");
        router.set_available_servers(make_servers());
        router.set_current_relay("54.255.205.216:51821".parse().unwrap(), "singapore");

        // Already on Singapore — no switch needed
        let result = router.handle_region_lookup(RobloxRegion::Singapore);
        assert!(result.is_none());
    }

    #[test]
    fn test_handle_region_lookup_unknown_no_switch() {
        let router = AutoRouter::new(true, "singapore");
        router.set_available_servers(make_servers());

        let result = router.handle_region_lookup(RobloxRegion::Unknown);
        assert!(result.is_none());
    }

    #[test]
    fn test_auto_router_deduplicates_ips() {
        let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel();
        let router = AutoRouter::new(true, "singapore");
        router.set_lookup_channel(tx);

        let ip = Ipv4Addr::new(128, 116, 50, 1);

        // First call sends to channel
        router.evaluate_game_server(ip);
        assert!(rx.try_recv().is_ok());

        // Second call with same IP should NOT send again
        router.evaluate_game_server(ip);
        assert!(rx.try_recv().is_err());
    }

    #[test]
    fn test_region_matching_no_false_prefix_matches() {
        let region = "america";

        let matches_region = |candidate: &str| -> bool {
            candidate == region || candidate.starts_with(&format!("{}-", region))
        };

        assert!(matches_region("america"));
        assert!(matches_region("america-01"));
        assert!(matches_region("america-west"));
        assert!(!matches_region("americano"));
        assert!(!matches_region("americas"));
        assert!(!matches_region("american"));
        assert!(!matches_region("singapore"));
        assert!(!matches_region("tokyo-02"));
    }
}
