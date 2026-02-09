//! Auto Routing - Automatic relay server switching based on game server region
//!
//! Detects when a Roblox player gets teleported to a game server in a different
//! region and automatically switches the relay server for optimal latency.
//!
//! Similar to GearUp's AIR (Adaptive Intelligent Routing) and ExitLag's
//! automatic region detection.

use std::collections::VecDeque;
use std::net::{Ipv4Addr, SocketAddr};
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};
use parking_lot::RwLock;
use crate::geolocation::{RobloxRegion, roblox_ip_to_region};

/// Minimum time between relay switches to prevent flapping
const MIN_SWITCH_INTERVAL: Duration = Duration::from_secs(10);

/// Number of consecutive packets to a new region before triggering a switch
const REGION_CHANGE_THRESHOLD: u32 = 5;

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
    /// Consecutive packet count to a new region (for debounce)
    pending_region_change: RwLock<Option<(RobloxRegion, u32)>>,
    /// Callback: list of (region_id, relay_addr) for available servers
    available_servers: RwLock<Vec<(String, SocketAddr)>>,
    /// Log of auto-routing events for UI display
    event_log: RwLock<VecDeque<AutoRoutingEvent>>,
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
            pending_region_change: RwLock::new(None),
            available_servers: RwLock::new(Vec::new()),
            event_log: RwLock::new(VecDeque::new()),
        }
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

    /// Evaluate a detected game server IP and determine if we should switch relays.
    ///
    /// This is called from the packet processing path when a new Roblox game server
    /// IP is detected. It must be fast (no blocking). Note: some small allocations
    /// occur (clone, format) but are negligible for this use case.
    pub fn evaluate_game_server(&self, game_server_ip: Ipv4Addr) -> AutoRoutingAction {
        if !self.is_enabled() {
            return AutoRoutingAction::NoAction;
        }

        // Determine game server region
        let game_region = roblox_ip_to_region(game_server_ip);
        if game_region == RobloxRegion::Unknown {
            return AutoRoutingAction::NoAction;
        }

        // Check if this is a new region
        let current = self.current_game_region.read().clone();
        if current.as_ref() == Some(&game_region) {
            // Same region - reset pending change counter
            *self.pending_region_change.write() = None;
            return AutoRoutingAction::NoAction;
        }

        // Debounce: count consecutive packets to the new region
        let mut pending = self.pending_region_change.write();
        if let Some((ref pending_region, ref mut count)) = *pending {
            if *pending_region == game_region {
                *count += 1;
                if *count < REGION_CHANGE_THRESHOLD {
                    return AutoRoutingAction::NoAction;
                }
                // Threshold met - proceed with switch evaluation
            } else {
                // Different region than pending - reset
                *pending = Some((game_region.clone(), 1));
                return AutoRoutingAction::NoAction;
            }
        } else {
            *pending = Some((game_region.clone(), 1));
            return AutoRoutingAction::NoAction;
        }
        // CRITICAL: Must drop the pending_region_change write lock before calling
        // record_switch(), which also acquires write locks on this and other fields.
        // parking_lot::RwLock is NOT reentrant, so holding this would deadlock.
        drop(pending);

        // Find the best SwiftTunnel server for this game region
        let best_st_region = match game_region.best_swifttunnel_region() {
            Some(r) => r,
            None => return AutoRoutingAction::NoAction,
        };
        let current_st_region = self.current_st_region.read().clone();

        // Check if we're already on the best region
        if current_st_region == best_st_region || current_st_region.starts_with(&format!("{}-", best_st_region)) {
            // Already on an optimal server (e.g. "singapore-02" starts with "singapore")
            *self.current_game_region.write() = Some(game_region);
            *self.pending_region_change.write() = None;
            return AutoRoutingAction::NoAction;
        }

        // Find the best server in the target region
        let servers = self.available_servers.read();
        let best_server = servers.iter()
            .find(|(region, _)| region == best_st_region || region.starts_with(&format!("{}-", best_st_region)));

        if let Some((new_region, new_addr)) = best_server {
            let new_region = new_region.clone();
            let new_addr = *new_addr;

            // Record the switch (also performs rate-limit check atomically)
            if !self.record_switch(&current_st_region, &new_region, &game_region, new_addr) {
                return AutoRoutingAction::NoAction;
            }

            AutoRoutingAction::SwitchRelay {
                new_addr,
                new_region,
                game_region,
            }
        } else {
            log::warn!(
                "Auto-routing: No server found for region '{}' (game region: {})",
                best_st_region, game_region
            );
            AutoRoutingAction::NoAction
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
        *self.pending_region_change.write() = None;

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
        *self.pending_region_change.write() = None;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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
    fn test_auto_router_debounce() {
        let router = AutoRouter::new(true, "singapore");
        router.set_available_servers(make_servers());
        router.set_current_relay(
            "54.255.205.216:51821".parse().unwrap(),
            "singapore",
        );

        // First few packets should be debounced (NoAction)
        let us_east_ip = Ipv4Addr::new(128, 116, 102, 1);
        for _ in 0..(REGION_CHANGE_THRESHOLD - 1) {
            let action = router.evaluate_game_server(us_east_ip);
            assert!(matches!(action, AutoRoutingAction::NoAction));
        }

        // After threshold, should trigger switch
        let action = router.evaluate_game_server(us_east_ip);
        assert!(matches!(action, AutoRoutingAction::SwitchRelay { .. }));
    }

    #[test]
    fn test_auto_router_same_region_no_switch() {
        let router = AutoRouter::new(true, "singapore");
        router.set_available_servers(make_servers());
        router.set_current_relay(
            "54.255.205.216:51821".parse().unwrap(),
            "singapore",
        );

        // Singapore game server while on Singapore relay = no switch
        let sg_ip = Ipv4Addr::new(128, 116, 50, 100);
        for _ in 0..10 {
            let action = router.evaluate_game_server(sg_ip);
            assert!(matches!(action, AutoRoutingAction::NoAction));
        }
    }

    #[test]
    fn test_auto_router_unknown_ip_no_switch() {
        let router = AutoRouter::new(true, "singapore");
        router.set_available_servers(make_servers());

        // Non-Roblox IP should never trigger switch
        let action = router.evaluate_game_server(Ipv4Addr::new(8, 8, 8, 8));
        assert!(matches!(action, AutoRoutingAction::NoAction));
    }

    #[test]
    fn test_region_matching_no_false_prefix_matches() {
        // Verifies that region matching requires an exact match or a "-" delimiter,
        // so "americano" does NOT match "america" but "america-01" does.
        let region = "america";

        let matches_region = |candidate: &str| -> bool {
            candidate == region || candidate.starts_with(&format!("{}-", region))
        };

        // Exact match
        assert!(matches_region("america"));
        // Hyphenated sub-region should match
        assert!(matches_region("america-01"));
        assert!(matches_region("america-west"));
        // False prefix that is NOT the same region
        assert!(!matches_region("americano"));
        assert!(!matches_region("americas"));
        assert!(!matches_region("american"));
        // Completely different region
        assert!(!matches_region("singapore"));
        assert!(!matches_region("tokyo-02"));
    }
}
