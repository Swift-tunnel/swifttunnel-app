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
    /// Callback: list of (region_id, relay_addr, cached_latency_ms) for available servers
    available_servers: RwLock<Vec<(String, SocketAddr, Option<u32>)>>,
    /// Log of auto-routing events for UI display
    event_log: RwLock<VecDeque<AutoRoutingEvent>>,
    /// Channel to send game server IPs for async geolocation lookup
    lookup_sender: RwLock<Option<tokio::sync::mpsc::UnboundedSender<Ipv4Addr>>>,
    /// IPs currently being looked up — packets to these are held (dropped) until
    /// the lookup completes, preventing the game server from seeing a relay IP change.
    pending_lookups: RwLock<HashSet<Ipv4Addr>>,
    /// Game regions where VPN should be bypassed (user's regular internet used instead).
    /// Stored as RobloxRegion display names (e.g., "Singapore", "Tokyo").
    whitelisted_regions: RwLock<HashSet<String>>,
    /// Whether auto-routing has bypassed VPN for the current game region.
    /// Read by the packet interceptor (AtomicBool for lock-free hot path check).
    auto_routing_bypassed: AtomicBool,
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
            pending_lookups: RwLock::new(HashSet::new()),
            whitelisted_regions: RwLock::new(HashSet::new()),
            auto_routing_bypassed: AtomicBool::new(false),
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

    /// Set the whitelisted regions (game regions where VPN should be bypassed).
    /// Accepts display names like "Singapore", "Tokyo", "US East".
    pub fn set_whitelisted_regions(&self, regions: Vec<String>) {
        log::info!("Auto-routing: Whitelisted regions updated: {:?}", regions);
        *self.whitelisted_regions.write() = regions.into_iter().collect();
    }

    /// Check whether VPN is currently bypassed due to a whitelisted game region.
    /// Lock-free AtomicBool check for use in the packet processing hot path.
    pub fn is_bypassed(&self) -> bool {
        self.auto_routing_bypassed.load(Ordering::Acquire)
    }

    /// Check if a game region is whitelisted (should bypass VPN).
    fn is_region_whitelisted(&self, region: &RobloxRegion) -> bool {
        self.whitelisted_regions.read().contains(region.display_name())
    }

    /// Update the list of available relay servers with cached latency data.
    /// Called when server list is fetched/refreshed.
    /// Latency is used to pick the best server when multiple match a region.
    pub fn set_available_servers(&self, servers: Vec<(String, SocketAddr, Option<u32>)>) {
        log::info!("Auto-routing: Updated available servers ({} servers)", servers.len());
        for (region, addr, latency) in &servers {
            log::info!("  {} ({}) - latency: {}",
                region, addr,
                latency.map_or("unknown".to_string(), |ms| format!("{}ms", ms))
            );
        }
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

        // New IP detected — add to pending set and send to background lookup task.
        // While pending, packets to this IP will be held (dropped) by the interceptor
        // so the game server only ever sees traffic from the correct relay.
        if let Some(mut pending) = self.pending_lookups.try_write() {
            pending.insert(game_server_ip);
        } else {
            log::warn!("Auto-routing: Failed to acquire pending_lookups write lock for {} — packets may leak to wrong relay during lookup", game_server_ip);
        }
        if let Some(sender) = self.lookup_sender.read().as_ref() {
            let _ = sender.send(game_server_ip);
            log::info!("Auto-routing: New game server {} detected, holding packets while looking up region...", game_server_ip);
        }

        AutoRoutingAction::NoAction
    }

    /// Check if the given game server IP has a region lookup in progress.
    /// Packets to pending IPs should be held (dropped) to prevent the game server
    /// from seeing traffic from a relay that's about to change.
    pub fn is_lookup_pending(&self, ip: Ipv4Addr) -> bool {
        self.pending_lookups.read().contains(&ip)
    }

    /// Clear a pending lookup (called when the ipinfo.io lookup completes).
    /// Uses write() (blocking) because this runs in the async background task,
    /// not the packet processing hot path. Must not fail silently or packets
    /// to this IP would be dropped forever.
    pub fn clear_pending_lookup(&self, ip: Ipv4Addr) {
        self.pending_lookups.write().remove(&ip);
        log::info!("Auto-routing: Lookup complete for {}, releasing packets", ip);
    }

    /// Get candidate relay servers for a game region.
    ///
    /// Returns `None` if already on the correct region or no candidates exist.
    /// Returns `Some((candidates, game_region))` where candidates are (region_name, addr)
    /// pairs that should be pinged to find the best one.
    pub fn get_candidates_for_region(&self, game_region: &RobloxRegion) -> Option<Vec<(String, SocketAddr)>> {
        if *game_region == RobloxRegion::Unknown {
            return None;
        }

        // Check if this game region is whitelisted (user wants to bypass VPN)
        if self.is_region_whitelisted(game_region) {
            log::info!("Auto-routing: Game region {} is whitelisted — bypassing VPN", game_region.display_name());
            self.auto_routing_bypassed.store(true, Ordering::Release);
            *self.current_game_region.write() = Some(game_region.clone());

            // Log the bypass event
            let mut log = self.event_log.write();
            log.push_back(AutoRoutingEvent {
                timestamp: Instant::now(),
                from_region: self.current_st_region.read().clone(),
                to_region: "BYPASS".to_string(),
                game_server_region: game_region.display_name().to_string(),
                reason: format!("{} is whitelisted — using direct connection", game_region.display_name()),
            });
            if log.len() > 20 { log.pop_front(); }

            return None;
        }

        // Not whitelisted — clear bypass flag and proceed with normal routing
        self.auto_routing_bypassed.store(false, Ordering::Release);

        let best_st_region = game_region.best_swifttunnel_region()?;
        let current_st_region = self.current_st_region.read().clone();

        // Check if we're already on the best region
        if current_st_region == best_st_region || current_st_region.starts_with(&format!("{}-", best_st_region)) {
            *self.current_game_region.write() = Some(game_region.clone());
            return None;
        }

        let servers = self.available_servers.read();
        let mut candidates_with_latency: Vec<&(String, SocketAddr, Option<u32>)> = servers.iter()
            .filter(|(region, _, _)| region == best_st_region || region.starts_with(&format!("{}-", best_st_region)))
            .collect();

        // Sort by cached latency (lowest first) so fallback picks best cached server
        candidates_with_latency.sort_by_key(|(_, _, latency)| latency.unwrap_or(u32::MAX));

        let candidates: Vec<(String, SocketAddr)> = candidates_with_latency.into_iter()
            .map(|(region, addr, _)| (region.clone(), *addr))
            .collect();

        if candidates.is_empty() {
            log::warn!(
                "Auto-routing: No server found for region '{}' (game region: {})",
                best_st_region, game_region
            );
            None
        } else {
            log::info!("Auto-routing: {} candidates for region '{}': {:?}",
                candidates.len(), best_st_region,
                candidates.iter().map(|(r, a)| format!("{} ({})", r, a)).collect::<Vec<_>>()
            );
            Some(candidates)
        }
    }

    /// Commit a relay switch after the best server has been selected (called from background task).
    ///
    /// `selected_region` and `selected_addr` are the result of pinging candidates.
    /// Returns `Some((addr, region))` if the switch was recorded, `None` if rate-limited.
    pub fn commit_switch(&self, game_region: RobloxRegion, selected_region: String, selected_addr: SocketAddr) -> Option<(SocketAddr, String)> {
        let current_st_region = self.current_st_region.read().clone();

        if self.record_switch(&current_st_region, &selected_region, &game_region, selected_addr) {
            Some((selected_addr, selected_region))
        } else {
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
        self.pending_lookups.write().clear();
        self.auto_routing_bypassed.store(false, Ordering::Release);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::geolocation::RobloxRegion;

    fn make_servers() -> Vec<(String, SocketAddr, Option<u32>)> {
        vec![
            ("singapore".to_string(), "54.255.205.216:51821".parse().unwrap(), None),
            ("singapore-02".to_string(), "51.79.128.67:51821".parse().unwrap(), None),
            ("mumbai".to_string(), "3.111.230.152:51821".parse().unwrap(), None),
            ("america-01".to_string(), "54.225.245.114:51821".parse().unwrap(), None),
            ("tokyo-02".to_string(), "45.32.253.124:51821".parse().unwrap(), None),
            ("sydney".to_string(), "54.153.235.165:51821".parse().unwrap(), None),
            ("germany-01".to_string(), "63.181.160.158:51821".parse().unwrap(), None),
            ("london-01".to_string(), "172.237.119.240:51821".parse().unwrap(), None),
            ("brazil-02".to_string(), "172.233.20.214:51821".parse().unwrap(), None),
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
    fn test_get_candidates_switches_relay() {
        let router = AutoRouter::new(true, "singapore");
        router.set_available_servers(make_servers());
        router.set_current_relay("54.255.205.216:51821".parse().unwrap(), "singapore");

        // Game server in US East — should return america candidates
        let candidates = router.get_candidates_for_region(&RobloxRegion::UsEast);
        assert!(candidates.is_some());
        let candidates = candidates.unwrap();
        assert_eq!(candidates.len(), 1);
        assert_eq!(candidates[0].0, "america-01");
        assert_eq!(candidates[0].1, "54.225.245.114:51821".parse::<SocketAddr>().unwrap());

        // Commit the switch
        let result = router.commit_switch(RobloxRegion::UsEast, candidates[0].0.clone(), candidates[0].1);
        assert!(result.is_some());
        let (addr, region) = result.unwrap();
        assert_eq!(region, "america-01");
        assert_eq!(addr, "54.225.245.114:51821".parse::<SocketAddr>().unwrap());
    }

    #[test]
    fn test_get_candidates_same_region_no_switch() {
        let router = AutoRouter::new(true, "singapore");
        router.set_available_servers(make_servers());
        router.set_current_relay("54.255.205.216:51821".parse().unwrap(), "singapore");

        // Already on Singapore — should return None (no candidates needed)
        let candidates = router.get_candidates_for_region(&RobloxRegion::Singapore);
        assert!(candidates.is_none());
    }

    #[test]
    fn test_get_candidates_unknown_no_switch() {
        let router = AutoRouter::new(true, "singapore");
        router.set_available_servers(make_servers());

        let candidates = router.get_candidates_for_region(&RobloxRegion::Unknown);
        assert!(candidates.is_none());
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
    fn test_whitelisted_region_bypasses_vpn() {
        let router = AutoRouter::new(true, "singapore");
        router.set_available_servers(make_servers());
        router.set_current_relay("54.255.205.216:51821".parse().unwrap(), "singapore");

        // Whitelist US East
        router.set_whitelisted_regions(vec!["US East".to_string()]);

        // Game server in US East — should bypass (return None) and set bypassed flag
        let candidates = router.get_candidates_for_region(&RobloxRegion::UsEast);
        assert!(candidates.is_none());
        assert!(router.is_bypassed());

        // Game region should still be tracked
        assert_eq!(router.current_game_region(), Some(RobloxRegion::UsEast));
    }

    #[test]
    fn test_non_whitelisted_region_not_bypassed() {
        let router = AutoRouter::new(true, "singapore");
        router.set_available_servers(make_servers());
        router.set_current_relay("54.255.205.216:51821".parse().unwrap(), "singapore");

        // Whitelist Singapore only
        router.set_whitelisted_regions(vec!["Singapore".to_string()]);

        // Game server in US East — should NOT bypass, should return candidates
        let candidates = router.get_candidates_for_region(&RobloxRegion::UsEast);
        assert!(candidates.is_some());
        assert!(!router.is_bypassed());
    }

    #[test]
    fn test_bypass_clears_when_non_whitelisted_region_detected() {
        let router = AutoRouter::new(true, "singapore");
        router.set_available_servers(make_servers());
        router.set_current_relay("54.255.205.216:51821".parse().unwrap(), "singapore");

        router.set_whitelisted_regions(vec!["US East".to_string()]);

        // First: whitelisted region → bypassed
        router.get_candidates_for_region(&RobloxRegion::UsEast);
        assert!(router.is_bypassed());

        // Then: non-whitelisted region → bypass cleared
        router.get_candidates_for_region(&RobloxRegion::Tokyo);
        assert!(!router.is_bypassed());
    }

    #[test]
    fn test_reset_clears_bypass() {
        let router = AutoRouter::new(true, "singapore");
        router.set_whitelisted_regions(vec!["US East".to_string()]);
        router.set_available_servers(make_servers());
        router.set_current_relay("54.255.205.216:51821".parse().unwrap(), "singapore");

        router.get_candidates_for_region(&RobloxRegion::UsEast);
        assert!(router.is_bypassed());

        router.reset();
        assert!(!router.is_bypassed());
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
