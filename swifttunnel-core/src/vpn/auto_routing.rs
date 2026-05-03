//! Auto Routing - Automatic relay server switching based on game server region
//!
//! Detects the first structured Roblox game-server region for a VPN session and
//! switches the relay server for optimal latency. Once a game server is pinned,
//! later Roblox-owned endpoints cannot change the route until disconnect.
//!
//! Similar to GearUp's AIR (Adaptive Intelligent Routing) and ExitLag's
//! automatic region detection.

use crate::geolocation::RobloxRegion;
use crate::vpn::connection::region_family;
use parking_lot::RwLock;
use std::collections::{HashMap, HashSet, VecDeque};
use std::net::{Ipv4Addr, SocketAddr};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::time::{Duration, Instant};

/// Minimum time between relay switches to prevent flapping
const MIN_SWITCH_INTERVAL: Duration = Duration::from_secs(10);

/// Maximum switches per minute
const MAX_SWITCHES_PER_MINUTE: u32 = 3;
const SAME_REGION_UPGRADE_THRESHOLD_MS: u32 = 10;

/// Cap on outstanding geolocation lookups. If the lookup backend stalls (API
/// outage, network down) this keeps the pending set from growing without bound.
const MAX_PENDING_LOOKUPS: usize = 100;

/// Cap on retained auto-routing events shown in the UI log.
const MAX_EVENT_LOG_ENTRIES: usize = 20;

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
    /// Game server IPs we've already evaluated this session
    seen_game_servers: RwLock<HashSet<Ipv4Addr>>,
    /// First structured game-server IP accepted for this VPN session.
    ///
    /// Roblox can contact several Roblox-owned endpoints while a user is already
    /// playing. Once a real game-server lookup succeeds, later candidate IPs
    /// must not override that route until disconnect resets the session.
    active_game_server_ip: RwLock<Option<Ipv4Addr>>,
    /// Callback: list of (region_id, relay_addr, cached_latency_ms) for available servers
    available_servers: RwLock<Vec<(String, SocketAddr, Option<u32>)>>,
    /// Log of auto-routing events for UI display
    event_log: RwLock<VecDeque<AutoRoutingEvent>>,
    /// Channel to send game server IPs for async geolocation lookup
    lookup_sender: RwLock<Option<tokio::sync::mpsc::UnboundedSender<(Ipv4Addr, u64)>>>,
    /// Monotonic generation assigned to newly detected game-server lookups.
    latest_lookup_generation: AtomicU64,
    /// IPs currently being looked up — packets to these are held (dropped) until
    /// the lookup completes, preventing the game server from seeing a relay IP change.
    pending_lookups: RwLock<HashSet<Ipv4Addr>>,
    /// Fast-path hint: whether `pending_lookups` is non-empty.
    ///
    /// This avoids taking a lock for the common case where there are no pending lookups.
    pending_any: AtomicBool,
    /// Game regions where VPN should be bypassed (user's regular internet used instead).
    /// Stored as RobloxRegion display names (e.g., "Singapore", "Tokyo").
    whitelisted_regions: RwLock<HashSet<String>>,
    /// Whether auto-routing has bypassed VPN for the current game region.
    /// Read by the packet interceptor (AtomicBool for lock-free hot path check).
    auto_routing_bypassed: AtomicBool,
    /// Pinned server per region (region_id -> server_id).
    /// When set, auto-routing will only use the pinned server for that region.
    forced_servers: RwLock<HashMap<String, String>>,
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
            // checked_sub avoids a debug-build panic when the process has
            // been alive for less than MIN_SWITCH_INTERVAL.
            last_switch_time: RwLock::new(
                Instant::now()
                    .checked_sub(MIN_SWITCH_INTERVAL)
                    .unwrap_or_else(Instant::now),
            ),
            switches_this_minute: RwLock::new((0, Instant::now())),
            seen_game_servers: RwLock::new(HashSet::new()),
            active_game_server_ip: RwLock::new(None),
            available_servers: RwLock::new(Vec::new()),
            event_log: RwLock::new(VecDeque::new()),
            lookup_sender: RwLock::new(None),
            latest_lookup_generation: AtomicU64::new(0),
            pending_lookups: RwLock::new(HashSet::new()),
            pending_any: AtomicBool::new(false),
            whitelisted_regions: RwLock::new(HashSet::new()),
            auto_routing_bypassed: AtomicBool::new(false),
            forced_servers: RwLock::new(HashMap::new()),
        }
    }

    /// Set the channel for sending game server IPs to the background lookup task
    pub fn set_lookup_channel(&self, sender: tokio::sync::mpsc::UnboundedSender<(Ipv4Addr, u64)>) {
        *self.lookup_sender.write() = Some(sender);
    }

    /// Drop the lookup sender so the background lookup task can exit during teardown.
    pub fn clear_lookup_channel(&self) {
        *self.lookup_sender.write() = None;
    }

    /// Enable or disable auto-routing
    pub fn set_enabled(&self, enabled: bool) {
        self.enabled.store(enabled, Ordering::Release);
        log::info!(
            "Auto-routing: {}",
            if enabled { "enabled" } else { "disabled" }
        );
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

    /// Set forced servers (region_id -> server_id).
    /// When a region has a forced server, auto-routing will only use that server.
    pub fn set_forced_servers(&self, servers: HashMap<String, String>) {
        log::info!("Auto-routing: Forced servers updated: {:?}", servers);
        *self.forced_servers.write() = servers;
    }

    /// Check whether VPN is currently bypassed due to a whitelisted game region.
    /// Lock-free AtomicBool check for use in the packet processing hot path.
    pub fn is_bypassed(&self) -> bool {
        self.auto_routing_bypassed.load(Ordering::Acquire)
    }

    /// Check if a game region is whitelisted (should bypass VPN).
    fn is_region_whitelisted(&self, region: &RobloxRegion) -> bool {
        self.whitelisted_regions
            .read()
            .contains(region.display_name())
    }

    /// Update the list of available relay servers with cached latency data.
    /// Called when server list is fetched/refreshed.
    /// Latency is used to pick the best server when multiple match a region.
    pub fn set_available_servers(&self, servers: Vec<(String, SocketAddr, Option<u32>)>) {
        log::info!(
            "Auto-routing: Updated available servers ({} servers)",
            servers.len()
        );
        for (region, addr, latency) in &servers {
            log::info!(
                "  {} ({}) - latency: {}",
                region,
                addr,
                latency.map_or("unknown".to_string(), |ms| format!("{}ms", ms))
            );
        }
        *self.available_servers.write() = servers;
    }

    /// Snapshot available relay servers for async probing/selection.
    pub fn available_servers_snapshot(&self) -> Vec<(String, SocketAddr, Option<u32>)> {
        self.available_servers.read().clone()
    }

    /// Get a forced server (if configured) for a SwiftTunnel region id.
    pub fn forced_server_for_region(&self, region_id: &str) -> Option<String> {
        self.forced_servers.read().get(region_id).cloned()
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

    pub fn current_relay(&self) -> Option<(String, SocketAddr)> {
        let addr = *self.current_relay_addr.read();
        addr.map(|addr| (self.current_st_region.read().clone(), addr))
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

        // Fast path: bail if we've already seen this IP.
        // Use try_read() to avoid blocking the hot path. If contended, retry on a
        // later packet (RakNet is chatty, we'll see it again quickly).
        //
        // The read-then-write here is a deliberate TOCTOU: two workers can both
        // pass the read check, but only one of them sees `insert(...) == true`
        // on the write path below — the loser bails on `if !is_new_ip` without
        // double-firing the lookup. Cheap by design; do not "fix" with a single
        // upgradeable lock unless you've measured a contention regression.
        match self.seen_game_servers.try_read() {
            Some(seen) => {
                if seen.contains(&game_server_ip) {
                    return AutoRoutingAction::NoAction;
                }
            }
            None => return AutoRoutingAction::NoAction,
        }

        // New IP candidate — insert under try_write() for dedupe.
        let is_new_ip = match self.seen_game_servers.try_write() {
            Some(mut seen) => seen.insert(game_server_ip),
            None => return AutoRoutingAction::NoAction,
        };

        if !is_new_ip {
            return AutoRoutingAction::NoAction;
        }

        let sender = match self.lookup_sender.read().as_ref() {
            Some(s) => s.clone(),
            None => {
                log::warn!(
                    "Auto-routing: Lookup channel not set (auto-routing task not running) — ignoring game server {}",
                    game_server_ip
                );
                return AutoRoutingAction::NoAction;
            }
        };

        // New IP detected — add to pending set and send to background lookup task.
        // While pending, packets to this IP will be held (dropped) by the interceptor
        // so the game server only ever sees traffic from the correct relay.
        {
            // Blocking write lock is OK here: this runs only once per new game server,
            // and the correctness requirement (holding packets) outweighs the tiny cost.
            let mut pending = self.pending_lookups.write();
            // Cap pending lookups so a stuck geolocation task (network down, API
            // outage) can't grow this set without bound. If full, roll back the
            // seen_game_servers insert above so a future packet can retry once
            // the pending set drains — otherwise the fast-path `seen.contains()`
            // check would permanently exclude this IP from auto-routing for the
            // remainder of the session.
            if pending.len() >= MAX_PENDING_LOOKUPS && !pending.contains(&game_server_ip) {
                drop(pending);
                self.seen_game_servers.write().remove(&game_server_ip);
                log::warn!(
                    "Auto-routing: pending_lookups at cap ({}), skipping hold for {}",
                    MAX_PENDING_LOOKUPS,
                    game_server_ip
                );
                return AutoRoutingAction::NoAction;
            }
            pending.insert(game_server_ip);
            self.pending_any.store(true, Ordering::Release);
        }

        let generation = self.latest_lookup_generation.fetch_add(1, Ordering::AcqRel) + 1;

        if sender.send((game_server_ip, generation)).is_err() {
            log::warn!(
                "Auto-routing: Lookup channel closed — releasing packets for {} and disabling holding behavior",
                game_server_ip
            );
            self.clear_pending_lookup(game_server_ip);
            return AutoRoutingAction::NoAction;
        }
        log::info!(
            "Auto-routing: New game server {} detected (generation {}), holding packets while looking up region...",
            game_server_ip,
            generation
        );

        AutoRoutingAction::NoAction
    }

    /// Check if the given game server IP has a region lookup in progress.
    /// Packets to pending IPs should be held (dropped) to prevent the game server
    /// from seeing traffic from a relay that's about to change.
    pub fn is_lookup_pending(&self, ip: Ipv4Addr) -> bool {
        if !self.pending_any.load(Ordering::Acquire) {
            return false;
        }
        self.pending_lookups.read().contains(&ip)
    }

    /// Clear a pending lookup (called when the ipinfo.io lookup completes).
    /// Uses write() (blocking) because this runs in the async background task,
    /// not the packet processing hot path. Must not fail silently or packets
    /// to this IP would be dropped forever.
    pub fn clear_pending_lookup(&self, ip: Ipv4Addr) {
        let mut pending = self.pending_lookups.write();
        pending.remove(&ip);
        self.pending_any
            .store(!pending.is_empty(), Ordering::Release);
        log::info!(
            "Auto-routing: Lookup complete for {}, releasing packets",
            ip
        );
    }

    /// Check whether a lookup result is still allowed to change relay state.
    pub fn is_current_lookup_generation(&self, generation: u64) -> bool {
        self.latest_lookup_generation.load(Ordering::Acquire) == generation
    }

    /// Whether a completed lookup result is allowed to affect routing.
    ///
    /// Before the first structured lookup succeeds, candidates may resolve in
    /// channel order. After one IP is accepted, superficially similar Roblox
    /// traffic cannot flip the relay mid-game.
    pub fn should_process_lookup_result(&self, ip: Ipv4Addr) -> bool {
        match *self.active_game_server_ip.read() {
            Some(active_ip) => active_ip == ip,
            None => true,
        }
    }

    /// Pin the first structured game-server lookup accepted for this session.
    /// Returns false when another IP already owns the active session.
    pub fn pin_active_game_server(&self, ip: Ipv4Addr) -> bool {
        let mut active = self.active_game_server_ip.write();
        match *active {
            Some(active_ip) => active_ip == ip,
            None => {
                *active = Some(ip);
                log::info!("Auto-routing: Active game server pinned to {}", ip);
                true
            }
        }
    }

    pub fn is_active_game_server(&self, ip: Ipv4Addr) -> bool {
        self.active_game_server_ip
            .read()
            .is_some_and(|active_ip| active_ip == ip)
    }

    /// Resolve the best relay server for a game region.
    ///
    /// Returns `None` if:
    /// - the region is unknown,
    /// - the region is whitelisted (VPN bypass),
    /// - already on the desired server,
    /// - or no matching server exists.
    pub fn get_best_server_for_region(
        &self,
        game_region: &RobloxRegion,
    ) -> Option<(String, SocketAddr)> {
        if *game_region == RobloxRegion::Unknown {
            return None;
        }

        // Check if this game region is whitelisted (user wants to bypass VPN)
        if self.is_region_whitelisted(game_region) {
            log::info!(
                "Auto-routing: Game region {} is whitelisted — bypassing VPN",
                game_region.display_name()
            );
            self.auto_routing_bypassed.store(true, Ordering::Release);
            *self.current_game_region.write() = Some(game_region.clone());

            // Log the bypass event
            let mut log = self.event_log.write();
            log.push_back(AutoRoutingEvent {
                timestamp: Instant::now(),
                from_region: self.current_st_region.read().clone(),
                to_region: "BYPASS".to_string(),
                game_server_region: game_region.display_name().to_string(),
                reason: format!(
                    "{} is whitelisted — using direct connection",
                    game_region.display_name()
                ),
            });
            if log.len() > MAX_EVENT_LOG_ENTRIES {
                log.pop_front();
            }

            return None;
        }

        // Not whitelisted — clear bypass flag and proceed with normal routing
        self.auto_routing_bypassed.store(false, Ordering::Release);

        let best_st_region = game_region.best_swifttunnel_region()?;
        // Check if the user has pinned a specific server for this region.
        // Clone so we don't hold the lock while resolving.
        let pinned_server = self.forced_servers.read().get(best_st_region).cloned();
        let pinned_server = pinned_server.as_deref();

        let servers = self.available_servers.read();
        let current_st_region = self.current_st_region.read().clone();
        let current_relay_addr = *self.current_relay_addr.read();
        let candidates =
            super::connection::relay_candidates_for_region(best_st_region, &servers, pinned_server);
        if candidates.is_empty() {
            log::warn!(
                "Auto-routing: No server found for region '{}' (game region: {})",
                best_st_region,
                game_region
            );
            return None;
        }

        let (resolved_region, resolved_addr, _) = candidates
            .iter()
            .min_by_key(|(_, _, latency_ms)| latency_ms.unwrap_or(u32::MAX))
            .cloned()
            .expect("candidates checked as non-empty");

        if candidates.len() == 1
            && current_st_region == resolved_region
            && current_relay_addr == Some(resolved_addr)
        {
            *self.current_game_region.write() = Some(game_region.clone());
            return None;
        }

        Some((resolved_region, resolved_addr))
    }

    /// Commit a relay switch after the best server has been selected (called from background task).
    ///
    /// `selected_region` and `selected_addr` are the result of pinging candidates.
    /// Returns `Some((addr, region))` if the switch was recorded, `None` if rate-limited.
    pub fn commit_switch(
        &self,
        game_region: RobloxRegion,
        selected_region: String,
        selected_addr: SocketAddr,
        latency_improvement_ms: Option<u32>,
    ) -> Option<(SocketAddr, String)> {
        let current_st_region = self.current_st_region.read().clone();

        if self.record_switch(
            &current_st_region,
            &selected_region,
            &game_region,
            selected_addr,
            latency_improvement_ms,
        ) {
            Some((selected_addr, selected_region))
        } else {
            None
        }
    }

    /// Record a relay switch, atomically checking rate limits.
    /// Returns true if the switch was recorded, false if rate-limited or already switched.
    fn record_switch(
        &self,
        from_region: &str,
        to_region: &str,
        game_region: &RobloxRegion,
        new_addr: SocketAddr,
        latency_improvement_ms: Option<u32>,
    ) -> bool {
        let current_region = self.current_st_region.read().clone();
        let current_addr = *self.current_relay_addr.read();
        if current_region == to_region && current_addr == Some(new_addr) {
            return false;
        }

        let same_region_upgrade = region_family(from_region) == region_family(to_region)
            && current_addr != Some(new_addr);
        let allow_immediate_upgrade = same_region_upgrade
            && latency_improvement_ms
                .is_some_and(|delta| delta >= SAME_REGION_UPGRADE_THRESHOLD_MS);
        let now = Instant::now();

        if same_region_upgrade && !allow_immediate_upgrade {
            log::debug!(
                "Auto-routing: Rate limited (same-region upgrade below {}ms), skipping switch",
                SAME_REGION_UPGRADE_THRESHOLD_MS
            );
            return false;
        }

        if !allow_immediate_upgrade {
            if now.duration_since(*self.last_switch_time.read()) < MIN_SWITCH_INTERVAL {
                log::debug!("Auto-routing: Rate limited (min interval), skipping switch");
                return false;
            }

            // Same-region upgrades that clear the threshold intentionally skip the churn
            // counter so an immediate correction does not consume cross-region switch budget.
            let mut window = self.switches_this_minute.write();
            if now.duration_since(window.1) > Duration::from_secs(60) {
                *window = (0, now);
            }
            if window.0 >= MAX_SWITCHES_PER_MINUTE {
                log::debug!("Auto-routing: Rate limited (max per minute), skipping switch");
                return false;
            }
            window.0 += 1;
        }

        *self.last_switch_time.write() = now;
        *self.current_st_region.write() = to_region.to_string();
        *self.current_relay_addr.write() = Some(new_addr);
        *self.current_game_region.write() = Some(game_region.clone());

        let reason = if same_region_upgrade {
            match latency_improvement_ms {
                Some(delta) => format!(
                    "Upgrade within region {} - {}ms faster",
                    region_family(to_region),
                    delta
                ),
                None => format!("Upgrade within region {}", region_family(to_region)),
            }
        } else {
            format!(
                "Game server moved to {} - switching from {} to {}",
                game_region.display_name(),
                from_region,
                to_region
            )
        };

        let event = AutoRoutingEvent {
            timestamp: now,
            from_region: from_region.to_string(),
            to_region: to_region.to_string(),
            game_server_region: game_region.display_name().to_string(),
            reason,
        };

        let mut log = self.event_log.write();
        log.push_back(event);
        if log.len() > MAX_EVENT_LOG_ENTRIES {
            log.pop_front();
        }

        if same_region_upgrade {
            log::info!(
                "Auto-routing: Upgraded within region {} {} -> {} ({:?}ms improvement)",
                region_family(to_region),
                from_region,
                to_region,
                latency_improvement_ms
            );
        } else {
            log::info!(
                "Auto-routing: Switched {} -> {} (game server in {})",
                from_region,
                to_region,
                game_region.display_name()
            );
        }

        true
    }

    /// Reset state (call on disconnect)
    pub fn reset(&self) {
        *self.current_game_region.write() = None;
        *self.current_relay_addr.write() = None;
        self.seen_game_servers.write().clear();
        *self.active_game_server_ip.write() = None;
        self.pending_lookups.write().clear();
        self.latest_lookup_generation.store(0, Ordering::Release);
        self.pending_any.store(false, Ordering::Release);
        self.auto_routing_bypassed.store(false, Ordering::Release);
        self.clear_lookup_channel();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::geolocation::RobloxRegion;

    fn make_servers() -> Vec<(String, SocketAddr, Option<u32>)> {
        vec![
            (
                "singapore".to_string(),
                "54.255.205.216:51821".parse().unwrap(),
                None,
            ),
            (
                "singapore-02".to_string(),
                "203.0.113.2:51821".parse().unwrap(),
                None,
            ),
            (
                "mumbai".to_string(),
                "3.111.230.152:51821".parse().unwrap(),
                None,
            ),
            (
                "us-east-nj".to_string(),
                "108.61.7.6:51821".parse().unwrap(),
                None,
            ),
            (
                "us-west-la".to_string(),
                "45.63.55.139:51821".parse().unwrap(),
                None,
            ),
            (
                "us-central-dallas".to_string(),
                "108.61.205.6:51821".parse().unwrap(),
                None,
            ),
            (
                "tokyo-02".to_string(),
                "45.32.253.124:51821".parse().unwrap(),
                None,
            ),
            (
                "sydney".to_string(),
                "54.153.235.165:51821".parse().unwrap(),
                None,
            ),
            (
                "germany-01".to_string(),
                "63.181.160.158:51821".parse().unwrap(),
                None,
            ),
            (
                "london-01".to_string(),
                "172.237.119.240:51821".parse().unwrap(),
                None,
            ),
            (
                "brazil-02".to_string(),
                "172.233.20.214:51821".parse().unwrap(),
                None,
            ),
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
    fn test_get_best_server_switches_relay() {
        let router = AutoRouter::new(true, "singapore");
        router.set_available_servers(make_servers());
        router.set_current_relay("54.255.205.216:51821".parse().unwrap(), "singapore");

        // Game server in US East — should resolve to us-east-nj
        let best = router.get_best_server_for_region(&RobloxRegion::UsEast);
        assert!(best.is_some());
        let (region, addr) = best.unwrap();
        assert_eq!(region, "us-east-nj");
        assert_eq!(addr, "108.61.7.6:51821".parse::<SocketAddr>().unwrap());

        // Commit the switch
        let result = router.commit_switch(RobloxRegion::UsEast, region, addr, None);
        assert!(result.is_some());
        let (addr, region) = result.unwrap();
        assert_eq!(region, "us-east-nj");
        assert_eq!(addr, "108.61.7.6:51821".parse::<SocketAddr>().unwrap());
    }

    #[test]
    fn test_get_best_server_same_region_still_returns_candidate_for_probe_refinement() {
        let router = AutoRouter::new(true, "singapore");
        router.set_available_servers(make_servers());
        router.set_current_relay("54.255.205.216:51821".parse().unwrap(), "singapore");

        // Singapore has multiple candidate servers, so auto-routing should keep the region
        // probeable even when the cached winner matches the current exact server.
        let best = router.get_best_server_for_region(&RobloxRegion::Singapore);
        assert_eq!(
            best,
            Some((
                "singapore".to_string(),
                "54.255.205.216:51821".parse::<SocketAddr>().unwrap()
            ))
        );
    }

    #[test]
    fn test_get_best_server_same_region_switches_to_manual_resolved_server() {
        // Regression test: previously we treated "already on best region" as "already on any
        // server with prefix {region}-", which prevented switching to the region's preferred
        // server (and ignored forced servers). Auto-routing should resolve the same server
        // as manual region connect and switch if we aren't already on it.
        let router = AutoRouter::new(true, "singapore-02");
        router.set_available_servers(make_servers());
        router.set_current_relay("203.0.113.2:51821".parse().unwrap(), "singapore-02");

        // Manual resolution prefers the exact "singapore" server id when it exists.
        let best = router.get_best_server_for_region(&RobloxRegion::Singapore);
        assert_eq!(
            best,
            Some((
                "singapore".to_string(),
                "54.255.205.216:51821".parse::<SocketAddr>().unwrap()
            ))
        );
    }

    #[test]
    fn test_forced_server_overrides_within_region() {
        use std::collections::HashMap;

        let router = AutoRouter::new(true, "singapore");
        router.set_available_servers(make_servers());
        router.set_current_relay("54.255.205.216:51821".parse().unwrap(), "singapore");

        // Force singapore -> singapore-02 (even though we're in the right region)
        router.set_forced_servers(HashMap::from([(
            "singapore".to_string(),
            "singapore-02".to_string(),
        )]));

        let best = router.get_best_server_for_region(&RobloxRegion::Singapore);
        assert_eq!(
            best,
            Some((
                "singapore-02".to_string(),
                "203.0.113.2:51821".parse::<SocketAddr>().unwrap()
            ))
        );
    }

    #[test]
    fn test_get_best_server_unknown_no_switch() {
        let router = AutoRouter::new(true, "singapore");
        router.set_available_servers(make_servers());

        let best = router.get_best_server_for_region(&RobloxRegion::Unknown);
        assert!(best.is_none());
    }

    #[test]
    fn test_auto_router_deduplicates_ips() {
        let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel();
        let router = AutoRouter::new(true, "singapore");
        router.set_lookup_channel(tx);

        let ip = Ipv4Addr::new(128, 116, 50, 1);

        // First call sends to channel
        router.evaluate_game_server(ip);
        let (received_ip, generation) = rx.try_recv().expect("first lookup should be sent");
        assert_eq!(received_ip, ip);
        assert_eq!(generation, 1);

        // Second call with same IP should NOT send again
        router.evaluate_game_server(ip);
        assert!(rx.try_recv().is_err());
    }

    #[test]
    fn test_lookup_generation_tracks_newest_game_server() {
        let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel();
        let router = AutoRouter::new(true, "singapore");
        router.set_lookup_channel(tx);

        router.evaluate_game_server(Ipv4Addr::new(128, 116, 50, 1));
        let (_, first_generation) = rx.try_recv().expect("first lookup");
        assert!(router.is_current_lookup_generation(first_generation));

        router.evaluate_game_server(Ipv4Addr::new(128, 116, 55, 1));
        let (_, second_generation) = rx.try_recv().expect("second lookup");
        assert!(!router.is_current_lookup_generation(first_generation));
        assert!(router.is_current_lookup_generation(second_generation));
    }

    #[test]
    fn test_active_game_server_pins_first_successful_lookup() {
        let router = AutoRouter::new(true, "singapore");
        let first_ip = Ipv4Addr::new(128, 116, 50, 1);
        let later_ip = Ipv4Addr::new(128, 116, 55, 1);

        assert!(router.should_process_lookup_result(first_ip));
        assert!(router.should_process_lookup_result(later_ip));
        assert!(router.pin_active_game_server(first_ip));

        assert!(router.should_process_lookup_result(first_ip));
        assert!(!router.should_process_lookup_result(later_ip));
        assert!(router.is_active_game_server(first_ip));
        assert!(!router.pin_active_game_server(later_ip));
    }

    #[test]
    fn test_active_game_server_allows_retry_until_lookup_succeeds() {
        let router = AutoRouter::new(true, "singapore");
        let failed_ip = Ipv4Addr::new(128, 116, 50, 1);
        let retry_ip = Ipv4Addr::new(128, 116, 55, 1);

        assert!(router.should_process_lookup_result(failed_ip));
        assert!(router.should_process_lookup_result(retry_ip));

        assert!(router.pin_active_game_server(retry_ip));
        assert!(!router.should_process_lookup_result(failed_ip));
    }

    #[test]
    fn test_pending_lookup_marked_and_cleared() {
        let (tx, _rx) = tokio::sync::mpsc::unbounded_channel();
        let router = AutoRouter::new(true, "singapore");
        router.set_lookup_channel(tx);

        let ip = Ipv4Addr::new(128, 116, 50, 1);
        router.evaluate_game_server(ip);
        assert!(router.is_lookup_pending(ip));

        router.clear_pending_lookup(ip);
        assert!(!router.is_lookup_pending(ip));
    }

    #[test]
    fn test_evaluate_without_lookup_channel_does_not_hold_packets() {
        let router = AutoRouter::new(true, "singapore");
        let ip = Ipv4Addr::new(128, 116, 50, 1);

        router.evaluate_game_server(ip);
        assert!(!router.is_lookup_pending(ip));
    }

    #[test]
    fn test_whitelisted_region_bypasses_vpn() {
        let router = AutoRouter::new(true, "singapore");
        router.set_available_servers(make_servers());
        router.set_current_relay("54.255.205.216:51821".parse().unwrap(), "singapore");

        // Whitelist US East
        router.set_whitelisted_regions(vec!["US East".to_string()]);

        // Game server in US East — should bypass (return None) and set bypassed flag
        let best = router.get_best_server_for_region(&RobloxRegion::UsEast);
        assert!(best.is_none());
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

        // Game server in US East — should NOT bypass, should resolve a best server
        let best = router.get_best_server_for_region(&RobloxRegion::UsEast);
        assert!(best.is_some());
        assert!(!router.is_bypassed());
    }

    #[test]
    fn test_bypass_clears_when_non_whitelisted_region_detected() {
        let router = AutoRouter::new(true, "singapore");
        router.set_available_servers(make_servers());
        router.set_current_relay("54.255.205.216:51821".parse().unwrap(), "singapore");

        router.set_whitelisted_regions(vec!["US East".to_string()]);

        // First: whitelisted region → bypassed
        router.get_best_server_for_region(&RobloxRegion::UsEast);
        assert!(router.is_bypassed());

        // Then: non-whitelisted region → bypass cleared
        router.get_best_server_for_region(&RobloxRegion::Tokyo);
        assert!(!router.is_bypassed());
    }

    #[test]
    fn test_reset_clears_bypass() {
        let router = AutoRouter::new(true, "singapore");
        router.set_whitelisted_regions(vec!["US East".to_string()]);
        router.set_available_servers(make_servers());
        router.set_current_relay("54.255.205.216:51821".parse().unwrap(), "singapore");

        router.get_best_server_for_region(&RobloxRegion::UsEast);
        assert!(router.is_bypassed());
        assert!(router.pin_active_game_server(Ipv4Addr::new(128, 116, 50, 1)));

        router.reset();
        assert!(!router.is_bypassed());
        assert!(router.should_process_lookup_result(Ipv4Addr::new(128, 116, 55, 1)));
    }

    #[test]
    fn test_commit_switch_allows_same_region_upgrade_inside_min_interval() {
        let router = AutoRouter::new(true, "singapore-02");
        router.set_current_relay("203.0.113.2:51821".parse().unwrap(), "singapore-02");
        *router.last_switch_time.write() = Instant::now();

        let result = router.commit_switch(
            RobloxRegion::Singapore,
            "singapore".to_string(),
            "54.255.205.216:51821".parse().unwrap(),
            Some(SAME_REGION_UPGRADE_THRESHOLD_MS + 2),
        );

        assert!(result.is_some());
        assert_eq!(router.current_region(), "singapore");
    }

    #[test]
    fn test_commit_switch_blocks_small_same_region_upgrade_inside_min_interval() {
        let router = AutoRouter::new(true, "singapore-02");
        router.set_current_relay("203.0.113.2:51821".parse().unwrap(), "singapore-02");
        *router.last_switch_time.write() = Instant::now();

        let result = router.commit_switch(
            RobloxRegion::Singapore,
            "singapore".to_string(),
            "54.255.205.216:51821".parse().unwrap(),
            Some(SAME_REGION_UPGRADE_THRESHOLD_MS - 1),
        );

        assert!(result.is_none());
        assert_eq!(router.current_region(), "singapore-02");
    }

    #[test]
    fn test_commit_switch_cross_region_still_respects_min_interval() {
        let router = AutoRouter::new(true, "singapore");
        router.set_current_relay("54.255.205.216:51821".parse().unwrap(), "singapore");
        *router.last_switch_time.write() = Instant::now();

        let result = router.commit_switch(
            RobloxRegion::Tokyo,
            "tokyo-02".to_string(),
            "45.32.253.124:51821".parse().unwrap(),
            Some(25),
        );

        assert!(result.is_none());
        assert_eq!(router.current_region(), "singapore");
    }

    #[test]
    fn test_region_matching_no_false_prefix_matches() {
        let region = "us-east";

        let matches_region = |candidate: &str| -> bool {
            candidate == region || candidate.starts_with(&format!("{}-", region))
        };

        assert!(matches_region("us-east"));
        assert!(matches_region("us-east-nj"));
        assert!(matches_region("us-east-va"));
        assert!(!matches_region("us-east2")); // no dash separator
        assert!(!matches_region("us-central-dallas"));
        assert!(!matches_region("us-west-la"));
        assert!(!matches_region("singapore"));
        assert!(!matches_region("tokyo-02"));
    }

    #[test]
    fn test_us_regions_route_to_distinct_servers() {
        // Regression test: US regions must map to separate API region IDs
        // (previously all mapped to "america" which no longer exists in API)
        let router = AutoRouter::new(true, "singapore");
        router.set_available_servers(make_servers());
        router.set_current_relay("54.255.205.216:51821".parse().unwrap(), "singapore");

        // US East -> us-east-nj
        let east = router.get_best_server_for_region(&RobloxRegion::UsEast);
        assert!(east.is_some(), "UsEast should resolve a best server");
        let (region, _addr) = east.unwrap();
        assert_eq!(region, "us-east-nj");

        // US West -> us-west-la
        let west = router.get_best_server_for_region(&RobloxRegion::UsWest);
        assert!(west.is_some(), "UsWest should resolve a best server");
        let (region, _addr) = west.unwrap();
        assert_eq!(region, "us-west-la");

        // US Central -> us-central-dallas
        let central = router.get_best_server_for_region(&RobloxRegion::UsCentral);
        assert!(central.is_some(), "UsCentral should resolve a best server");
        let (region, _addr) = central.unwrap();
        assert_eq!(region, "us-central-dallas");
    }

    #[test]
    fn test_legacy_america_name_finds_no_candidates() {
        // Documents the bug: "america" as a region base name no longer matches
        // any server in the current API. This test proves the fix is necessary.
        let router = AutoRouter::new(true, "singapore");
        router.set_available_servers(make_servers());
        router.set_current_relay("54.255.205.216:51821".parse().unwrap(), "singapore");

        // No server in make_servers() has region "america" or "america-*"
        let servers = router.available_servers.read();
        let legacy_candidates: Vec<_> = servers
            .iter()
            .filter(|(region, _, _)| region == "america" || region.starts_with("america-"))
            .collect();
        assert!(
            legacy_candidates.is_empty(),
            "No servers should match the legacy 'america' region name"
        );
    }

    #[test]
    fn test_pending_lookup_stays_held_until_cleared() {
        let router = AutoRouter::new(true, "singapore");
        let ip = Ipv4Addr::new(128, 116, 1, 1);

        router.pending_lookups.write().insert(ip);
        router.pending_any.store(true, Ordering::Release);
        assert!(router.is_lookup_pending(ip));
        std::thread::sleep(Duration::from_millis(600));
        assert!(router.is_lookup_pending(ip));

        router.clear_pending_lookup(ip);
        assert!(!router.is_lookup_pending(ip));
    }
}
