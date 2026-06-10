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
pub(crate) const SAME_REGION_UPGRADE_THRESHOLD_MS: u32 = 10;

/// A new game-server IP is only a routing signal when every *other* tracked
/// game-server IP has been quiet for at least this long. While another
/// connection is actively sending, the new IP is either a Roblox-owned side
/// endpoint (not a routing signal) or a connection that will establish
/// through the current relay — switching the relay after establishment would
/// change the source IP the game server sees mid-session, which RakNet does
/// not tolerate.
const GAME_TRAFFIC_QUIET_HANDOFF: Duration = Duration::from_secs(3);

/// Cap on tracked per-IP last-seen entries (long sessions teleporting across
/// many instances). At the cap, the stalest entry is evicted.
const MAX_TRACKED_GAME_TRAFFIC_IPS: usize = 4096;

/// Don't take the game-traffic write lock more often than this per IP.
const GAME_TRAFFIC_UPDATE_GRANULARITY: Duration = Duration::from_millis(250);

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
    /// Game-server IP whose lookup currently owns the route.
    ///
    /// Roblox can contact several Roblox-owned endpoints while a user is
    /// already playing; those must not flip the relay mid-game. A new IP may
    /// take over the pin only via the gone-quiet handoff: when all other
    /// tracked game traffic has stopped for [`GAME_TRAFFIC_QUIET_HANDOFF`]
    /// (player left the old server / teleported), the replacement candidate
    /// is held during resolution and committed like a fresh join.
    active_game_server_ip: RwLock<Option<Ipv4Addr>>,
    /// Last-seen time per candidate-shaped game-server destination IP.
    /// Updated from the packet hot path (throttled per IP); drives the
    /// gone-quiet handoff decision.
    game_traffic: RwLock<HashMap<Ipv4Addr, Instant>>,
    /// Callback: list of (region_id, relay_addr, cached_latency_ms) for available servers
    available_servers: RwLock<Vec<(String, SocketAddr, Option<u32>)>>,
    /// Log of auto-routing events for UI display
    event_log: RwLock<VecDeque<AutoRoutingEvent>>,
    /// Channel to send game server IPs for async geolocation lookup
    lookup_sender: RwLock<Option<tokio::sync::mpsc::UnboundedSender<(Ipv4Addr, u64, u64)>>>,
    /// Monotonic generation assigned to newly detected game-server lookups.
    latest_lookup_generation: AtomicU64,
    /// Session epoch copied into lookup messages so post-reset results cannot
    /// mutate a freshly reset router.
    lookup_session_epoch: AtomicU64,
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
            game_traffic: RwLock::new(HashMap::new()),
            available_servers: RwLock::new(Vec::new()),
            event_log: RwLock::new(VecDeque::new()),
            lookup_sender: RwLock::new(None),
            latest_lookup_generation: AtomicU64::new(0),
            lookup_session_epoch: AtomicU64::new(1),
            pending_lookups: RwLock::new(HashSet::new()),
            pending_any: AtomicBool::new(false),
            whitelisted_regions: RwLock::new(HashSet::new()),
            auto_routing_bypassed: AtomicBool::new(false),
            forced_servers: RwLock::new(HashMap::new()),
        }
    }

    /// Set the channel for sending game server IPs to the background lookup task
    pub fn set_lookup_channel(
        &self,
        sender: tokio::sync::mpsc::UnboundedSender<(Ipv4Addr, u64, u64)>,
    ) {
        *self.lookup_sender.write() = Some(sender);
    }

    /// Drop the lookup sender so the background lookup task can exit during teardown.
    pub fn clear_lookup_channel(&self) {
        *self.lookup_sender.write() = None;
    }

    /// Enable or disable auto-routing.
    ///
    /// Disabling permanently invalidates every in-flight lookup (queued,
    /// resolving, or mid-auth-handshake) by bumping the session epoch, so a
    /// quick off→on toggle cannot resurrect a lookup gated during the
    /// earlier "on" period. The pinned active game server is kept: its
    /// connection is flowing and must never be re-routed mid-session anyway.
    ///
    /// Enabling mid-session quarantines game servers with recent traffic as
    /// non-signals (their connections are already flowing through the
    /// current relay); only joins observed after the enable re-route.
    pub fn set_enabled(&self, enabled: bool) {
        let was_enabled = self.enabled.swap(enabled, Ordering::AcqRel);
        if !enabled {
            self.lookup_session_epoch.fetch_add(1, Ordering::AcqRel);
            // A whitelist bypass is an auto-routing decision; disabling Auto
            // Route revokes it so game traffic returns to the relay instead
            // of continuing direct until disconnect.
            if self.auto_routing_bypassed.swap(false, Ordering::AcqRel) {
                log::info!("Auto-routing: Clearing whitelist bypass (auto-routing disabled)");
            }
        } else if !was_enabled {
            // Off→on transition: game servers that were already receiving
            // traffic while auto-routing was off (traffic is tracked even
            // when disabled) are flowing sessions, not fresh joins. Mark
            // them seen so their next packet cannot be mistaken for a join
            // boundary and trigger a mid-session relay switch; only IPs
            // whose traffic already went quiet — or genuinely new ones —
            // are routing signals from here on.
            let now = Instant::now();
            let active: Vec<Ipv4Addr> = self
                .game_traffic
                .read()
                .iter()
                .filter(|(_, last_seen)| {
                    now.duration_since(**last_seen) < GAME_TRAFFIC_QUIET_HANDOFF
                })
                .map(|(ip, _)| *ip)
                .collect();
            if !active.is_empty() {
                let mut seen = self.seen_game_servers.write();
                let quarantined = active
                    .into_iter()
                    .filter(|ip| seen.insert(*ip))
                    .collect::<Vec<_>>();
                if !quarantined.is_empty() {
                    log::info!(
                        "Auto-routing: Enabled mid-session — flowing game-server connection(s) {:?} are not routing signals",
                        quarantined
                    );
                }
            }
        }
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
        // Revoke an active bypass whose region was just un-whitelisted: the
        // input behind the off-relay decision is gone, so game traffic must
        // return to the relay. The reverse — newly whitelisting the current
        // region — engages only at the next lookup boundary; a bypass is
        // never silently engaged mid-session.
        if self.is_bypassed() {
            let still_whitelisted = self
                .current_game_region
                .read()
                .as_ref()
                .is_some_and(|region| self.is_region_whitelisted(region));
            if !still_whitelisted && self.auto_routing_bypassed.swap(false, Ordering::AcqRel) {
                log::info!(
                    "Auto-routing: Clearing whitelist bypass (current game region no longer whitelisted)"
                );
            }
        }
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

    /// Record the detected game region without switching relays (used when
    /// the current relay is already the best match for the region).
    pub fn record_game_region(&self, region: RobloxRegion) {
        *self.current_game_region.write() = Some(region);
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

    /// Record hot-path traffic to a candidate-shaped game-server destination.
    ///
    /// Throttled per IP via a read-first check so the write lock is taken at
    /// most once per [`GAME_TRAFFIC_UPDATE_GRANULARITY`] per IP. Uses
    /// try-locks: a missed update under contention only coarsens the
    /// gone-quiet timestamps by one packet interval.
    fn note_game_traffic(&self, ip: Ipv4Addr) {
        let now = Instant::now();
        match self.game_traffic.try_read() {
            Some(traffic) => {
                if let Some(last) = traffic.get(&ip) {
                    if now.duration_since(*last) < GAME_TRAFFIC_UPDATE_GRANULARITY {
                        return;
                    }
                }
            }
            None => return,
        }

        if let Some(mut traffic) = self.game_traffic.try_write() {
            if traffic.len() >= MAX_TRACKED_GAME_TRAFFIC_IPS && !traffic.contains_key(&ip) {
                if let Some(stalest) = traffic
                    .iter()
                    .min_by_key(|(_, last)| **last)
                    .map(|(ip, _)| *ip)
                {
                    traffic.remove(&stalest);
                }
            }
            traffic.insert(ip, now);
        }
    }

    /// True when every tracked game-server IP other than `candidate` has been
    /// quiet for at least [`GAME_TRAFFIC_QUIET_HANDOFF`].
    fn other_game_traffic_quiet(&self, candidate: Ipv4Addr) -> bool {
        let now = Instant::now();
        let traffic = self.game_traffic.read();
        !traffic.iter().any(|(ip, last)| {
            *ip != candidate && now.duration_since(*last) < GAME_TRAFFIC_QUIET_HANDOFF
        })
    }

    /// Evaluate a detected game server IP and trigger an async region lookup.
    ///
    /// This is called from the packet processing hot path when a new Roblox game server
    /// IP is detected. It must be fast (no blocking). New IPs are sent to a background
    /// task that performs a region lookup and switches the relay if needed.
    ///
    /// A new IP observed while another game-server connection is still actively
    /// sending is *not* a routing signal (see [`GAME_TRAFFIC_QUIET_HANDOFF`]):
    /// it is recorded as seen without holding packets or starting a lookup, so
    /// its connection establishes through the current relay and is never
    /// switched mid-session.
    ///
    /// Always returns NoAction — the actual relay switch happens asynchronously
    /// in the background lookup task when the resolver response arrives.
    pub fn evaluate_game_server(&self, game_server_ip: Ipv4Addr) -> AutoRoutingAction {
        // Track traffic even while disabled: if Auto Route is enabled
        // mid-session, set_enabled(true) uses this history to tell flowing
        // connections apart from fresh joins.
        self.note_game_traffic(game_server_ip);

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

        // Gone-quiet gate: while any other game-server IP is actively
        // sending, this candidate must not start a lookup or hold packets.
        // Marking it seen (below) is deliberate: its connection establishes
        // through the current relay, and a later switch would change the
        // source IP the game server sees mid-session.
        let deferred = !self.other_game_traffic_quiet(game_server_ip);

        // New IP candidate — insert under try_write() for dedupe.
        let is_new_ip = match self.seen_game_servers.try_write() {
            Some(mut seen) => seen.insert(game_server_ip),
            None => return AutoRoutingAction::NoAction,
        };

        if !is_new_ip {
            return AutoRoutingAction::NoAction;
        }

        if deferred {
            log::info!(
                "Auto-routing: New game server {} observed while another connection is active — \
                 not a routing signal, keeping current relay for it",
                game_server_ip
            );
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
        let session_epoch = self.lookup_session_epoch.load(Ordering::Acquire);

        if sender
            .send((game_server_ip, generation, session_epoch))
            .is_err()
        {
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

    pub fn is_current_lookup_session(&self, session_epoch: u64) -> bool {
        self.lookup_session_epoch.load(Ordering::Acquire) == session_epoch
    }

    /// Whether a completed lookup result is allowed to affect routing.
    ///
    /// Before the first structured lookup succeeds, candidates may resolve in
    /// channel order. After one IP is accepted, a different IP's result is
    /// honored only via the gone-quiet handoff: all other game traffic must
    /// have stopped (player left/teleported), re-checked at processing time
    /// in case the old connection resumed while the lookup was in flight.
    pub fn should_process_lookup_result(&self, ip: Ipv4Addr) -> bool {
        match *self.active_game_server_ip.read() {
            Some(active_ip) => active_ip == ip || self.other_game_traffic_quiet(ip),
            None => true,
        }
    }

    /// Pin the first structured game-server lookup accepted for this session.
    /// Returns false when another IP already owns the active session.
    pub fn pin_active_game_server(&self, ip: Ipv4Addr) -> bool {
        let session_epoch = self.lookup_session_epoch.load(Ordering::Acquire);
        self.pin_active_game_server_for_session(ip, session_epoch)
    }

    /// Pin only if the lookup belongs to the currently active session.
    ///
    /// The session check happens while holding the active-IP lock so reset()
    /// cannot clear the pin between a stale lookup's session check and pin.
    ///
    /// A different IP replaces the pin only via the gone-quiet handoff
    /// (re-verified here under the lock): the previous game-server connection
    /// must have stopped sending, so the replacement is a fresh join whose
    /// packets are still held — switching the relay for it is safe.
    pub fn pin_active_game_server_for_session(&self, ip: Ipv4Addr, session_epoch: u64) -> bool {
        let mut active = self.active_game_server_ip.write();
        if !self.is_current_lookup_session(session_epoch) {
            return false;
        }
        match *active {
            Some(active_ip) if active_ip == ip => true,
            Some(active_ip) => {
                if self.other_game_traffic_quiet(ip) {
                    log::info!(
                        "Auto-routing: Game-server handoff {} -> {} (previous connection quiet)",
                        active_ip,
                        ip
                    );
                    *active = Some(ip);
                    true
                } else {
                    false
                }
            }
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

    /// Final gate before an authenticated switch commits, re-checked after
    /// every await in the lookup task: the router must still be enabled
    /// (disabling Auto Route mid-lookup cancels in-flight switches, not just
    /// future evaluations), the lookup must belong to the current session,
    /// and its IP must still be the active game server.
    pub fn lookup_commit_allowed(&self, ip: Ipv4Addr, session_epoch: u64) -> bool {
        self.is_enabled()
            && self.is_current_lookup_session(session_epoch)
            && self.is_active_game_server(ip)
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
    /// `ip`/`session_epoch` identify the lookup this commit belongs to. The
    /// commit re-runs [`Self::lookup_commit_allowed`] immediately before
    /// mutating relay state so a disable or reset that landed after the
    /// caller's earlier gate cannot be overwritten by a stale lookup. The
    /// check cannot stay locked across `record_switch` (`reset()` acquires
    /// the routing-state locks in the opposite order), but the lookup task
    /// is the only committer and `set_enabled(false)` bumps the session
    /// epoch, so the residual window is a benign last-instant authenticated
    /// switch, never an unauthenticated or mid-session one.
    ///
    /// Returns `Some((addr, region))` if the switch was recorded, `None` if
    /// rate-limited or no longer allowed.
    pub fn commit_switch(
        &self,
        ip: Ipv4Addr,
        session_epoch: u64,
        game_region: RobloxRegion,
        selected_region: String,
        selected_addr: SocketAddr,
        latency_improvement_ms: Option<u32>,
    ) -> Option<(SocketAddr, String)> {
        if !self.lookup_commit_allowed(ip, session_epoch) {
            log::info!(
                "Auto-routing: Commit for {} aborted — lookup no longer owns the route",
                ip
            );
            return None;
        }

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

    /// Non-mutating preview of `record_switch`'s rate-limit decision.
    ///
    /// The lookup task calls this before fetching a relay ticket so a switch
    /// that would be rate-limited doesn't burn a single-use ticket. The
    /// authoritative check still happens inside `commit_switch`.
    pub fn switch_allowed_precheck(
        &self,
        to_region: &str,
        new_addr: SocketAddr,
        latency_improvement_ms: Option<u32>,
    ) -> bool {
        let current_region = self.current_st_region.read().clone();
        let current_addr = *self.current_relay_addr.read();
        if current_region == to_region && current_addr == Some(new_addr) {
            return false;
        }

        let same_region_upgrade = region_family(&current_region) == region_family(to_region)
            && current_addr != Some(new_addr);
        let allow_immediate_upgrade = same_region_upgrade
            && latency_improvement_ms
                .is_some_and(|delta| delta >= SAME_REGION_UPGRADE_THRESHOLD_MS);
        if same_region_upgrade && !allow_immediate_upgrade {
            return false;
        }
        if allow_immediate_upgrade {
            return true;
        }

        let now = Instant::now();
        if now.duration_since(*self.last_switch_time.read()) < MIN_SWITCH_INTERVAL {
            return false;
        }
        let window = self.switches_this_minute.read();
        !(now.duration_since(window.1) <= Duration::from_secs(60)
            && window.0 >= MAX_SWITCHES_PER_MINUTE)
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
        self.lookup_session_epoch.fetch_add(1, Ordering::AcqRel);
        *self.active_game_server_ip.write() = None;
        self.game_traffic.write().clear();
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
        let game_ip = Ipv4Addr::new(128, 116, 50, 1);
        let epoch = pin_for_commit(&router, game_ip);
        let result = router.commit_switch(game_ip, epoch, RobloxRegion::UsEast, region, addr, None);
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
        let (received_ip, generation, session_epoch) =
            rx.try_recv().expect("first lookup should be sent");
        assert_eq!(received_ip, ip);
        assert_eq!(generation, 1);
        assert!(router.is_current_lookup_session(session_epoch));

        // Second call with same IP should NOT send again
        router.evaluate_game_server(ip);
        assert!(rx.try_recv().is_err());
    }

    /// Mark an IP's traffic as last seen `age` ago (test helper for the
    /// gone-quiet handoff gate).
    fn backdate_game_traffic(router: &AutoRouter, ip: Ipv4Addr, age: Duration) {
        let then = Instant::now()
            .checked_sub(age)
            .expect("test backdate within Instant range");
        router.game_traffic.write().insert(ip, then);
    }

    /// Pin `ip` as the active game server and return the current session
    /// epoch (test helper for `commit_switch`'s revalidation gate).
    fn pin_for_commit(router: &AutoRouter, ip: Ipv4Addr) -> u64 {
        let epoch = router.lookup_session_epoch.load(Ordering::Acquire);
        assert!(router.pin_active_game_server_for_session(ip, epoch));
        epoch
    }

    #[test]
    fn test_lookup_generation_tracks_newest_game_server() {
        let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel();
        let router = AutoRouter::new(true, "singapore");
        router.set_lookup_channel(tx);

        let first_ip = Ipv4Addr::new(128, 116, 50, 1);
        router.evaluate_game_server(first_ip);
        let (_, first_generation, first_session_epoch) = rx.try_recv().expect("first lookup");
        assert!(router.is_current_lookup_generation(first_generation));
        assert!(router.is_current_lookup_session(first_session_epoch));

        // Second candidate only becomes a routing signal once the first IP's
        // traffic has gone quiet.
        backdate_game_traffic(&router, first_ip, GAME_TRAFFIC_QUIET_HANDOFF * 2);
        router.evaluate_game_server(Ipv4Addr::new(128, 116, 55, 1));
        let (_, second_generation, second_session_epoch) = rx.try_recv().expect("second lookup");
        assert!(!router.is_current_lookup_generation(first_generation));
        assert!(router.is_current_lookup_generation(second_generation));
        assert_eq!(first_session_epoch, second_session_epoch);
        assert!(router.is_current_lookup_session(second_session_epoch));
    }

    #[test]
    fn test_new_ip_during_active_game_traffic_is_not_a_routing_signal() {
        // Negative case: a second game-server-range IP observed while the
        // first connection is still actively sending must not start a lookup,
        // must not hold packets, and must stay excluded even after the first
        // connection later goes quiet (its connection already established
        // through the current relay — a later switch would change the
        // game-visible source IP mid-session).
        let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel();
        let router = AutoRouter::new(true, "singapore");
        router.set_lookup_channel(tx);

        let first_ip = Ipv4Addr::new(128, 116, 50, 1);
        let overlap_ip = Ipv4Addr::new(128, 116, 55, 1);

        router.evaluate_game_server(first_ip);
        let _ = rx.try_recv().expect("first lookup");

        // first_ip traffic is fresh (just noted) — overlap_ip is deferred.
        router.evaluate_game_server(overlap_ip);
        assert!(
            rx.try_recv().is_err(),
            "deferred candidate must not enqueue a lookup"
        );
        assert!(
            !router.is_lookup_pending(overlap_ip),
            "deferred candidate must not hold packets"
        );

        // Even after the first connection goes quiet, the deferred candidate
        // stays excluded: its session is already flowing through the current
        // relay.
        backdate_game_traffic(&router, first_ip, GAME_TRAFFIC_QUIET_HANDOFF * 2);
        router.evaluate_game_server(overlap_ip);
        assert!(rx.try_recv().is_err());
    }

    #[test]
    fn test_gone_quiet_handoff_replaces_pin_and_allows_new_lookup() {
        let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel();
        let router = AutoRouter::new(true, "singapore");
        router.set_lookup_channel(tx);

        let first_ip = Ipv4Addr::new(128, 116, 50, 1);
        let teleport_ip = Ipv4Addr::new(128, 116, 55, 1);

        router.evaluate_game_server(first_ip);
        let (_, _, epoch) = rx.try_recv().expect("first lookup");
        assert!(router.pin_active_game_server_for_session(first_ip, epoch));

        // Teleport: first connection goes quiet, then the new server appears.
        backdate_game_traffic(&router, first_ip, GAME_TRAFFIC_QUIET_HANDOFF * 2);
        router.evaluate_game_server(teleport_ip);
        let (received_ip, _, epoch2) = rx.try_recv().expect("handoff lookup must be enqueued");
        assert_eq!(received_ip, teleport_ip);
        assert!(
            router.is_lookup_pending(teleport_ip),
            "handoff candidate is held"
        );

        assert!(router.should_process_lookup_result(teleport_ip));
        assert!(router.pin_active_game_server_for_session(teleport_ip, epoch2));
        assert!(router.is_active_game_server(teleport_ip));
        assert!(!router.is_active_game_server(first_ip));
    }

    #[test]
    fn test_handoff_aborts_if_previous_connection_resumes() {
        // The quiet check is re-verified at lookup-processing time: if the
        // previous connection resumes while the handoff lookup is in flight,
        // the result must be discarded.
        let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel();
        let router = AutoRouter::new(true, "singapore");
        router.set_lookup_channel(tx);

        let first_ip = Ipv4Addr::new(128, 116, 50, 1);
        let candidate_ip = Ipv4Addr::new(128, 116, 55, 1);

        router.evaluate_game_server(first_ip);
        let (_, _, epoch) = rx.try_recv().expect("first lookup");
        assert!(router.pin_active_game_server_for_session(first_ip, epoch));

        backdate_game_traffic(&router, first_ip, GAME_TRAFFIC_QUIET_HANDOFF * 2);
        router.evaluate_game_server(candidate_ip);
        let (_, _, epoch2) = rx.try_recv().expect("handoff lookup");

        // First connection resumes before the lookup completes.
        router.note_game_traffic(first_ip);

        assert!(!router.should_process_lookup_result(candidate_ip));
        assert!(!router.pin_active_game_server_for_session(candidate_ip, epoch2));
        assert!(router.is_active_game_server(first_ip));
    }

    #[test]
    fn test_reset_invalidates_inflight_lookup_session() {
        let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel();
        let router = AutoRouter::new(true, "singapore");
        router.set_lookup_channel(tx);

        router.evaluate_game_server(Ipv4Addr::new(128, 116, 50, 1));
        let (_, _generation, session_epoch) = rx.try_recv().expect("lookup");
        assert!(router.is_current_lookup_session(session_epoch));

        router.reset();
        assert!(!router.is_current_lookup_session(session_epoch));
        assert!(
            !router
                .pin_active_game_server_for_session(Ipv4Addr::new(128, 116, 50, 1), session_epoch)
        );
    }

    #[test]
    fn test_disable_mid_lookup_blocks_commit() {
        // Disabling Auto Route while a lookup is in flight (queued, resolving,
        // or mid-auth-handshake) must cancel the switch at commit time, and
        // re-enabling must restore the live gate.
        let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel();
        let router = AutoRouter::new(true, "singapore");
        router.set_lookup_channel(tx);

        let ip = Ipv4Addr::new(128, 116, 50, 1);
        router.evaluate_game_server(ip);
        let (_, _, epoch) = rx.try_recv().expect("lookup enqueued");
        assert!(router.pin_active_game_server_for_session(ip, epoch));
        assert!(
            router.lookup_commit_allowed(ip, epoch),
            "enabled + current session + active ip must commit"
        );

        router.set_enabled(false);
        assert!(
            !router.lookup_commit_allowed(ip, epoch),
            "disable mid-lookup must block the commit even though the lookup is otherwise current"
        );

        // Disable invalidates the lookup permanently: re-enabling must not
        // let the pre-disable lookup commit (its epoch is stale).
        router.set_enabled(true);
        assert!(!router.lookup_commit_allowed(ip, epoch));

        // The gate still enforces session/active-ip staleness independently
        // of the enabled flag.
        let fresh_epoch = router.lookup_session_epoch.load(Ordering::Acquire);
        assert!(router.pin_active_game_server_for_session(ip, fresh_epoch));
        assert!(router.lookup_commit_allowed(ip, fresh_epoch));
        assert!(!router.lookup_commit_allowed(Ipv4Addr::new(128, 116, 55, 1), fresh_epoch));
        assert!(!router.lookup_commit_allowed(ip, fresh_epoch + 1));
    }

    #[test]
    fn test_active_game_server_pins_first_successful_lookup() {
        let router = AutoRouter::new(true, "singapore");
        let first_ip = Ipv4Addr::new(128, 116, 50, 1);
        let later_ip = Ipv4Addr::new(128, 116, 55, 1);

        assert!(router.should_process_lookup_result(first_ip));
        assert!(router.should_process_lookup_result(later_ip));
        assert!(router.pin_active_game_server(first_ip));
        // Pinned connection is actively sending.
        router.note_game_traffic(first_ip);

        assert!(router.should_process_lookup_result(first_ip));
        assert!(
            !router.should_process_lookup_result(later_ip),
            "other lookups must not flip the relay while the pinned game is live"
        );
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
        router.note_game_traffic(retry_ip);
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
    fn test_disable_toggle_invalidates_inflight_lookup() {
        // Toggling Auto Route off then back on while a lookup is in flight
        // must permanently kill that lookup: the later gates would otherwise
        // see the re-enabled value and let a stale switch commit.
        let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel();
        let router = AutoRouter::new(true, "singapore");
        router.set_lookup_channel(tx);

        let ip = Ipv4Addr::new(128, 116, 50, 1);
        router.evaluate_game_server(ip);
        let (_, _, epoch) = rx.try_recv().expect("lookup enqueued");

        router.set_enabled(false);
        router.set_enabled(true);

        assert!(
            !router.is_current_lookup_session(epoch),
            "disable must invalidate the in-flight lookup session"
        );
        assert!(!router.pin_active_game_server_for_session(ip, epoch));
        assert!(!router.lookup_commit_allowed(ip, epoch));

        // A fresh evaluation after re-enable works with the new epoch
        // (old connection has gone quiet, so the new IP is a routing signal).
        let new_ip = Ipv4Addr::new(128, 116, 55, 1);
        backdate_game_traffic(&router, ip, GAME_TRAFFIC_QUIET_HANDOFF * 2);
        router.evaluate_game_server(new_ip);
        let (_, _, new_epoch) = rx.try_recv().expect("post-reenable lookup enqueued");
        assert!(router.is_current_lookup_session(new_epoch));
        assert!(router.pin_active_game_server_for_session(new_ip, new_epoch));
        assert!(router.lookup_commit_allowed(new_ip, new_epoch));
    }

    #[test]
    fn test_commit_switch_revalidates_before_mutating() {
        let router = AutoRouter::new(true, "singapore");
        router.set_available_servers(make_servers());
        router.set_current_relay("54.255.205.216:51821".parse().unwrap(), "singapore");

        let game_ip = Ipv4Addr::new(128, 116, 50, 1);
        let epoch = pin_for_commit(&router, game_ip);
        let target: SocketAddr = "108.61.7.6:51821".parse().unwrap();

        // Stale epoch (disable happened after the caller's gate): refused.
        assert!(
            router
                .commit_switch(
                    game_ip,
                    epoch + 1,
                    RobloxRegion::UsEast,
                    "us-east-nj".to_string(),
                    target,
                    None,
                )
                .is_none(),
            "stale session epoch must not commit"
        );
        // IP that lost the pin: refused.
        assert!(
            router
                .commit_switch(
                    Ipv4Addr::new(128, 116, 99, 1),
                    epoch,
                    RobloxRegion::UsEast,
                    "us-east-nj".to_string(),
                    target,
                    None,
                )
                .is_none(),
            "an IP that does not own the route must not commit"
        );
        // Disabled at commit time: refused, and relay state untouched.
        router.set_enabled(false);
        assert!(
            router
                .commit_switch(
                    game_ip,
                    epoch,
                    RobloxRegion::UsEast,
                    "us-east-nj".to_string(),
                    target,
                    None,
                )
                .is_none()
        );
        assert_eq!(router.current_region(), "singapore");

        // Positive control: re-pin under the post-disable epoch and commit.
        router.set_enabled(true);
        let fresh_epoch = pin_for_commit(&router, game_ip);
        assert!(
            router
                .commit_switch(
                    game_ip,
                    fresh_epoch,
                    RobloxRegion::UsEast,
                    "us-east-nj".to_string(),
                    target,
                    None,
                )
                .is_some()
        );
        assert_eq!(router.current_region(), "us-east-nj");
    }

    #[test]
    fn test_enable_mid_session_does_not_reroute_flowing_connection() {
        // Auto Route off at connect (or toggled off), player already in a
        // game. Enabling from settings must not mistake the flowing
        // connection's next packet for a fresh join — that would hold its
        // packets and commit a mid-session relay switch.
        let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel();
        let router = AutoRouter::new(false, "singapore");
        router.set_lookup_channel(tx);

        let flowing_ip = Ipv4Addr::new(128, 116, 50, 1);
        // Traffic observed while disabled: tracked, but no evaluation.
        router.evaluate_game_server(flowing_ip);
        assert!(rx.try_recv().is_err(), "disabled router must not enqueue");
        assert!(!router.is_lookup_pending(flowing_ip));

        router.set_enabled(true);

        // The flowing connection keeps sending: still not a routing signal.
        router.evaluate_game_server(flowing_ip);
        assert!(
            rx.try_recv().is_err(),
            "flowing connection must not become a routing signal on enable"
        );
        assert!(!router.is_lookup_pending(flowing_ip));

        // After the flowing connection goes quiet, a new join is a signal.
        backdate_game_traffic(&router, flowing_ip, GAME_TRAFFIC_QUIET_HANDOFF * 2);
        let new_ip = Ipv4Addr::new(128, 116, 55, 1);
        router.evaluate_game_server(new_ip);
        let (received_ip, _, _) = rx.try_recv().expect("fresh join after enable is a signal");
        assert_eq!(received_ip, new_ip);
    }

    #[test]
    fn test_enable_after_traffic_went_quiet_treats_next_join_as_fresh() {
        // Negative control for the quarantine: traffic that already went
        // quiet while disabled is NOT quarantined — when the player joins
        // that server again it is a genuine fresh join and must re-route.
        let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel();
        let router = AutoRouter::new(false, "singapore");
        router.set_lookup_channel(tx);

        let ip = Ipv4Addr::new(128, 116, 50, 1);
        router.evaluate_game_server(ip);
        backdate_game_traffic(&router, ip, GAME_TRAFFIC_QUIET_HANDOFF * 2);

        router.set_enabled(true);

        router.evaluate_game_server(ip);
        let (received_ip, _, _) = rx
            .try_recv()
            .expect("quiet IP is a fresh join after enable");
        assert_eq!(received_ip, ip);
        assert!(router.is_lookup_pending(ip));
    }

    #[test]
    fn test_redundant_enable_does_not_quarantine() {
        // Settings saves call set_enabled(true) even when Auto Route was
        // already on; that must not quarantine anything.
        let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel();
        let router = AutoRouter::new(true, "singapore");
        router.set_lookup_channel(tx);

        let ip = Ipv4Addr::new(128, 116, 50, 1);
        router.note_game_traffic(ip);
        router.set_enabled(true);

        router.evaluate_game_server(ip);
        assert!(
            rx.try_recv().is_ok(),
            "already-enabled save must not quarantine pending candidates"
        );
    }

    #[test]
    fn test_disable_clears_bypass() {
        // Disabling Auto Route revokes an active whitelist bypass so game
        // traffic returns to the relay instead of going direct until
        // disconnect.
        let router = AutoRouter::new(true, "singapore");
        router.set_available_servers(make_servers());
        router.set_current_relay("54.255.205.216:51821".parse().unwrap(), "singapore");
        router.set_whitelisted_regions(vec!["US East".to_string()]);

        router.get_best_server_for_region(&RobloxRegion::UsEast);
        assert!(router.is_bypassed());

        router.set_enabled(false);
        assert!(!router.is_bypassed(), "disable must revoke the bypass");

        // Re-enabling must not resurrect the bypass on its own — only a new
        // lookup decision may engage it.
        router.set_enabled(true);
        assert!(!router.is_bypassed());
    }

    #[test]
    fn test_whitelist_update_revokes_stale_bypass_only() {
        let router = AutoRouter::new(true, "singapore");
        router.set_available_servers(make_servers());
        router.set_current_relay("54.255.205.216:51821".parse().unwrap(), "singapore");
        router.set_whitelisted_regions(vec!["US East".to_string()]);

        router.get_best_server_for_region(&RobloxRegion::UsEast);
        assert!(router.is_bypassed());

        // Whitelist update that keeps the current region must NOT revoke.
        router.set_whitelisted_regions(vec!["US East".to_string(), "Tokyo".to_string()]);
        assert!(
            router.is_bypassed(),
            "bypass stays while the current region remains whitelisted"
        );

        // Removing the current region revokes the bypass.
        router.set_whitelisted_regions(vec!["Tokyo".to_string()]);
        assert!(
            !router.is_bypassed(),
            "un-whitelisting must revoke the bypass"
        );

        // Re-adding it must not silently re-engage mid-session.
        router.set_whitelisted_regions(vec!["US East".to_string()]);
        assert!(
            !router.is_bypassed(),
            "bypass only engages at a lookup boundary, never on settings save"
        );
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

        let game_ip = Ipv4Addr::new(128, 116, 50, 1);
        let epoch = pin_for_commit(&router, game_ip);
        let result = router.commit_switch(
            game_ip,
            epoch,
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

        let game_ip = Ipv4Addr::new(128, 116, 50, 1);
        let epoch = pin_for_commit(&router, game_ip);
        let result = router.commit_switch(
            game_ip,
            epoch,
            RobloxRegion::Singapore,
            "singapore".to_string(),
            "54.255.205.216:51821".parse().unwrap(),
            Some(SAME_REGION_UPGRADE_THRESHOLD_MS - 1),
        );

        assert!(result.is_none());
        assert_eq!(router.current_region(), "singapore-02");
    }

    #[test]
    fn test_switch_precheck_matches_commit_decisions() {
        let router = AutoRouter::new(true, "singapore-02");
        router.set_current_relay("203.0.113.2:51821".parse().unwrap(), "singapore-02");
        *router.last_switch_time.write() = Instant::now();

        let same_region_addr: SocketAddr = "54.255.205.216:51821".parse().unwrap();
        // Same-region upgrade below threshold: blocked.
        assert!(!router.switch_allowed_precheck(
            "singapore",
            same_region_addr,
            Some(SAME_REGION_UPGRADE_THRESHOLD_MS - 1)
        ));
        // Same-region upgrade at threshold: allowed even inside min interval.
        assert!(router.switch_allowed_precheck(
            "singapore",
            same_region_addr,
            Some(SAME_REGION_UPGRADE_THRESHOLD_MS)
        ));
        // Same-region upgrade with unknown improvement: blocked (negative
        // case — an unmeasurable improvement is not a switch trigger).
        assert!(!router.switch_allowed_precheck("singapore", same_region_addr, None));

        // Cross-region inside min interval: blocked.
        let tokyo_addr: SocketAddr = "45.32.253.124:51821".parse().unwrap();
        assert!(!router.switch_allowed_precheck("tokyo-02", tokyo_addr, Some(25)));

        // Cross-region after min interval: allowed.
        *router.last_switch_time.write() = Instant::now()
            .checked_sub(MIN_SWITCH_INTERVAL * 2)
            .expect("backdate");
        assert!(router.switch_allowed_precheck("tokyo-02", tokyo_addr, Some(25)));

        // Already on the target: blocked.
        assert!(!router.switch_allowed_precheck(
            "singapore-02",
            "203.0.113.2:51821".parse().unwrap(),
            Some(100)
        ));
    }

    #[test]
    fn test_commit_switch_cross_region_still_respects_min_interval() {
        let router = AutoRouter::new(true, "singapore");
        router.set_current_relay("54.255.205.216:51821".parse().unwrap(), "singapore");
        *router.last_switch_time.write() = Instant::now();

        let game_ip = Ipv4Addr::new(128, 116, 50, 1);
        let epoch = pin_for_commit(&router, game_ip);
        let result = router.commit_switch(
            game_ip,
            epoch,
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
