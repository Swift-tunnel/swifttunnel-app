//! VPN Connection Manager
//!
//! Manages the lifecycle of VPN connections, coordinating:
//! - Relay endpoint resolution
//! - Split tunneling via ndisapi (process-based per-app routing)
//! - UDP relay for game traffic forwarding
//! - Connection state tracking

use super::local_connectivity::LocalConnectivity;
use super::parallel_interceptor::WorkerPanicCause;
use super::parallel_interceptor::{
    AdapterBindingPreference, QueueOverflowMode, ThroughputStats,
    is_point_to_point_default_route_context,
};
use super::process_performance::{GameProcessPerformanceManager, GameProcessPerformancePolicy};
use super::process_watcher::{ProcessStartEvent, ProcessWatcher};
use super::split_tunnel::{SplitTunnelConfig, SplitTunnelDriver};
use super::{VpnError, VpnResult};
use crate::auth::http_client::AuthClient;
use crate::auth::types::{AuthError, RelayPreflightMode, RelayQueueFullMode, VpnConfig};
use crate::settings::GameProcessPerformanceSettings;
use crossbeam_channel::Receiver;
use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicI64, AtomicU64, Ordering};
use std::time::{Duration, Instant};
use tokio::sync::{Mutex, watch};

/// Refresh interval for process exclusion scanning (ms)
/// Lower = faster detection of new processes, slightly higher CPU
/// 500ms balances detection speed with CPU usage
const REFRESH_INTERVAL_MS: u64 = 500;

/// How long after a successful connect we keep the local-connectivity watchdog
/// armed. The point of the watchdog is specifically to catch *adapter-reset
/// rollback* — `Set-NetAdapterAdvancedProperty` calls during interceptor start
/// can briefly bounce the NIC on some hardware (Realtek, Killer, USB-Ethernet)
/// and we want to fail fast with a clear retry message instead of letting the
/// user sit through the relay-dead timeout. After this window passes we
/// disarm; mid-session connectivity loss is handled by the existing
/// `classify_relay_health` path which also consults `LocalConnectivity`.
const ADAPTER_WATCHDOG_WINDOW_SECS: u64 = 30;

/// Number of consecutive `LocalConnectivity::Offline` ticks (each spaced
/// `REFRESH_INTERVAL_MS` apart, and only counted when relay health is
/// also non-`Healthy`) before the watchdog aborts the session. With the
/// 500ms tick this is a 3s sustained dual-signal floor — long enough to
/// ignore brief link flaps (Wi-Fi handover, momentary route refresh) and
/// short enough to abort well before the relay-dead timeout fires.
const ADAPTER_WATCHDOG_OFFLINE_TICK_THRESHOLD: u32 = 6;

/// Cleanup-reason marker propagated through the existing teardown path when
/// the watchdog fires. Distinct from `relay_dead_recovery` /
/// `internet_lost_recovery` so process-performance and telemetry can
/// distinguish "we aborted during the connect window because the adapter
/// reset took the route with it" from mid-session relay loss.
const ADAPTER_RESET_ROLLBACK_REASON: &str = "adapter_reset_rollback";

/// Error string surfaced to the UI on watchdog rollback. Wording deliberately
/// asks the user to retry — the path is recoverable on next connect.
const ADAPTER_RESET_ROLLBACK_MESSAGE: &str = "SwiftTunnel rolled back the connection because your network adapter went offline during setup. This usually clears up on its own — please try connecting again.";
const ETW_CONNECTION_READY_TIMEOUT_MS: u64 = 150;
const ETW_CONNECTION_READY_POLL_MS: u64 = 5;
/// Once the UDP relay health reaches `Dead`, keep the session alive briefly
/// before teardown. Real dead relays still fail, but short NAT/ISP return-path
/// stalls get a chance to recover instead of kicking users mid-game.
const RELAY_DEAD_GRACE_SECS: u64 = 20;
/// Authenticated relay leases last five minutes. Refresh comfortably before
/// expiry while leaving enough room for a transient API failure and retry.
const RELAY_LEASE_REFRESH_INTERVAL: Duration = Duration::from_secs(120);
const RELAY_LEASE_RETRY_INTERVAL: Duration = Duration::from_secs(30);
/// Number of ICMP samples to collect per relay candidate when probing.
const AUTO_ROUTING_PING_SAMPLES: usize = 5;
const CONNECT_FAIL_HANDSHAKE_TIMEOUT: &str = "ST_CONNECT_HANDSHAKE_TIMEOUT";
const CONNECT_FAIL_CANDIDATE_EXHAUSTED: &str = "ST_CONNECT_CANDIDATE_EXHAUSTED";
const CONNECT_FAIL_PREFLIGHT_ENFORCED: &str = "ST_CONNECT_PREFLIGHT_ENFORCED";
const CONNECT_FAIL_AUTH_REQUIRED: &str = "ST_CONNECT_AUTH_REQUIRED";
const CONNECT_FAIL_POLICY_UNAVAILABLE: &str = "ST_CONNECT_POLICY_UNAVAILABLE";
const CONNECT_FAIL_REGION_UNAVAILABLE: &str = "ST_CONNECT_REGION_UNAVAILABLE";

/// Relay UDP port used *only* as a last-resort fallback when the resolved
/// server list carried no relay candidate (and no custom relay is configured)
/// to derive a port from. Normal connects use the per-relay `relay_port`
/// advertised by `/api/vpn/servers`; reaching this constant means the server
/// list was empty or malformed, which `setup_split_tunnel` logs as a warning.
const FALLBACK_RELAY_PORT: u16 = 51821;

/// Latest free-tier budget reported by the backend, in seconds. `-1` means
/// "no limit known" — either the backend has the limit switched off, or it
/// predates the feature and omits the fields.
///
/// Refreshed every time a relay ticket is fetched (~2 min while connected).
/// The UI ticks its own countdown between refreshes and resyncs from here.
static FREE_TIER_REMAINING_SECS: AtomicI64 = AtomicI64::new(-1);
static FREE_TIER_LIMIT_SECS: AtomicI64 = AtomicI64::new(-1);

/// Grace left after the allowance ran out, `-1` when not in grace. The backend
/// is still issuing leases during this window, so the client must keep the
/// session up and only warn.
static FREE_TIER_GRACE_SECS: AtomicI64 = AtomicI64::new(-1);

/// Record the budget carried on a freshly fetched ticket.
fn record_free_tier_quota(ticket: &crate::auth::types::RelayTicketResponse) {
    FREE_TIER_REMAINING_SECS.store(ticket.remaining_seconds.unwrap_or(-1), Ordering::Relaxed);
    FREE_TIER_LIMIT_SECS.store(ticket.limit_seconds.unwrap_or(-1), Ordering::Relaxed);
    FREE_TIER_GRACE_SECS.store(ticket.grace_seconds.unwrap_or(-1), Ordering::Relaxed);
}

/// Whether the crowded-relay notice has already been shown for the relay we are
/// currently on. Tickets refresh every few minutes for as long as someone stays
/// connected, so without this the same warning would fire repeatedly through a
/// whole session.
static CROWDING_WARNED_FOR: std::sync::Mutex<Option<String>> = std::sync::Mutex::new(None);

/// Tell the user once when the relay they pinned is busy and a quieter one in
/// the same city is available.
///
/// Only fires for a pinned server: automatic selection already prefers a
/// quieter relay, so reaching this means the user chose this box explicitly and
/// is the only one who can act on it.
fn notify_if_relay_crowded(region: &str, ticket: &crate::auth::types::RelayTicketResponse) {
    if !ticket.degraded {
        // Recovered, or a different relay: allow a future warning to fire.
        if let Ok(mut warned) = CROWDING_WARNED_FOR.lock()
            && warned.as_deref() == Some(region)
        {
            *warned = None;
        }
        return;
    }

    match CROWDING_WARNED_FOR.lock() {
        Ok(mut warned) => {
            if warned.as_deref() == Some(region) {
                return;
            }
            *warned = Some(region.to_string());
        }
        Err(_) => return,
    }

    let label = crate::discord_rpc::region_display_label(region);
    let message = match ticket.suggested_region.as_deref() {
        Some(alt) => format!(
            "{} is busy right now. {} is quieter - switch for a better connection.",
            label,
            crate::discord_rpc::region_display_label(alt)
        ),
        None => format!("{} is busy right now, so your ping may be higher.", label),
    };

    log::info!("Relay {} reported crowded; notifying user", region);
    crate::notification::show_notification("Server busy", &message);
}

/// `(remaining_seconds, limit_seconds)`, each `None` when no limit applies.
pub fn free_tier_quota() -> (Option<i64>, Option<i64>) {
    let remaining = FREE_TIER_REMAINING_SECS.load(Ordering::Relaxed);
    let limit = FREE_TIER_LIMIT_SECS.load(Ordering::Relaxed);
    (
        if remaining < 0 { None } else { Some(remaining) },
        if limit <= 0 { None } else { Some(limit) },
    )
}

/// Grace seconds left, or `None` when the allowance has not run out.
pub fn free_tier_grace_seconds() -> Option<i64> {
    let grace = FREE_TIER_GRACE_SECS.load(Ordering::Relaxed);
    if grace < 0 { None } else { Some(grace) }
}

static HANDSHAKE_TIMEOUT_EVENTS: AtomicU64 = AtomicU64::new(0);
static CANDIDATE_EXHAUSTED_EVENTS: AtomicU64 = AtomicU64::new(0);
static PREFLIGHT_ENFORCED_EVENTS: AtomicU64 = AtomicU64::new(0);
static AUTH_REQUIRED_EVENTS: AtomicU64 = AtomicU64::new(0);
static POLICY_UNAVAILABLE_EVENTS: AtomicU64 = AtomicU64::new(0);
static REGION_UNAVAILABLE_EVENTS: AtomicU64 = AtomicU64::new(0);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct TunnelRoutingFlags {
    api_tunneling: bool,
    udp_tunneling: bool,
}

/// Resolve the per-protocol relay behavior from the three user-facing toggles.
///
/// - Route Assist: relay Roblox's control-plane TCP so matchmaking lands the
///   player in game servers near the tunneled region. It only adds the TCP
///   control-plane path; normal SwiftTunnel gameplay UDP routing remains the
///   owner of in-game traffic while connected.
/// - Full country-ban bypass (whole platform blocked, e.g. Egypt): relay the
///   control plane AND gameplay UDP — the censor may block Roblox's IP ranges
///   wholesale, so nothing can be trusted to the direct path. GoodbyeDPI runs
///   on top; the relay is the fallback when DPI evasion alone isn't enough.
/// - Partial country-ban bypass (only specific games blocked, e.g. Vietnam):
///   relay the Roblox web/search/join control path so banned games appear and
///   launch, while gameplay UDP and bulk assets stay DIRECT for normal ping.
///   If Route Assist is also enabled from an older/bad settings state, Partial
///   wins: stacking both has caused temporary joins followed by Roblox
///   server/menu failures.
fn resolve_tunnel_routing_flags(
    route_assist_requested: bool,
    full_ban_bypass_requested: bool,
) -> TunnelRoutingFlags {
    TunnelRoutingFlags {
        api_tunneling: route_assist_requested || full_ban_bypass_requested,
        // Unconditional since Partial Bypass was removed: it was the only mode
        // that wanted Roblox TCP relayed while gameplay UDP stayed direct.
        // Keeping the field rather than deleting it avoids churning ~30 call
        // sites for a value that is now constant.
        udp_tunneling: true,
    }
}

#[derive(Debug, Clone)]
struct RelayCandidateAttempt {
    region: String,
    addr: SocketAddr,
    authenticated: bool,
    policy_known: bool,
    auth_required: bool,
    preflight_mode: RelayPreflightMode,
    queue_full_mode: RelayQueueFullMode,
}

fn log_sampled_connect_event(counter: &AtomicU64, code: &str, message: impl AsRef<str>) {
    let event = counter.fetch_add(1, Ordering::Relaxed) + 1;
    if event <= 5 || event.is_power_of_two() {
        log::warn!("{}: {} (event #{})", code, message.as_ref(), event);
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum RelayHealthAction {
    Continue {
        relay_status: Option<String>,
    },
    Fatal {
        error_message: String,
        cleanup_reason: &'static str,
    },
}

fn classify_relay_health(
    health: super::udp_relay::RelayHealthState,
    sender_panicked: bool,
    local_connectivity: LocalConnectivity,
    relay_dead_grace_elapsed: bool,
) -> RelayHealthAction {
    use super::udp_relay::RelayHealthState;

    if sender_panicked {
        // The relay sender thread panicked or hit an unrecoverable send error.
        // Every outbound game packet is silently dropped for the rest of this
        // session, so the connection is effectively dead. Prefer this
        // structured sender-failure signal even if relay health has also raced
        // to Dead, so teardown records the primary failure instead of a generic
        // relay-dead label.
        return RelayHealthAction::Fatal {
            error_message: "Relay connection failed - SwiftTunnel stopped the session because the outbound relay path failed. Please reconnect."
                .to_string(),
            cleanup_reason: "relay_sender_panicked",
        };
    }

    if health == RelayHealthState::Dead {
        // The relay-dead heuristic also fires when the user's own machine
        // loses internet (Wi-Fi blip, sleep/resume, ISP outage): keepalives
        // appear "unanswered" purely because nothing leaves the NIC. Asking
        // Windows whether it currently has internet lets us pick a message
        // the user can act on instead of telling them to choose a different
        // relay when no relay is reachable.
        if local_connectivity == LocalConnectivity::Offline {
            return RelayHealthAction::Fatal {
                error_message: "Internet connection lost - SwiftTunnel stopped the session because your device went offline. Reconnect to your network and try again."
                    .to_string(),
                cleanup_reason: "internet_lost_recovery",
            };
        }
        if !relay_dead_grace_elapsed {
            return RelayHealthAction::Continue {
                relay_status: Some("dead".to_string()),
            };
        }
        return RelayHealthAction::Fatal {
            error_message: "Relay connection failed - SwiftTunnel stopped the session because the relay stopped returning traffic. Please reconnect or choose another relay."
                .to_string(),
            cleanup_reason: "relay_dead_recovery",
        };
    }

    match health {
        RelayHealthState::Stale => RelayHealthAction::Continue {
            relay_status: Some("stale".to_string()),
        },
        RelayHealthState::Healthy | RelayHealthState::NoTrafficYet => {
            RelayHealthAction::Continue { relay_status: None }
        }
        RelayHealthState::Dead => unreachable!("handled above"),
    }
}

/// Maps a `WorkerPanicCause` to the user-facing error message and the
/// teardown `cleanup_reason` marker. Pulled out as a pure function so the
/// UI-contract wording is unit-testable.
///
/// `ReaderHandleLost` MUST keep wording that matches `isDriverMissing()` in
/// swifttunnel-desktop/src/components/connect/connectState.ts — that helper
/// substring-matches "split tunnel driver not available" AND "windows packet
/// filter driver" (case-insensitive) to render the install-driver CTA.
/// `InternalThreadFailed` MUST NOT contain those substrings: a panicked
/// reader/inbound thread is an internal bug, not a missing driver, so the UI
/// should offer a plain reconnect instead of a misleading reinstall prompt.
fn worker_panic_error(cause: WorkerPanicCause) -> (String, &'static str) {
    match cause {
        WorkerPanicCause::ReaderHandleLost => (
            "Split tunnel driver not available — the Windows Packet Filter driver lost \
             its adapter handle and could not recover. Please reconnect, or reinstall \
             the driver."
                .to_string(),
            "workers_panicked_recovery",
        ),
        WorkerPanicCause::InternalThreadFailed => (
            "SwiftTunnel stopped the session because an internal networking thread failed \
             unexpectedly. Please reconnect."
                .to_string(),
            "worker_thread_failed_recovery",
        ),
    }
}

/// Decision returned by the post-connect adapter-reset watchdog on each
/// refresh tick. Pulled out as a pure function so the threshold and
/// window semantics can be unit-tested without spinning up the full
/// async monitor.
#[derive(Debug, Clone, PartialEq, Eq)]
enum WatchdogTickAction {
    /// Window still active; the dual-signal gate did not push the counter
    /// past threshold. The caller stores `consecutive_offline_ticks` for
    /// the next tick. The counter only increments when probe is `Offline`
    /// AND relay health is *not* `Healthy`; any other combination resets
    /// it to 0 — `Reachable`, `Unknown`, or relay still `Healthy` are all
    /// "internet works" signals from the watchdog's perspective.
    Continue { consecutive_offline_ticks: u32 },
    /// Counter reached the offline-tick threshold inside the window — abort
    /// the session and run the standard teardown with this reason/message.
    Abort {
        error_message: String,
        cleanup_reason: &'static str,
    },
    /// 30s window has elapsed without firing. Watchdog disarms for the rest
    /// of this session; relay-health monitoring takes over from here.
    Disarmed,
}

fn watchdog_tick(
    elapsed_since_connect: Duration,
    probe: LocalConnectivity,
    relay_health: super::udp_relay::RelayHealthState,
    prior_consecutive_offline_ticks: u32,
) -> WatchdogTickAction {
    use super::udp_relay::RelayHealthState;

    if elapsed_since_connect >= Duration::from_secs(ADAPTER_WATCHDOG_WINDOW_SECS) {
        return WatchdogTickAction::Disarmed;
    }

    // Two-signal gate. NLM Offline alone is a heuristic — captive/filtered
    // networks, hidden-SSID corporate setups, and NLM bugs can produce
    // false-positive Offline reports on machines that are actually online.
    // Relay `Healthy` is positive ground truth: we've recently received an
    // inbound packet through this NIC, so the user provably has working
    // internet right now regardless of what NLM says. Only count an Offline
    // tick if both signals agree something is wrong.
    //
    // `Unknown` for the probe (API failure / non-Windows / Hidden hint) and
    // `Reachable` both reset the counter — same "do not act on Unknown"
    // semantic that `classify_relay_health` uses.
    let new_count = match (probe, relay_health) {
        (
            LocalConnectivity::Offline,
            RelayHealthState::NoTrafficYet | RelayHealthState::Stale | RelayHealthState::Dead,
        ) => prior_consecutive_offline_ticks.saturating_add(1),
        _ => 0,
    };

    if new_count >= ADAPTER_WATCHDOG_OFFLINE_TICK_THRESHOLD {
        WatchdogTickAction::Abort {
            error_message: ADAPTER_RESET_ROLLBACK_MESSAGE.to_string(),
            cleanup_reason: ADAPTER_RESET_ROLLBACK_REASON,
        }
    } else {
        WatchdogTickAction::Continue {
            consecutive_offline_ticks: new_count,
        }
    }
}

fn select_candidate_after_preflight(
    attempts: &[RelayCandidateAttempt],
) -> Result<(String, SocketAddr, RelayQueueFullMode), &'static str> {
    if let Some(attempt) = attempts.iter().find(|attempt| attempt.authenticated) {
        return Ok((
            attempt.region.clone(),
            attempt.addr,
            attempt.queue_full_mode,
        ));
    }

    let fallback = attempts.first().ok_or(CONNECT_FAIL_CANDIDATE_EXHAUSTED)?;

    if attempts.iter().any(|attempt| attempt.auth_required) {
        return Err(CONNECT_FAIL_AUTH_REQUIRED);
    }

    if attempts
        .iter()
        .any(|attempt| attempt.preflight_mode == RelayPreflightMode::Enforce)
    {
        return Err(CONNECT_FAIL_PREFLIGHT_ENFORCED);
    }

    Ok((
        fallback.region.clone(),
        fallback.addr,
        fallback.queue_full_mode,
    ))
}

fn relay_ticket_ban_reason(error: &AuthError) -> Option<String> {
    match error {
        AuthError::UserBanned(reason) => Some(reason.clone()),
        _ => None,
    }
}

/// The API rejected our session, so every relay will refuse a ticket too. Like
/// the quota case this stops the candidate loop, but unlike it the app must also
/// end the session: retrying is useless until the user signs in again.
fn relay_ticket_session_dead(error: &AuthError) -> bool {
    matches!(
        error,
        AuthError::RefreshTokenInvalid | AuthError::NotAuthenticated
    )
}

/// The quota is per account, not per relay, so a 429 here means every remaining
/// candidate would 429 too. Callers use this to stop the candidate loop instead
/// of walking the whole fleet before failing.
/// The API refused because this build is too old (426 `update_required`).
///
/// Every relay will refuse too, so the connect must abort here. Without this
/// the error fell through to the generic "candidate unavailable" path, which
/// records `auth_required: false` — leaving the legacy-fallback selector with
/// no evidence that authentication was mandatory, so it happily connected.
fn relay_ticket_update_required_message(error: &AuthError) -> Option<String> {
    match error {
        AuthError::UpdateRequired(message) => Some(message.clone()),
        _ => None,
    }
}

fn relay_ticket_quota_message(error: &AuthError) -> Option<String> {
    match error {
        AuthError::FreeTierLimitReached(message) => Some(message.clone()),
        _ => None,
    }
}

fn terminal_relay_lease_error_message(error: &AuthError) -> Option<String> {
    if let Some(message) = relay_ticket_quota_message(error) {
        return Some(message);
    }

    if let Some(message) = relay_ticket_update_required_message(error) {
        return Some(message);
    }

    if let Some(reason) = relay_ticket_ban_reason(error) {
        return Some(format!("Your SwiftTunnel account is blocked: {reason}"));
    }

    relay_ticket_session_dead(error)
        .then(|| "Your SwiftTunnel session expired. Sign in again.".to_string())
}

/// Relays within this many ms of the fastest are treated as equivalent, so the
/// choice between them can be made on occupancy instead.
///
/// Sized from the real fleet: same-city pairs measure 2-3ms apart (mumbai1 23
/// vs mumbai2 25, sg1 41 vs sg2 43, tokyo1 115 vs tokyo2 118) and sit well
/// inside the band, while different regions are 50ms+ apart and never get
/// mistaken for one another. Nobody can feel 3ms; everybody feels a saturated
/// box.
const LATENCY_TIE_BAND_MS: u32 = 15;

/// Pick a relay, preferring a quieter one among those that are equally fast.
///
/// This used to be `min_by_key(latency)` alone, which reliably crowds one box:
/// the emptiest relay answers fastest, so every client picks it, and it only
/// stops being attractive once it has already degraded. Latency is also sampled
/// once at connect and never revisited, so whoever arrived while a box was
/// empty rides it all the way down.
///
/// Outside the band latency still wins outright — occupancy never sends anyone
/// to a slower region.
#[allow(dead_code)]
fn pick_lowest_latency_server<'a>(
    candidates: impl Iterator<Item = &'a (String, SocketAddr, Option<u32>)>,
) -> Option<&'a (String, SocketAddr, Option<u32>)> {
    let all: Vec<&(String, SocketAddr, Option<u32>)> = candidates.collect();
    let fastest = all.iter().filter_map(|(_, _, ms)| *ms).min()?;

    all.into_iter()
        .filter(|(_, _, ms)| ms.is_some_and(|v| v.saturating_sub(fastest) <= LATENCY_TIE_BAND_MS))
        .min_by_key(|(region, _, latency_ms)| {
            let (bucket, metered) = relay_load_rank(region);
            (bucket, metered, latency_ms.unwrap_or(u32::MAX))
        })
}

/// Occupancy is compared in coarse steps so ordinary churn does not flip the
/// choice between two relays on every reconnect.
const RELAY_LOAD_BUCKET_USERS: u32 = 20;

/// Bucket given to a relay whose occupancy is unknown: the worst one.
const RELAY_LOAD_BUCKET_MAX: u32 = 4;

/// How a relay's occupancy and cost rank it against an equally fast neighbour.
/// Lower is preferred.
///
/// Unknown occupancy ranks worst rather than best. A relay that has stopped
/// reporting must not become the box everybody is sent to, which is exactly
/// what treating `None` as empty would do.
fn relay_load_rank(region: &str) -> (u32, u32) {
    let load = crate::vpn::servers::relay_load(region);
    let bucket = match load.and_then(|l| l.active_users) {
        Some(users) => (users / RELAY_LOAD_BUCKET_USERS).min(RELAY_LOAD_BUCKET_MAX),
        None => RELAY_LOAD_BUCKET_MAX,
    };
    let metered = load.map_or(0, |l| u32::from(l.metered));
    (bucket, metered)
}

async fn wait_for_tunnel_process_connections(
    driver: &Arc<Mutex<SplitTunnelDriver>>,
    events: &[ProcessStartEvent],
) -> Vec<(u32, String)> {
    let deadline = Instant::now() + Duration::from_millis(ETW_CONNECTION_READY_TIMEOUT_MS);
    let poll_interval = Duration::from_millis(ETW_CONNECTION_READY_POLL_MS);
    loop {
        if Instant::now() >= deadline {
            let driver_guard = driver.lock().await;
            return events
                .iter()
                .filter(|event| !driver_guard.has_cached_connection_for_pid(event.pid))
                .map(|event| (event.pid, event.name.clone()))
                .collect();
        }

        let mut driver_guard = driver.lock().await;
        if let Err(e) = driver_guard.refresh_exclusions() {
            log::warn!("V3: Refresh during ETW hold failed: {}", e);
        }

        let pending: Vec<(u32, String)> = events
            .iter()
            .filter(|event| !driver_guard.has_cached_connection_for_pid(event.pid))
            .map(|event| (event.pid, event.name.clone()))
            .collect();
        drop(driver_guard);

        if pending.is_empty() || Instant::now() >= deadline {
            return pending;
        }

        tokio::time::sleep(poll_interval).await;
    }
}

#[derive(Debug, Clone)]
struct RankedRelayCandidate {
    region: String,
    addr: SocketAddr,
    cached_latency_ms: Option<u32>,
    probed_latency_ms: Option<u32>,
}

impl RankedRelayCandidate {
    fn from_candidate(candidate: (String, SocketAddr, Option<u32>)) -> Self {
        let (region, addr, cached_latency_ms) = candidate;
        Self {
            region,
            addr,
            cached_latency_ms,
            probed_latency_ms: None,
        }
    }

    fn effective_latency_ms(&self) -> Option<u32> {
        self.probed_latency_ms.or(self.cached_latency_ms)
    }
}

#[derive(Debug, Clone)]
struct RelayProbeMeasurement {
    region: String,
    addr: SocketAddr,
    latency_ms: Option<u32>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum RelaySelectionSource {
    FreshProbe,
    CachedLatency,
    Deterministic,
}

pub(crate) fn region_family(region: &str) -> String {
    let parts: Vec<&str> = region.split('-').collect();
    if parts.len() >= 3 && parts.first() == Some(&"us") {
        return format!("{}-{}", parts[0], parts[1]);
    }
    if parts.len() >= 2
        && parts
            .last()
            .is_some_and(|part| part.chars().all(|ch| ch.is_ascii_digit()))
    {
        return parts[..parts.len() - 1].join("-");
    }
    region.to_string()
}

fn region_matches_candidate(selected_region: &str, server_region: &str) -> bool {
    // `selected_region` is expected to be a canonical region id like `germany`,
    // `singapore`, or `us-east`, not a broad prefix like `us`.
    region_family(server_region) == selected_region
}

pub(crate) fn relay_candidates_for_region(
    selected_region: &str,
    available_servers: &[(String, SocketAddr, Option<u32>)],
    forced_server: Option<&str>,
) -> Vec<(String, SocketAddr, Option<u32>)> {
    // If a specific server is pinned for this region, use it directly
    if let Some(pinned) = forced_server {
        if let Some((server_region, relay_addr, latency_ms)) = available_servers
            .iter()
            .find(|(server_region, _, _)| server_region == pinned)
        {
            log::info!(
                "Using pinned server '{}' for region '{}'",
                pinned,
                selected_region
            );
            return vec![(server_region.clone(), *relay_addr, *latency_ms)];
        }
        log::warn!(
            "Pinned server '{}' not found in server list, falling back to best latency",
            pinned
        );
    }

    available_servers
        .iter()
        .filter(|(server_region, _, _)| region_matches_candidate(selected_region, server_region))
        .map(|(server_region, relay_addr, latency_ms)| {
            (server_region.clone(), *relay_addr, *latency_ms)
        })
        .collect()
}

fn sort_ranked_candidates(candidates: &mut [RankedRelayCandidate]) -> RelaySelectionSource {
    let any_successful_probe = candidates
        .iter()
        .any(|candidate| candidate.probed_latency_ms.is_some());

    // The number everything is ranked on. Once any probe has succeeded a
    // measured latency beats a remembered one outright, so unprobed candidates
    // drop to the back rather than competing on a stale figure.
    let ranking_latency = |candidate: &RankedRelayCandidate| -> Option<u32> {
        if any_successful_probe {
            candidate.probed_latency_ms
        } else {
            candidate.cached_latency_ms
        }
    };

    // Relays within LATENCY_TIE_BAND_MS of this count as equally fast, and the
    // choice between them is made on occupancy instead.
    //
    // Computed once over the whole set rather than inside the comparator:
    // "within the band" is a property of the group, not of any pair, and a
    // comparator that cannot see the fastest candidate cannot decide it.
    let fastest = candidates.iter().filter_map(ranking_latency).min();

    candidates.sort_by_cached_key(|candidate| {
        let latency = ranking_latency(candidate);
        let in_tie_band = match (latency, fastest) {
            (Some(ms), Some(best)) => ms.saturating_sub(best) <= LATENCY_TIE_BAND_MS,
            _ => false,
        };

        // Occupancy only ever breaks a tie. Outside the band it is zeroed, so a
        // quiet relay can never pull anyone into a slower region: the band flag
        // itself has already ordered those candidates behind every in-band one.
        let (load_bucket, metered) = if in_tie_band {
            relay_load_rank(&candidate.region)
        } else {
            (0, 0)
        };

        (
            latency.is_none(),
            u8::from(!in_tie_band),
            load_bucket,
            metered,
            latency.unwrap_or(u32::MAX),
            candidate.cached_latency_ms.unwrap_or(u32::MAX),
            candidate.region.clone(),
            candidate.addr.ip(),
            candidate.addr.port(),
        )
    });

    if any_successful_probe {
        RelaySelectionSource::FreshProbe
    } else if candidates
        .first()
        .and_then(|candidate| candidate.cached_latency_ms)
        .is_some()
    {
        RelaySelectionSource::CachedLatency
    } else {
        RelaySelectionSource::Deterministic
    }
}

fn log_resolution_source(source: RelaySelectionSource, candidate: &RankedRelayCandidate) {
    match source {
        RelaySelectionSource::FreshProbe => {
            if let Some(latency_ms) = candidate.probed_latency_ms {
                log::info!(
                    "Resolved via fresh probe to {} ({}) at {}ms",
                    candidate.region,
                    candidate.addr,
                    latency_ms
                );
            }
        }
        RelaySelectionSource::CachedLatency => {
            if let Some(latency_ms) = candidate.cached_latency_ms {
                log::info!(
                    "Resolved via cached latency to {} ({}) at {}ms",
                    candidate.region,
                    candidate.addr,
                    latency_ms
                );
            }
        }
        RelaySelectionSource::Deterministic => {
            log::info!(
                "Resolved via deterministic fallback to {} ({})",
                candidate.region,
                candidate.addr
            );
        }
    }
}

fn apply_probe_measurements(
    candidates: &mut [RankedRelayCandidate],
    probe_results: &[RelayProbeMeasurement],
) {
    for measurement in probe_results {
        if let Some(candidate) = candidates.iter_mut().find(|candidate| {
            candidate.region == measurement.region && candidate.addr == measurement.addr
        }) {
            candidate.probed_latency_ms = measurement.latency_ms;
        }
    }
}

fn ranked_candidates_from_raw(
    candidates: Vec<(String, SocketAddr, Option<u32>)>,
) -> Vec<RankedRelayCandidate> {
    candidates
        .into_iter()
        .map(RankedRelayCandidate::from_candidate)
        .collect()
}

async fn ranked_relay_candidates_for_region(
    selected_region: &str,
    available_servers: &[(String, SocketAddr, Option<u32>)],
    forced_server: Option<&str>,
) -> Vec<RankedRelayCandidate> {
    let raw_candidates =
        relay_candidates_for_region(selected_region, available_servers, forced_server);
    let mut candidates = ranked_candidates_from_raw(raw_candidates);
    if candidates.is_empty() {
        return candidates;
    }

    if candidates.len() > 1 {
        let all_have_cached = candidates.iter().all(|c| c.cached_latency_ms.is_some());
        if all_have_cached {
            log::info!(
                "Skipping relay probing — all {} candidates have cached latency",
                candidates.len()
            );
        } else {
            let probe_targets: Vec<(String, SocketAddr)> = candidates
                .iter()
                .map(|candidate| (candidate.region.clone(), candidate.addr))
                .collect();
            let probe_results = probe_relay_candidates(&probe_targets).await;
            apply_probe_measurements(&mut candidates, &probe_results);
        }
    }

    let source = sort_ranked_candidates(&mut candidates);
    if let Some(candidate) = candidates.first() {
        log_resolution_source(source, candidate);
    }
    candidates
}

#[allow(dead_code)]
fn sort_candidates_by_latency(candidates: &mut [(String, SocketAddr, Option<u32>)]) {
    candidates.sort_by(|a, b| {
        let a_latency = a.2.unwrap_or(u32::MAX);
        let b_latency = b.2.unwrap_or(u32::MAX);
        a_latency
            .cmp(&b_latency)
            .then_with(|| a.0.cmp(&b.0))
            .then_with(|| a.1.ip().cmp(&b.1.ip()))
            .then_with(|| a.1.port().cmp(&b.1.port()))
    });
}

#[allow(dead_code)]
fn resolved_forced_server(
    forced_for_region: Option<&str>,
    relay_candidates: &[(String, SocketAddr, Option<u32>)],
) -> Option<String> {
    let forced = forced_for_region?;
    relay_candidates
        .iter()
        .find(|(candidate_region, _, _)| candidate_region == forced)
        .map(|(candidate_region, _, _)| candidate_region.clone())
}

fn dedupe_process_names(processes: &[(u32, String)]) -> Vec<String> {
    let mut names: Vec<String> = processes.iter().map(|(_, name)| name.clone()).collect();
    names.sort();
    names.dedup();
    names
}

async fn ordered_relay_candidates_for_region(
    selected_region: &str,
    available_servers: &[(String, SocketAddr, Option<u32>)],
    forced_server: Option<&str>,
) -> Vec<(String, SocketAddr, Option<u32>)> {
    ranked_relay_candidates_for_region(selected_region, available_servers, forced_server)
        .await
        .into_iter()
        .map(|candidate| {
            let latency_ms = candidate.effective_latency_ms();
            (candidate.region, candidate.addr, latency_ms)
        })
        .collect()
}

#[allow(dead_code)]
pub(crate) fn resolve_relay_server_for_region(
    selected_region: &str,
    available_servers: &[(String, SocketAddr, Option<u32>)],
    forced_server: Option<&str>,
) -> Option<(String, SocketAddr)> {
    let mut candidates =
        relay_candidates_for_region(selected_region, available_servers, forced_server);
    sort_candidates_by_latency(&mut candidates);
    pick_lowest_latency_server(candidates.iter())
        .map(|(server_region, relay_addr, _)| (server_region.clone(), *relay_addr))
}

fn average_probe_latency(samples: &[u32]) -> Option<u32> {
    if samples.is_empty() {
        return None;
    }

    let total: u64 = samples.iter().map(|v| *v as u64).sum();
    Some((total / samples.len() as u64) as u32)
}

#[allow(dead_code)]
fn resolve_relay_server_from_candidates(
    candidates: &[RankedRelayCandidate],
) -> Option<(String, SocketAddr)> {
    if candidates.is_empty() {
        return None;
    }

    if candidates.len() == 1 {
        let candidate = &candidates[0];
        return Some((candidate.region.clone(), candidate.addr));
    }

    // Most callers hand this helper an already-ranked list, but we sort again to keep
    // the helper robust for tests and any future direct callers.
    let mut sorted = candidates.to_vec();
    let source = sort_ranked_candidates(&mut sorted);
    sorted.first().map(|candidate| {
        log_resolution_source(source, candidate);
        (candidate.region.clone(), candidate.addr)
    })
}

fn compute_cached_latency_improvement(
    available_servers: &[(String, SocketAddr, Option<u32>)],
    selected_addr: SocketAddr,
    current_addr: SocketAddr,
) -> Option<u32> {
    let selected_latency = available_servers
        .iter()
        .find(|(_, addr, _)| *addr == selected_addr)
        .and_then(|(_, _, lat)| *lat)?;
    let current_latency = available_servers
        .iter()
        .find(|(_, addr, _)| *addr == current_addr)
        .and_then(|(_, _, lat)| *lat);
    match current_latency {
        Some(current_latency) => {
            (current_latency > selected_latency).then_some(current_latency - selected_latency)
        }
        // The current relay has no cached latency: either its probes are
        // timing out (degraded) or it was drained from the server list
        // mid-session. A measurable alternative must not be blocked by the
        // same-region upgrade gate in that state, so report exactly the
        // threshold improvement.
        None => Some(super::auto_routing::SAME_REGION_UPGRADE_THRESHOLD_MS),
    }
}

/// Probe candidate relay servers in parallel using ICMP and return their
/// averaged measurements.
async fn probe_relay_candidates(candidates: &[(String, SocketAddr)]) -> Vec<RelayProbeMeasurement> {
    use crate::vpn::servers::measure_latency_icmp;

    let mut tasks = Vec::new();
    for (region, addr) in candidates {
        let region = region.clone();
        let addr = *addr;
        tasks.push(tokio::spawn(async move {
            let ip = addr.ip().to_string();
            // Use ICMP ping — reliable for all server types.
            // The previous UDP probe ([0u8; 1] to relay port 51821) never got responses
            // because relay servers only respond to valid session ID packets.
            let result = tokio::task::spawn_blocking(move || {
                let mut samples = Vec::with_capacity(AUTO_ROUTING_PING_SAMPLES);
                for _ in 0..AUTO_ROUTING_PING_SAMPLES {
                    if let Some(ms) = measure_latency_icmp(&ip) {
                        samples.push(ms);
                    }
                }
                (average_probe_latency(&samples), samples.len())
            })
            .await;

            match result {
                Ok((latency_ms, successful)) => {
                    match latency_ms {
                        Some(latency_ms) => {
                            log::info!(
                                "Relay probe: {} ({}) = {}ms avg ({} of {} samples)",
                                region,
                                addr,
                                latency_ms,
                                successful,
                                AUTO_ROUTING_PING_SAMPLES
                            );
                        }
                        None => {
                            log::info!(
                                "Relay probe: {} ({}) = timeout (0 of {} samples)",
                                region,
                                addr,
                                AUTO_ROUTING_PING_SAMPLES
                            );
                        }
                    }
                    RelayProbeMeasurement {
                        region,
                        addr,
                        latency_ms,
                    }
                }
                Err(_) => RelayProbeMeasurement {
                    region,
                    addr,
                    latency_ms: None,
                },
            }
        }));
    }

    let mut results = Vec::with_capacity(tasks.len());
    for task in tasks {
        if let Ok(measurement) = task.await {
            results.push(measurement);
        }
    }
    results
}

/// Outcome of authenticating an auto-routing switch target relay.
enum SwitchAuthOutcome {
    /// Relay acknowledged the ticket with status Ok — safe to switch.
    Ok,
    /// Relay (or control plane) answered with a definitive rejection —
    /// retrying with a fresh ticket won't help.
    Rejected(String),
    /// Transport-level failure (token/ticket fetch, send, ack timeout) —
    /// one bounded retry is reasonable.
    Retryable(String),
}

/// Fetch a relay ticket for `server_region` and authenticate this session
/// with `target_addr` without moving any tunnel traffic. The caller may only
/// switch the relay after `SwitchAuthOutcome::Ok` — anything else must leave
/// the session on its current, already-authenticated relay.
async fn authenticate_switch_target(
    auth_manager: &tokio::sync::Mutex<crate::auth::AuthManager>,
    relay: &super::udp_relay::UdpRelay,
    server_region: &str,
    target_addr: SocketAddr,
) -> SwitchAuthOutcome {
    let access_token = {
        let auth = auth_manager.lock().await;
        match auth.get_access_token().await {
            Ok(token) => token,
            Err(e) => {
                return SwitchAuthOutcome::Retryable(format!("access token unavailable: {}", e));
            }
        }
    };

    let auth_client = AuthClient::new();
    let session_id_hex = relay.session_id_hex();
    let ticket = match auth_client
        .get_relay_ticket(&access_token, server_region, &session_id_hex)
        .await
    {
        Ok(ticket) => {
            record_free_tier_quota(&ticket);
            notify_if_relay_crowded(server_region, &ticket);
            ticket
        }
        Err(e) => {
            if relay_ticket_ban_reason(&e).is_some() {
                return SwitchAuthOutcome::Rejected(
                    "relay ticket rejected: account banned".to_string(),
                );
            }
            if relay_ticket_session_dead(&e) {
                return SwitchAuthOutcome::Rejected(
                    "relay ticket rejected: session expired".to_string(),
                );
            }
            if relay_ticket_quota_message(&e).is_some() {
                // Not retryable: the allowance is per account, so no amount of
                // waiting or switching relays gets a ticket back.
                return SwitchAuthOutcome::Rejected(
                    "relay ticket rejected: free tier allowance spent".to_string(),
                );
            }
            if relay_ticket_update_required_message(&e).is_some() {
                // Every relay refuses an out-of-date build, so switching is
                // pointless — Rejected, not Retryable.
                return SwitchAuthOutcome::Rejected(
                    "relay ticket rejected: build below MIN_CLIENT_VERSION".to_string(),
                );
            }
            return SwitchAuthOutcome::Retryable(format!("relay ticket fetch failed: {}", e));
        }
    };

    match relay
        .authenticate_addr_with_ticket(&ticket.token, target_addr)
        .await
    {
        Ok(Some(status)) if status.is_authenticated() => SwitchAuthOutcome::Ok,
        Ok(Some(status)) => SwitchAuthOutcome::Rejected(format!("auth ack '{}'", status.as_str())),
        Ok(None) => SwitchAuthOutcome::Retryable("auth ack timeout".to_string()),
        Err(e) => SwitchAuthOutcome::Retryable(format!("auth hello send failed: {}", e)),
    }
}

/// VPN connection state
#[derive(Debug, Clone, PartialEq, Default)]
pub enum ConnectionState {
    #[default]
    Disconnected,
    FetchingConfig,
    ConfiguringSplitTunnel,
    Connected {
        since: Instant,
        server_region: String,
        server_endpoint: String,
        assigned_ip: String,
        relay_auth_mode: String,
        split_tunnel_active: bool,
        tunneled_processes: Vec<String>,
        /// Relay health status for UI display ("healthy", "stale", "dead").
        /// None means healthy (default). Only set when degraded.
        relay_status: Option<String>,
    },
    Disconnecting,
    Error(String),
}

impl ConnectionState {
    pub fn is_connected(&self) -> bool {
        matches!(self, ConnectionState::Connected { .. })
    }

    pub fn is_connecting(&self) -> bool {
        matches!(
            self,
            ConnectionState::FetchingConfig | ConnectionState::ConfiguringSplitTunnel
        )
    }

    pub fn is_error(&self) -> bool {
        matches!(self, ConnectionState::Error(_))
    }

    pub fn error_message(&self) -> Option<&str> {
        match self {
            ConnectionState::Error(msg) => Some(msg),
            _ => None,
        }
    }

    pub fn status_text(&self) -> &'static str {
        match self {
            ConnectionState::Disconnected => "Disconnected",
            ConnectionState::FetchingConfig => "Resolving relay endpoint...",
            ConnectionState::ConfiguringSplitTunnel => "Configuring split tunnel...",
            ConnectionState::Connected { .. } => "Connected",
            ConnectionState::Disconnecting => "Disconnecting...",
            ConnectionState::Error(_) => "Error",
        }
    }
}

/// VPN Connection manager
pub struct VpnConnection {
    /// State is published through a `tokio::sync::watch` channel so every
    /// transition — including in-place mutations made from background tasks
    /// (relay health, auto-routing, process monitor) — automatically fans out
    /// to all subscribers. The desktop app subscribes once at startup and
    /// bridges these updates to the `VPN_STATE_CHANGED` Tauri event, so the
    /// UI can never render a state the backend has silently left behind.
    state: Arc<watch::Sender<ConnectionState>>,
    split_tunnel: Option<Arc<Mutex<SplitTunnelDriver>>>,
    config: Option<VpnConfig>,
    process_monitor_stop: Arc<AtomicBool>,
    /// ETW process watcher for instant game detection
    etw_watcher: Option<ProcessWatcher>,
    /// Auto-router for automatic relay switching based on game server region
    auto_router: Option<Arc<super::auto_routing::AutoRouter>>,
    /// Background task that performs async auto-routing IP lookups.
    auto_lookup_handle: Option<tokio::task::JoinHandle<()>>,
    /// Periodically renews the authenticated relay lease while connected.
    relay_lease_refresh_handle: Option<tokio::task::JoinHandle<()>>,
    /// Set by the lease refresh task when a terminal auth or quota failure
    /// requires the owning desktop task to tear down the session.
    terminal_cleanup_requested: Arc<AtomicBool>,
    /// Auth manager used by the auto-routing task to fetch relay tickets for
    /// mid-session relay switches. Without it, auto-routing will not switch
    /// relays (an unauthenticated switch would be dropped by auth-required
    /// relays or silently downgrade the session to legacy mode).
    auth_manager: Option<Arc<tokio::sync::Mutex<crate::auth::AuthManager>>>,
    /// Per-process game performance tuning manager (Windows-only behavior).
    process_performance_manager: Option<Arc<Mutex<GameProcessPerformanceManager>>>,
    /// Tracks whether this connection wrote the temporary Roblox bootstrap hosts repair.
    bootstrap_dns_repair_applied: bool,
    /// Scoped GoodbyeDPI helper for Bypass country bans Roblox traffic.
    goodbye_dpi_guard: Option<crate::roblox_proxy::goodbyedpi::GoodbyeDpiGuard>,
    country_ban_bypass_failure: Option<String>,
}

impl VpnConnection {
    pub fn new() -> Self {
        let (state_tx, _) = watch::channel(ConnectionState::Disconnected);
        Self {
            state: Arc::new(state_tx),
            split_tunnel: None,
            config: None,
            process_monitor_stop: Arc::new(AtomicBool::new(false)),
            etw_watcher: None,
            auto_router: None,
            auto_lookup_handle: None,
            relay_lease_refresh_handle: None,
            terminal_cleanup_requested: Arc::new(AtomicBool::new(false)),
            auth_manager: None,
            process_performance_manager: None,
            bootstrap_dns_repair_applied: false,
            goodbye_dpi_guard: None,
            country_ban_bypass_failure: None,
        }
    }

    pub async fn state(&self) -> ConnectionState {
        self.state.borrow().clone()
    }

    /// Provide the auth manager used for mid-session relay-ticket fetches
    /// (auto-routing switches). Call once before `connect`; without it,
    /// auto-routing detects regions but never switches relays.
    pub fn set_auth_manager(
        &mut self,
        auth_manager: Arc<tokio::sync::Mutex<crate::auth::AuthManager>>,
    ) {
        self.auth_manager = Some(auth_manager);
    }

    /// Subscribe to state transitions. Each returned `Receiver` observes every
    /// change published through `set_state` or the in-place mutations in the
    /// background monitor and `switch_server`.
    pub fn state_handle(&self) -> watch::Receiver<ConnectionState> {
        self.state.subscribe()
    }

    /// Clone the inner split-tunnel driver handle so that command callers
    /// can hit `try_lock` on the driver directly without taking the (much
    /// hotter) `VpnConnection` mutex. Returns `None` until the driver has
    /// been wired up by `connect()`.
    pub fn split_tunnel_handle(&self) -> Option<Arc<Mutex<SplitTunnelDriver>>> {
        self.split_tunnel.as_ref().map(Arc::clone)
    }

    /// Get throughput stats for GUI display
    ///
    /// Returns the ThroughputStats handle if split tunnel is active and using parallel mode.
    /// Uses try_lock() to avoid blocking the GUI thread.
    pub fn get_throughput_stats(&self) -> Option<ThroughputStats> {
        self.split_tunnel.as_ref().and_then(|st| {
            st.try_lock()
                .ok()
                .and_then(|driver| driver.get_throughput_stats())
        })
    }

    /// Get relay RTT/jitter telemetry snapshot for UI display.
    /// Uses try_lock() to avoid blocking the GUI thread.
    pub fn get_relay_ping_snapshot(&self) -> Option<super::RelayPingSnapshot> {
        self.split_tunnel.as_ref().and_then(|st| {
            st.try_lock().ok().and_then(|driver| {
                driver
                    .get_relay_context()
                    .map(|relay| relay.ping_snapshot())
            })
        })
    }

    /// Get split tunnel diagnostic info for UI display.
    /// Uses try_lock() to avoid blocking the GUI thread.
    pub fn get_split_tunnel_diagnostics(&self) -> Option<super::SplitTunnelDiagnostics> {
        self.split_tunnel.as_ref().and_then(|st| {
            st.try_lock()
                .ok()
                .and_then(|driver| driver.get_diagnostics())
        })
    }

    /// Get the current config ID (for latency updates)
    pub fn get_config_id(&self) -> Option<String> {
        self.config.as_ref().map(|c| c.id.clone())
    }

    /// Get detected game server IPs for notifications (Bloxstrap-style)
    ///
    /// Returns a list of Roblox game server IPs that have been tunneled.
    /// Uses try_lock() to avoid blocking the GUI thread.
    pub fn get_detected_game_servers(&self) -> Vec<std::net::Ipv4Addr> {
        self.split_tunnel
            .as_ref()
            .and_then(|st| {
                st.try_lock()
                    .ok()
                    .map(|driver| driver.get_detected_game_servers())
            })
            .unwrap_or_default()
    }

    /// Clear detected game servers (call on disconnect)
    pub fn clear_detected_game_servers(&self) {
        if let Some(st) = self.split_tunnel.as_ref()
            && let Ok(driver) = st.try_lock()
        {
            driver.clear_detected_game_servers();
        }
    }

    /// Get the auto-router for GUI display or external access
    pub fn auto_router(&self) -> Option<&Arc<super::auto_routing::AutoRouter>> {
        self.auto_router.as_ref()
    }

    pub fn take_country_ban_bypass_failure(&mut self) -> Option<String> {
        self.country_ban_bypass_failure.take()
    }

    async fn set_state(&self, state: ConnectionState) {
        log::info!("Connection state: {:?}", state);
        // `send_replace` always notifies subscribers, even if the new value
        // equals the old. That's the behavior we want — the UI re-reads the
        // full state on every event, and suppressing a notification here could
        // drop an Error-after-Error or a Disconnected-during-shutdown signal.
        let _ = self.state.send_replace(state);
    }

    /// Connect to VPN server using UDP relay (V3 mode)
    ///
    /// Sets up ndisapi packet interception with UDP relay forwarding.
    /// No Wintun adapter, no WireGuard encryption — lowest latency.
    ///
    /// # Arguments
    /// * `access_token` - Bearer token used to fetch relay auth ticket
    /// * `region` - Server region to connect to
    /// * `tunnel_apps` - Apps that SHOULD use VPN (games). Everything else bypasses.
    #[allow(clippy::too_many_arguments)]
    pub async fn connect(
        &mut self,
        access_token: &str,
        region: &str,
        tunnel_apps: Vec<String>,
        custom_relay_server: Option<String>,
        auto_routing_enabled: bool,
        available_servers: Vec<(String, std::net::SocketAddr, Option<u32>)>,
        whitelisted_regions: Vec<String>,
        forced_servers: std::collections::HashMap<String, String>,
        binding_preference: Option<AdapterBindingPreference>,
        process_performance_settings: GameProcessPerformanceSettings,
        enable_api_tunneling: bool,
        enable_country_ban: bool,
    ) -> VpnResult<()> {
        // Full bypass (whole platform blocked) relays Roblox TCP and gameplay
        // UDP alike, because nothing can be trusted to the direct path.
        let routing_flags = resolve_tunnel_routing_flags(enable_api_tunneling, enable_country_ban);
        let enable_api_tunneling = routing_flags.api_tunneling;
        let enable_udp_tunneling = routing_flags.udp_tunneling;

        // While bypassing a country ban, also tunnel third-party Roblox
        // bootstrappers (Bloxstrap/Froststrap/...). Their launch-time
        // clientsettings + update fetches otherwise hit the block directly and
        // time out ("clientsettings.roblox.com:443"). Users who aren't blocked
        // never enable Bypass, so their strappers stay untunneled.
        let mut tunnel_apps = tunnel_apps;
        if enable_country_ban {
            for strapper in crate::process_names::STRAPPER_PROCESS_NAMES {
                if !tunnel_apps
                    .iter()
                    .any(|app| app.eq_ignore_ascii_case(strapper))
                {
                    tunnel_apps.push((*strapper).to_string());
                }
            }
        } else {
            // Roblox Studio is a developer tool, not a game client — it never
            // joins the game servers Route Assist optimizes for, so relaying it
            // adds nothing and breaks Team Create (its place-sync TCP exceeds the
            // relay's forward buffer → "connectToTeamCreateSession: no response").
            // Keep Studio direct unless a country block actually requires relaying
            // it to reach Roblox at all (the country-ban branch above keeps it).
            tunnel_apps.retain(|app| !crate::process_names::is_roblox_studio_process_name(app));
        }

        let prior_was_error = {
            let state = self.state.borrow();
            if state.is_connected() {
                log::info!(
                    "Connect requested while already connected; treating as idempotent success"
                );
                return Ok(());
            }
            if state.is_connecting() {
                return Err(VpnError::Connection("Connection in progress".to_string()));
            }
            matches!(*state, ConnectionState::Error(_))
        };

        // A new connection attempt owns a fresh cleanup lifecycle. Any
        // terminal request left by the previous lease task is reconciled by
        // the Error cleanup below and must not tear down the new session.
        self.terminal_cleanup_requested
            .store(false, Ordering::SeqCst);

        // If the prior state was Error, the monitor task's recovery flow
        // already closed the driver + ran best-effort Arc-shared cleanup, but
        // the `&mut self`-only resources (`etw_watcher`, `config`,
        // `split_tunnel = None`) can still be stale. Reconcile them here so
        // reconnects from Error always start from a clean slate.
        if prior_was_error {
            self.cleanup().await;
        }

        log::info!("Starting VPN connection to region: {}", region);
        log::info!("Apps to tunnel: {:?}", tunnel_apps);
        // Support breadcrumb: internet-cafe diskless PCs behave differently
        // (RAM cleaning is disabled there; system disk rides the LAN).
        if crate::diskless::system_is_diskless() {
            log::info!("Network-booted (diskless) PC detected for this session");
        }
        self.process_performance_manager = None;
        self.goodbye_dpi_guard = None;
        self.country_ban_bypass_failure = None;

        log::info!("========================================");
        log::info!("V3 MODE: Lightweight UDP Relay");
        log::info!("========================================");
        log::info!("  - No Wintun adapter");
        log::info!("  - No WireGuard encryption");
        log::info!("  - No route configuration");
        log::info!("  - Direct UDP relay to game servers");
        log::info!("========================================");

        // Step 1: Resolve initial relay endpoint from available servers
        self.set_state(ConnectionState::FetchingConfig).await;
        let forced_for_region = forced_servers.get(region).cloned();
        let relay_candidates = ordered_relay_candidates_for_region(
            region,
            &available_servers,
            forced_for_region.as_deref(),
        )
        .await;
        let (resolved_server_region, selected_relay_addr) = match relay_candidates
            .first()
            .map(|(server_region, relay_addr, _)| (server_region.clone(), *relay_addr))
        {
            Some((server_region, relay_addr)) => (server_region, relay_addr),
            None => {
                log_sampled_connect_event(
                    &REGION_UNAVAILABLE_EVENTS,
                    CONNECT_FAIL_REGION_UNAVAILABLE,
                    format!("Selected region '{}' is unavailable in server list", region),
                );
                let error = VpnError::ConfigFetch(format!(
                    "Selected region '{}' is unavailable in server list",
                    region
                ));
                self.set_state(ConnectionState::Error(super::user_friendly_error(&error)))
                    .await;
                return Err(error);
            }
        };

        if resolved_server_region != region {
            log::info!(
                "Resolved selected region '{}' to relay server '{}'",
                region,
                resolved_server_region
            );
        }

        let config = VpnConfig {
            // In V3 we only need region + endpoint for relay bootstrap.
            // Use the resolved server id (e.g. "us-east-nj") so UI can show the exact server.
            region: resolved_server_region.clone(),
            endpoint: selected_relay_addr.to_string(),
            ..Default::default()
        };

        log::info!(
            "V3: Server endpoint: {} (resolved via server '{}')",
            config.endpoint,
            resolved_server_region
        );
        // V3 no longer creates/stores vpn_configs records via generate-config.
        self.config = None;

        // Initialize WFP block filter engine (for instant process blocking)
        if let Err(e) = super::wfp_block::init() {
            log::warn!(
                "WFP block filter init failed (will use speculative tunneling): {}",
                e
            );
        }

        // Step 2: Skip Wintun - go directly to split tunnel
        // V3 doesn't need a virtual adapter
        self.set_state(ConnectionState::ConfiguringSplitTunnel)
            .await;

        // Routing diagnostics for every tunnel session.
        //
        // Which destinations went direct, and why, is invisible in the existing
        // logs: they only fire on the relay path. That is where the
        // website-not-loading and missing-image reports die, and it is also the
        // only way to see which endpoints Roblox voice uses when the in-game
        // mic disappears — which happens with no bypass enabled at all, so
        // gating this on the bypass modes hid exactly the session we needed.
        {
            use crate::vpn::bypass_diag::{BypassMode, begin_session};
            let mode = if enable_country_ban {
                BypassMode::FullCountryBan
            } else if enable_api_tunneling {
                BypassMode::RouteAssist
            } else {
                BypassMode::Plain
            };
            begin_session(
                mode,
                crate::roblox_proxy::hosts::active_bootstrap_ip_count(),
            );
        }

        if enable_api_tunneling && !tunnel_apps.is_empty() {
            match crate::roblox_proxy::hosts::apply_bootstrap_overrides(enable_country_ban).await {
                Ok(()) => {
                    self.bootstrap_dns_repair_applied = true;
                    log::info!("V3: Applied Roblox bootstrap DNS repair for API tunneling");
                }
                Err(e) => {
                    log::warn!(
                        "V3: Roblox bootstrap DNS repair skipped; API tunneling will continue without hosts repair: {}",
                        e
                    );
                    // Under a full country block this is load-bearing: without
                    // pins, system DNS (often poisoned by the censor) decides
                    // which IPs Roblox connects to, and even relayed flows then
                    // go to bogus endpoints (Studio/installer SslConnectFail).
                    // Surface it so the UI/support can see why bypass degraded.
                    if enable_country_ban {
                        self.country_ban_bypass_failure = Some(format!(
                            "Roblox DNS repair failed (your network may be blocking secure DNS): {e}"
                        ));
                    }
                }
            }
        }

        // Never inherit a previous session's answer.
        crate::roblox_proxy::hosts::set_dpi_evasion_confirmed(false);

        if enable_country_ban {
            // GoodbyeDPI decides how much the relay has to carry.
            //
            // When it confirms a working mode, Roblox web and asset traffic goes
            // direct and the relay carries gameplay alone. Assets are the bulk of
            // the bytes, and funnelling a game's whole asset set through one
            // relay hop is what made pages take minutes to load.
            //
            // When it cannot confirm (common under aggressive DPI like Egypt's,
            // which is exactly why we relay at all) the relay carries everything,
            // which is the behaviour that shipped before this split. Failing to
            // confirm is therefore never a user-facing error: that signal stays
            // reserved for failures that actually break the relay bypass, such as
            // the DNS repair above.
            match crate::roblox_proxy::goodbyedpi::start_for_roblox().await {
                Ok(Some(guard)) => {
                    self.goodbye_dpi_guard = Some(guard);
                    crate::roblox_proxy::hosts::set_dpi_evasion_confirmed(true);
                    log::info!(
                        "V3: GoodbyeDPI confirmed a working mode; Roblox web and assets go DIRECT, relay carries gameplay only"
                    );
                }
                Ok(None) => {
                    log::info!(
                        "V3: GoodbyeDPI helper unavailable; relay carries Roblox web, assets and gameplay"
                    );
                }
                Err(e) => {
                    log::warn!(
                        "V3: GoodbyeDPI could not confirm a working mode; relay carries Roblox web, assets and gameplay: {}",
                        e
                    );
                }
            }
        }

        let mut active_server_region = config.region.clone();
        let mut active_server_endpoint = config.endpoint.clone();

        let (tunneled_processes, split_tunnel_active, relay_auth_mode) = if !tunnel_apps.is_empty()
        {
            match self
                .setup_split_tunnel(
                    access_token,
                    &config,
                    tunnel_apps.clone(),
                    custom_relay_server,
                    auto_routing_enabled,
                    available_servers,
                    relay_candidates,
                    whitelisted_regions,
                    forced_servers,
                    binding_preference.clone(),
                    process_performance_settings,
                    enable_api_tunneling,
                    enable_udp_tunneling,
                )
                .await
            {
                Ok((processes, auth_mode, active_region, active_addr)) => {
                    log::info!("V3 split tunnel setup succeeded");
                    active_server_region = active_region;
                    active_server_endpoint = active_addr.to_string();
                    (processes, true, auth_mode)
                }
                Err(e) => {
                    log::error!("V3 split tunnel setup FAILED: {}", e);
                    self.cleanup().await;
                    self.set_state(ConnectionState::Error(super::user_friendly_error(&e)))
                        .await;
                    return Err(e);
                }
            }
        } else {
            log::warn!("No tunnel apps specified");
            (Vec::new(), false, "legacy_fallback".to_string())
        };

        // Full bypass + a real DNS block (Egypt): local DoH is dead and system DNS
        // is poisoned, so the pins above may be missing/wrong and the player would
        // reach poisoned addresses the relay can't forward to ("problem reaching
        // our servers"). Now that the relay tunnel is up, resolve Roblox's real
        // IPs *through* the relay (which sits outside the censorship) and merge
        // them into the pins. Best-effort: an older relay just returns nothing.
        if enable_country_ban
            && let Some(relay) = self
                .split_tunnel
                .as_ref()
                .and_then(|st| st.try_lock().ok().and_then(|d| d.get_relay_context()))
        {
            let resolved = relay
                .resolve_roblox_hosts(
                    crate::roblox_proxy::hosts::ROBLOX_BOOTSTRAP_DOMAINS,
                    std::time::Duration::from_secs(3),
                )
                .await;
            if resolved.is_empty() {
                log::info!(
                    "Relay-resolved DNS returned nothing (relay without resolve support, or hosts unresolved)"
                );
            } else {
                let count = resolved.len();
                match crate::roblox_proxy::hosts::apply_relay_resolved_overrides(resolved).await {
                    Ok(()) => log::info!(
                        "Applied relay-resolved pins for {count} Roblox host(s) (DNS via relay)"
                    ),
                    Err(e) => {
                        log::warn!("Relay-resolved Roblox pins could not be applied: {e}")
                    }
                }
            }
        }

        // Step 3: Skip routes - V3 doesn't need them
        // Traffic is intercepted at NDIS layer and forwarded via relay

        // Step 4: Mark as connected
        self.set_state(ConnectionState::Connected {
            since: Instant::now(),
            server_region: active_server_region,
            server_endpoint: active_server_endpoint,
            assigned_ip: "V3-Relay".to_string(), // No VPN IP in V3 mode
            relay_auth_mode,
            split_tunnel_active,
            tunneled_processes,
            relay_status: None,
        })
        .await;

        log::info!("V3 connected successfully (no encryption, lowest latency)");
        Ok(())
    }

    /// Split tunnel setup - ndisapi + UDP relay
    ///
    /// Simplified flow:
    /// 1. Check driver availability
    /// 2. Open/initialize driver
    /// 3. Create UDP relay to server
    /// 4. Configure with relay context (no WireGuard)
    /// 5. Start process monitor
    #[allow(clippy::too_many_arguments)]
    async fn setup_split_tunnel(
        &mut self,
        access_token: &str,
        config: &VpnConfig,
        tunnel_apps: Vec<String>,
        custom_relay_server: Option<String>,
        auto_routing_enabled: bool,
        available_servers: Vec<(String, std::net::SocketAddr, Option<u32>)>,
        relay_candidates: Vec<(String, std::net::SocketAddr, Option<u32>)>,
        whitelisted_regions: Vec<String>,
        forced_servers: std::collections::HashMap<String, String>,
        binding_preference: Option<AdapterBindingPreference>,
        process_performance_settings: GameProcessPerformanceSettings,
        enable_api_tunneling: bool,
        enable_udp_tunneling: bool,
    ) -> VpnResult<(Vec<String>, String, String, SocketAddr)> {
        log::info!("Setting up V3 split tunnel (no Wintun)...");

        // Check if driver is available
        if !SplitTunnelDriver::check_driver_available() {
            return Err(VpnError::SplitTunnelNotAvailable);
        }

        // Create and configure driver
        let mut driver = SplitTunnelDriver::new();

        // Open driver
        driver.open().map_err(|e| {
            VpnError::SplitTunnelSetupFailed(format!("Failed to open driver: {}", e))
        })?;
        log::info!("V3: Split tunnel driver opened");

        // Initialize driver
        driver.initialize().map_err(|e| {
            let _ = driver.close();
            VpnError::SplitTunnelSetupFailed(format!("Failed to initialize driver: {}", e))
        })?;
        log::info!("V3: Split tunnel driver initialized");

        // Create UDP relay to relay server.
        // Use custom relay if configured (experimental feature), otherwise bootstrap from
        // the ordered candidate list resolved during connect().
        let mut selected_relay_region = config.region.clone();
        let mut relay_addr: SocketAddr = if let Some(ref custom) = custom_relay_server {
            // Custom relay configured - resolve with DNS support
            log::info!("V3: Using CUSTOM relay server: {}", custom);

            // Parse host:port and resolve via Cloudflare DNS (1.1.1.1)
            let (host, port) = if let Some((h, p)) = custom.rsplit_once(':') {
                let port: u16 = p.parse().map_err(|e| {
                    let _ = driver.close();
                    VpnError::SplitTunnelSetupFailed(format!("Invalid port in '{}': {}", custom, e))
                })?;
                (h, port)
            } else {
                let _ = driver.close();
                return Err(VpnError::SplitTunnelSetupFailed(format!(
                    "Custom relay '{}' must include a port (e.g. host:51821)",
                    custom
                )));
            };

            // Try parsing as IP first to skip DNS for raw IPs
            if let Ok(ip) = host.parse::<std::net::IpAddr>() {
                let addr = SocketAddr::new(ip, port);
                log::info!("V3: Custom relay is IP address: {}", addr);
                addr
            } else {
                // Resolve hostname via system DNS
                match tokio::net::lookup_host(format!("{}:{}", host, port)).await {
                    Ok(mut addrs) => {
                        if let Some(addr) = addrs.next() {
                            log::info!("V3: Resolved custom relay to {}", addr);
                            addr
                        } else {
                            let _ = driver.close();
                            return Err(VpnError::SplitTunnelSetupFailed(format!(
                                "DNS resolution returned no addresses for '{}'",
                                custom
                            )));
                        }
                    }
                    Err(e) => {
                        let _ = driver.close();
                        return Err(VpnError::SplitTunnelSetupFailed(format!(
                            "Failed to resolve custom relay '{}': {}",
                            custom, e
                        )));
                    }
                }
            }
        } else if let Some((server_region, addr, _)) = relay_candidates.first() {
            selected_relay_region = server_region.clone();
            *addr
        } else {
            // No custom relay AND no relay candidate from the server list.
            // This should not happen on a healthy connect — `/api/vpn/servers`
            // carries a `relay_port` per relay — so we fall back to the
            // resolved server endpoint with `FALLBACK_RELAY_PORT` and log it
            // loudly rather than silently guessing a port.
            log::warn!(
                "V3: no relay candidate resolved; falling back to {} with hardcoded port {}",
                config.endpoint,
                FALLBACK_RELAY_PORT
            );
            if let Ok(addr) = config.endpoint.parse::<SocketAddr>() {
                SocketAddr::new(addr.ip(), FALLBACK_RELAY_PORT)
            } else if let Ok(ip) = config.endpoint.parse::<std::net::IpAddr>() {
                SocketAddr::new(ip, FALLBACK_RELAY_PORT)
            } else {
                let vpn_ip = config
                    .endpoint
                    .split(':')
                    .next()
                    .unwrap_or(&config.endpoint);
                format!("{}:{}", vpn_ip, FALLBACK_RELAY_PORT)
                    .parse()
                    .map_err(|e| {
                        VpnError::SplitTunnelSetupFailed(format!(
                            "Invalid VPN server IP for relay: {}",
                            e
                        ))
                    })?
            }
        };

        log::info!("V3: Creating UDP relay to {}", relay_addr);

        let relay_path_context = super::udp_relay::RelayPathContext {
            point_to_point_default_route: is_point_to_point_default_route_context(),
        };
        if relay_path_context.point_to_point_default_route {
            log::info!("V3: PPP/point-to-point default route detected; enabling relay MTU clamp");
        }

        let relay =
            match super::udp_relay::UdpRelay::new_with_path_context(relay_addr, relay_path_context)
            {
                Ok(r) => std::sync::Arc::new(r),
                Err(e) => {
                    let _ = driver.close();
                    return Err(VpnError::SplitTunnelSetupFailed(format!(
                        "Failed to create V3 relay: {}",
                        e
                    )));
                }
            };

        let mut relay_auth_mode = if custom_relay_server.is_some() {
            "custom_legacy".to_string()
        } else {
            "legacy_fallback".to_string()
        };
        let mut queue_full_mode = RelayQueueFullMode::Bypass;

        if custom_relay_server.is_some() {
            log::warn!("V3: Custom relay enabled, skipping authenticated relay ticket bootstrap");
        } else {
            let auth_client = AuthClient::new();
            let session_id_hex = relay.session_id_hex();
            let mut candidates = relay_candidates.clone();
            if candidates.is_empty() {
                candidates.push((config.region.clone(), relay_addr, None));
            }

            let mut authenticated = false;
            let mut saw_timeout = false;
            let mut attempt_results: Vec<RelayCandidateAttempt> = Vec::new();

            for (idx, (candidate_region, candidate_addr, _)) in candidates.iter().enumerate() {
                if relay.relay_addr() != *candidate_addr {
                    relay.switch_relay(*candidate_addr);
                }

                let ticket = match auth_client
                    .get_relay_ticket(access_token, candidate_region, &session_id_hex)
                    .await
                {
                    Ok(ticket) => {
                        record_free_tier_quota(&ticket);
                        notify_if_relay_crowded(candidate_region, &ticket);
                        ticket
                    }
                    Err(e) => {
                        if let Some(reason) = relay_ticket_ban_reason(&e) {
                            log::warn!(
                                "V3: Relay ticket rejected because the current account is banned"
                            );
                            let _ = driver.close();
                            return Err(VpnError::UserBanned(reason));
                        }
                        if relay_ticket_session_dead(&e) {
                            log::warn!("V3: Relay ticket rejected - session expired");
                            let _ = driver.close();
                            return Err(VpnError::SessionExpired);
                        }
                        if let Some(message) = relay_ticket_quota_message(&e) {
                            log::warn!("V3: Relay ticket rejected - free tier allowance spent");
                            let _ = driver.close();
                            return Err(VpnError::FreeTierLimitReached(message));
                        }
                        if let Some(message) = relay_ticket_update_required_message(&e) {
                            log::warn!(
                                "V3: Relay ticket rejected - build below MIN_CLIENT_VERSION"
                            );
                            let _ = driver.close();
                            return Err(VpnError::UpdateRequired(message));
                        }
                        log::warn!(
                            "V3: Relay ticket unavailable for '{}' ({})",
                            candidate_region,
                            e
                        );
                        attempt_results.push(RelayCandidateAttempt {
                            region: candidate_region.clone(),
                            addr: *candidate_addr,
                            authenticated: false,
                            policy_known: false,
                            auth_required: false,
                            preflight_mode: RelayPreflightMode::Legacy,
                            queue_full_mode: RelayQueueFullMode::Bypass,
                        });
                        continue;
                    }
                };

                let candidate_preflight_mode = ticket.preflight_mode();
                let candidate_queue_full_mode = ticket.queue_full_mode();
                log::info!(
                    "V3: Candidate {} policy preflight={:?}, queue_full={:?}",
                    candidate_region,
                    candidate_preflight_mode,
                    candidate_queue_full_mode
                );

                match relay.authenticate_with_ticket(&ticket.token) {
                    Ok(Some(status)) if status.is_authenticated() => {
                        relay_auth_mode = "authenticated".to_string();
                        selected_relay_region = candidate_region.clone();
                        relay_addr = *candidate_addr;
                        queue_full_mode = candidate_queue_full_mode;
                        attempt_results.push(RelayCandidateAttempt {
                            region: candidate_region.clone(),
                            addr: *candidate_addr,
                            authenticated: true,
                            policy_known: true,
                            auth_required: ticket.auth_required,
                            preflight_mode: candidate_preflight_mode,
                            queue_full_mode: candidate_queue_full_mode,
                        });
                        authenticated = true;
                        if idx > 0 {
                            log::info!(
                                "V3: Relay auth failover selected '{}' after {} attempt(s)",
                                candidate_region,
                                idx + 1
                            );
                        }
                        log::info!(
                            "V3: Relay authenticated (session {}, key_id={}, region={})",
                            session_id_hex,
                            ticket.key_id,
                            candidate_region
                        );
                        break;
                    }
                    Ok(Some(status)) => {
                        log::warn!(
                            "V3: Relay auth ack '{}' for candidate '{}' (session {})",
                            status.as_str(),
                            candidate_region,
                            session_id_hex
                        );
                        attempt_results.push(RelayCandidateAttempt {
                            region: candidate_region.clone(),
                            addr: *candidate_addr,
                            authenticated: false,
                            policy_known: true,
                            auth_required: ticket.auth_required,
                            preflight_mode: candidate_preflight_mode,
                            queue_full_mode: candidate_queue_full_mode,
                        });
                    }
                    Ok(None) => {
                        saw_timeout = true;
                        log_sampled_connect_event(
                            &HANDSHAKE_TIMEOUT_EVENTS,
                            CONNECT_FAIL_HANDSHAKE_TIMEOUT,
                            format!(
                                "Relay auth timed out for candidate '{}' (session {})",
                                candidate_region, session_id_hex
                            ),
                        );
                        attempt_results.push(RelayCandidateAttempt {
                            region: candidate_region.clone(),
                            addr: *candidate_addr,
                            authenticated: false,
                            policy_known: true,
                            auth_required: ticket.auth_required,
                            preflight_mode: candidate_preflight_mode,
                            queue_full_mode: candidate_queue_full_mode,
                        });
                    }
                    Err(e) => {
                        log::warn!(
                            "V3: Relay auth handshake failed for candidate '{}' (session {}, {})",
                            candidate_region,
                            session_id_hex,
                            e
                        );
                        attempt_results.push(RelayCandidateAttempt {
                            region: candidate_region.clone(),
                            addr: *candidate_addr,
                            authenticated: false,
                            policy_known: true,
                            auth_required: ticket.auth_required,
                            preflight_mode: candidate_preflight_mode,
                            queue_full_mode: candidate_queue_full_mode,
                        });
                    }
                }
            }

            if !authenticated {
                log_sampled_connect_event(
                    &CANDIDATE_EXHAUSTED_EVENTS,
                    CONNECT_FAIL_CANDIDATE_EXHAUSTED,
                    format!(
                        "All {} relay candidate(s) failed for '{}' (session {})",
                        candidates.len(),
                        config.region,
                        session_id_hex
                    ),
                );
                if saw_timeout {
                    log::warn!(
                        "V3: Falling back to legacy relay mode after authentication timeouts"
                    );
                } else {
                    log::warn!("V3: Falling back to legacy relay mode after candidate exhaustion");
                }

                match select_candidate_after_preflight(&attempt_results) {
                    Ok((fallback_region, fallback_addr, fallback_queue_mode)) => {
                        let policy_known = attempt_results
                            .iter()
                            .find(|attempt| {
                                attempt.region == fallback_region && attempt.addr == fallback_addr
                            })
                            .is_none_or(|attempt| attempt.policy_known);
                        if !policy_known {
                            relay_auth_mode = "policy_unavailable_legacy_fallback".to_string();
                            log_sampled_connect_event(
                                &POLICY_UNAVAILABLE_EVENTS,
                                CONNECT_FAIL_POLICY_UNAVAILABLE,
                                format!(
                                    "Relay policy unavailable for '{}'; attempting marked legacy fallback on '{}' (session {})",
                                    config.region, fallback_region, session_id_hex
                                ),
                            );
                        }
                        selected_relay_region = fallback_region;
                        relay_addr = fallback_addr;
                        queue_full_mode = fallback_queue_mode;
                        relay.switch_relay(fallback_addr);
                    }
                    Err(CONNECT_FAIL_PREFLIGHT_ENFORCED) => {
                        log_sampled_connect_event(
                            &PREFLIGHT_ENFORCED_EVENTS,
                            CONNECT_FAIL_PREFLIGHT_ENFORCED,
                            format!(
                                "Strict preflight rejected legacy fallback for '{}' (session {})",
                                config.region, session_id_hex
                            ),
                        );
                        let _ = driver.close();
                        return Err(VpnError::Connection(
                            "Relay preflight enforcement blocked connection (no healthy authenticated relay candidate)"
                                .to_string(),
                        ));
                    }
                    Err(CONNECT_FAIL_AUTH_REQUIRED) => {
                        log_sampled_connect_event(
                            &AUTH_REQUIRED_EVENTS,
                            CONNECT_FAIL_AUTH_REQUIRED,
                            format!(
                                "Required relay auth rejected legacy fallback for '{}' (session {})",
                                config.region, session_id_hex
                            ),
                        );
                        let _ = driver.close();
                        return Err(VpnError::Connection(
                            "Relay authentication required but no relay candidate authenticated"
                                .to_string(),
                        ));
                    }
                    Err(CONNECT_FAIL_POLICY_UNAVAILABLE) => {
                        log_sampled_connect_event(
                            &POLICY_UNAVAILABLE_EVENTS,
                            CONNECT_FAIL_POLICY_UNAVAILABLE,
                            format!(
                                "Relay policy unavailable for '{}' (session {})",
                                config.region, session_id_hex
                            ),
                        );
                        let _ = driver.close();
                        return Err(VpnError::Connection(
                            "Relay policy unavailable; refusing unauthenticated legacy fallback"
                                .to_string(),
                        ));
                    }
                    Err(code) => {
                        log_sampled_connect_event(
                            &CANDIDATE_EXHAUSTED_EVENTS,
                            code,
                            format!(
                                "Relay fallback candidate selection failed for '{}' (session {})",
                                config.region, session_id_hex
                            ),
                        );
                    }
                }
            }
        }

        let queue_overflow_mode = match queue_full_mode {
            RelayQueueFullMode::Bypass => QueueOverflowMode::Bypass,
            RelayQueueFullMode::Drop => QueueOverflowMode::Drop,
        };
        driver.set_queue_overflow_mode(queue_overflow_mode);
        log::info!(
            "V3: Queue overflow mode set from relay policy: {:?}",
            queue_overflow_mode
        );

        let relay_for_lookup = Arc::clone(&relay);
        let relay_for_health = Arc::clone(&relay);
        let relay_for_lease_refresh = Arc::clone(&relay);
        driver.set_relay_context(relay);
        log::info!("V3: UDP relay context set (auth mode: {})", relay_auth_mode);
        relay_for_lookup.set_ping_enabled(true);
        log::debug!("V3: Relay ping telemetry enabled (20Hz when active)");

        // Set up auto-routing
        let auto_router = Arc::new(super::auto_routing::AutoRouter::new(
            auto_routing_enabled,
            &selected_relay_region,
        ));
        auto_router.set_current_relay(relay_addr, &selected_relay_region);
        auto_router.set_available_servers(available_servers);
        if !whitelisted_regions.is_empty() {
            auto_router.set_whitelisted_regions(whitelisted_regions);
        }
        if !forced_servers.is_empty() {
            auto_router.set_forced_servers(forced_servers);
        }

        // Spawn background task for async region lookups. Spawned for every
        // non-custom-relay session (not just when auto-routing is enabled at
        // connect) so toggling auto-routing on mid-session works; the router's
        // `enabled` flag gates all evaluation. Custom-relay sessions never get
        // the task: automatic relay replacement is disabled for them.
        if custom_relay_server.is_none() {
            let (lookup_tx, mut lookup_rx) =
                tokio::sync::mpsc::unbounded_channel::<(std::net::Ipv4Addr, u64, u64)>();
            auto_router.set_lookup_channel(lookup_tx);

            let router_for_lookup = Arc::clone(&auto_router);
            let state_for_lookup = Arc::clone(&self.state);
            let auth_manager_for_lookup = self.auth_manager.clone();
            let lookup_handle = tokio::spawn(async move {
                use crate::geolocation::GameServerRegionLookup;

                while let Some((ip, generation, session_epoch)) = lookup_rx.recv().await {
                    // Auto Route may have been disabled (settings save) after
                    // this lookup was queued — release the held packets on the
                    // current relay instead of resolving.
                    if !router_for_lookup.is_enabled() {
                        log::info!(
                            "Auto-routing: Dropping queued lookup for {} — auto-routing was disabled",
                            ip
                        );
                        router_for_lookup.clear_pending_lookup(ip);
                        continue;
                    }

                    // Resolve the region, with one bounded retry for
                    // transport-level failures only. A definitive "resolver
                    // answered but no region" is diagnostic, not retryable.
                    let mut outcome = crate::geolocation::lookup_game_server_region(ip).await;
                    if outcome == GameServerRegionLookup::Failed
                        && router_for_lookup.is_current_lookup_session(session_epoch)
                    {
                        tokio::time::sleep(Duration::from_millis(250)).await;
                        outcome = crate::geolocation::lookup_game_server_region(ip).await;
                    }

                    let (region, location) = match outcome {
                        GameServerRegionLookup::Resolved(region, location) => (region, location),
                        GameServerRegionLookup::NoRegion => {
                            log::info!(
                                "Auto-routing: Resolver returned no structured region for {} — releasing packets on current relay",
                                ip
                            );
                            router_for_lookup.clear_pending_lookup(ip);
                            continue;
                        }
                        GameServerRegionLookup::Failed => {
                            log::warn!(
                                "Auto-routing: Resolver lookup failed for {} (after retry) — releasing packets on current relay",
                                ip
                            );
                            router_for_lookup.clear_pending_lookup(ip);
                            continue;
                        }
                    };

                    // Re-check after the resolver await: a disable mid-lookup
                    // must not pin the game server or burn a relay ticket on
                    // the auth handshake below.
                    if !router_for_lookup.is_enabled() {
                        log::info!(
                            "Auto-routing: Dropping resolved lookup for {} — auto-routing was disabled",
                            ip
                        );
                        router_for_lookup.clear_pending_lookup(ip);
                        continue;
                    }
                    if !router_for_lookup.is_current_lookup_session(session_epoch) {
                        log::info!(
                            "Auto-routing: Ignoring stale lookup for {} (generation {}, session {}) after router reset",
                            ip,
                            generation,
                            session_epoch
                        );
                        router_for_lookup.clear_pending_lookup(ip);
                        continue;
                    }
                    if !router_for_lookup.should_process_lookup_result(ip) {
                        log::info!(
                            "Auto-routing: Ignoring lookup for {} (generation {}) because another game server is active",
                            ip,
                            generation
                        );
                        router_for_lookup.clear_pending_lookup(ip);
                        continue;
                    }
                    if !router_for_lookup.pin_active_game_server_for_session(ip, session_epoch) {
                        log::info!(
                            "Auto-routing: Ignoring lookup for {} (generation {}) after active game server changed",
                            ip,
                            generation
                        );
                        router_for_lookup.clear_pending_lookup(ip);
                        continue;
                    }

                    log::info!(
                        "Auto-routing: {} resolved to {} ({})",
                        ip,
                        location,
                        region.display_name()
                    );
                    let old_region = router_for_lookup.current_region();

                    // Resolve the target relay from cached latency. Any switch
                    // happens *while this IP's packets are still held*: the game
                    // server must only ever see traffic from the final relay —
                    // a post-establishment switch would change the source IP
                    // mid-session, which Roblox's RakNet drops.
                    if let Some((selected_region, selected_addr)) =
                        router_for_lookup.get_best_server_for_region(&region)
                    {
                        let cached_improvement =
                            router_for_lookup.current_relay().and_then(|current| {
                                let servers = router_for_lookup.available_servers_snapshot();
                                compute_cached_latency_improvement(
                                    &servers,
                                    selected_addr,
                                    current.1,
                                )
                            });
                        let current_addr = router_for_lookup.current_relay().map(|(_, addr)| addr);
                        let needs_switch = current_addr != Some(selected_addr);

                        if needs_switch
                            && router_for_lookup.switch_allowed_precheck(
                                &selected_region,
                                selected_addr,
                                cached_improvement,
                            )
                        {
                            // Authenticate the target relay BEFORE moving any
                            // traffic. Bans/revocation stay enforced and an
                            // auth-required relay can never blackhole the
                            // session. One retry for transport-level failures.
                            let mut auth_result = match auth_manager_for_lookup.as_ref() {
                                Some(auth_manager) => {
                                    authenticate_switch_target(
                                        auth_manager,
                                        &relay_for_lookup,
                                        &selected_region,
                                        selected_addr,
                                    )
                                    .await
                                }
                                None => SwitchAuthOutcome::Rejected(
                                    "no auth manager configured".to_string(),
                                ),
                            };
                            if let SwitchAuthOutcome::Retryable(reason) = &auth_result {
                                log::warn!(
                                    "Auto-routing: Relay auth for {} failed ({}), retrying once",
                                    selected_region,
                                    reason
                                );
                                if let Some(auth_manager) = auth_manager_for_lookup.as_ref() {
                                    auth_result = authenticate_switch_target(
                                        auth_manager,
                                        &relay_for_lookup,
                                        &selected_region,
                                        selected_addr,
                                    )
                                    .await;
                                }
                            }

                            // The auth handshake awaited — re-verify this lookup
                            // still owns the route (and Auto Route wasn't
                            // disabled meanwhile) before committing.
                            let still_current =
                                router_for_lookup.lookup_commit_allowed(ip, session_epoch);

                            match auth_result {
                                SwitchAuthOutcome::Ok if still_current => {
                                    if let Some((new_addr, new_region)) = router_for_lookup
                                        .commit_switch(
                                            ip,
                                            session_epoch,
                                            region.clone(),
                                            selected_region,
                                            selected_addr,
                                            cached_improvement,
                                        )
                                    {
                                        log::info!(
                                            "Auto-routing: SWITCHING relay {} -> {} (addr: {}, authenticated)",
                                            old_region,
                                            new_region,
                                            new_addr
                                        );
                                        relay_for_lookup.switch_relay(new_addr);
                                        state_for_lookup.send_if_modified(|state| {
                                            if let ConnectionState::Connected {
                                                ref mut server_region,
                                                ref mut server_endpoint,
                                                ..
                                            } = *state
                                            {
                                                *server_region = new_region.clone();
                                                *server_endpoint = new_addr.to_string();
                                                true
                                            } else {
                                                false
                                            }
                                        });
                                        if let Err(e) =
                                            relay_for_lookup.send_keepalive_burst_async().await
                                        {
                                            log::warn!(
                                                "Auto-routing: Failed to send keepalive burst to new relay: {}",
                                                e
                                            );
                                        }
                                        crate::notification::show_relay_switch(
                                            &old_region,
                                            &new_region,
                                            &location,
                                        );
                                    }
                                }
                                SwitchAuthOutcome::Ok => {
                                    log::info!(
                                        "Auto-routing: Discarding authenticated switch for {} (lookup no longer current or auto-routing disabled)",
                                        ip
                                    );
                                }
                                SwitchAuthOutcome::Rejected(reason)
                                | SwitchAuthOutcome::Retryable(reason) => {
                                    log::warn!(
                                        "Auto-routing: Not switching to {} ({}) — staying on authenticated relay {}",
                                        selected_region,
                                        reason,
                                        old_region
                                    );
                                }
                            }
                        } else if !needs_switch {
                            router_for_lookup.record_game_region(region.clone());
                            log::info!(
                                "Auto-routing: Already on best relay for {} ({})",
                                location,
                                selected_region
                            );
                        } else {
                            log::info!(
                                "Auto-routing: Switch to {} for {} skipped by rate limiter",
                                selected_region,
                                location
                            );
                        }
                    } else {
                        log::info!(
                            "Auto-routing: No switch needed (bypass or no server for {})",
                            location
                        );
                    }

                    // Release held packets — the relay is final for this
                    // game-server connection.
                    router_for_lookup.clear_pending_lookup(ip);
                }
                log::debug!("Auto-routing: Lookup task exiting (channel closed)");
            });
            self.auto_lookup_handle = Some(lookup_handle);
            log::info!("V3: Auto-routing lookup task spawned");
        }

        driver.set_auto_router(Arc::clone(&auto_router));
        self.auto_router = Some(Arc::clone(&auto_router));
        log::info!(
            "V3: Auto-router initialized for region {} (enabled: {})",
            selected_relay_region,
            auto_routing_enabled
        );

        // Configure split tunnel driver (no Wintun LUID needed for UDP relay)
        let split_config =
            SplitTunnelConfig::new(tunnel_apps.clone(), 0, binding_preference.clone());

        // Set TCP API tunneling flag before configure() spawns the reader
        // thread, so the flag is visible from the very first packet batch.
        if enable_api_tunneling {
            driver.set_api_tunneling_enabled(true);
            log::info!("V3: API tunneling (TCP) enabled");
        }
        driver.set_udp_tunneling_enabled(enable_udp_tunneling);
        if !enable_udp_tunneling {
            log::info!("V3: UDP gameplay tunneling disabled for TCP-only country-ban bypass");
        }

        driver.configure(split_config).map_err(|e| {
            let _ = driver.close();
            VpnError::SplitTunnelSetupFailed(format!("Failed to configure V3 split tunnel: {}", e))
        })?;

        let process_performance_policy =
            GameProcessPerformancePolicy::from(process_performance_settings);
        let process_performance_manager = if process_performance_policy.is_enabled() {
            log::info!(
                "V3: Process tuning enabled (gpu_binding={}, prefer_p_cores={}, unbind_cpu0={})",
                process_performance_policy.high_performance_gpu_binding,
                process_performance_policy.prefer_performance_cores,
                process_performance_policy.unbind_cpu0
            );
            Some(Arc::new(Mutex::new(GameProcessPerformanceManager::new(
                process_performance_policy,
            ))))
        } else {
            log::info!("V3: Process tuning disabled (all toggles off)");
            None
        };
        self.process_performance_manager = process_performance_manager.clone();

        // CACHE WARMUP: Do an immediate refresh to populate process snapshot
        // This handles the case where Roblox is ALREADY running when the user connects.
        // Without this, the snapshot is empty until the first periodic refresh (up to 2s),
        // and all traffic would rely on speculative IP matching which misses STUN/voice.
        if let Err(e) = driver.refresh_exclusions() {
            log::warn!("V3: Initial cache warmup failed: {}", e);
        } else {
            log::info!("V3: Initial cache warmup completed - process snapshot populated");
        }

        let running_processes = driver.get_running_tunnel_processes();
        if let Some(ref manager) = process_performance_manager {
            let mut guard = manager.lock().await;
            guard.sync_targets(&running_processes);
        }
        let running = dedupe_process_names(&running_processes);
        if !running.is_empty() {
            log::info!("V3: Currently tunneling: {:?}", running);
        }

        // Capture the interceptor's panic-cause flag before the driver moves
        // into an Arc<Mutex<_>> — the monitor task needs lock-free access to
        // poll it alongside relay_health and sender_panicked.
        let workers_panic_cause_for_monitor = driver.workers_panic_cause_arc();
        let driver = Arc::new(Mutex::new(driver));
        self.split_tunnel = Some(Arc::clone(&driver));

        // Start ETW process watcher for instant game detection
        let watch_list: std::collections::HashSet<String> =
            tunnel_apps.iter().map(|s| s.to_lowercase()).collect();

        let etw_receiver: Option<Receiver<ProcessStartEvent>> =
            match ProcessWatcher::start(watch_list) {
                Ok(watcher) => {
                    log::info!("V3: ETW process watcher started");
                    let receiver = watcher.receiver().clone();
                    self.etw_watcher = Some(watcher);
                    Some(receiver)
                }
                Err(e) => {
                    log::warn!(
                        "V3: ETW process watcher failed (continuing with polling): {}",
                        e
                    );
                    None
                }
            };

        // Bridge ETW (crossbeam) receiver into a tokio channel so the async monitor can
        // `select!` without repeatedly spawning blocking tasks.
        let mut etw_tokio_rx: Option<tokio::sync::mpsc::UnboundedReceiver<ProcessStartEvent>> =
            None;
        if let Some(receiver) = etw_receiver {
            let (tx, rx) = tokio::sync::mpsc::unbounded_channel::<ProcessStartEvent>();
            match std::thread::Builder::new()
                .name("v3-etw-forwarder".to_string())
                .spawn(move || {
                    while let Ok(event) = receiver.recv() {
                        if tx.send(event).is_err() {
                            break;
                        }
                    }
                    log::debug!("V3 ETW: Forwarder thread exiting");
                }) {
                Ok(_handle) => {
                    etw_tokio_rx = Some(rx);
                }
                Err(e) => {
                    log::warn!(
                        "V3: Failed to spawn ETW forwarder thread (continuing with polling): {}",
                        e
                    );
                }
            }
        }

        // Start process monitor (event-driven ETW + periodic refresh)
        self.process_monitor_stop.store(false, Ordering::SeqCst);
        let stop_flag = Arc::clone(&self.process_monitor_stop);
        let state_handle = Arc::clone(&self.state);
        let auto_router_for_monitor = self.auto_router.clone();
        let process_performance_for_monitor = self.process_performance_manager.clone();
        let relay_health_monitor = relay_for_health;
        let workers_panic_cause_monitor = workers_panic_cause_for_monitor;

        tokio::spawn(async move {
            log::info!("V3: Process monitor started");
            // Match previous behavior: first periodic refresh occurs after the interval.
            let first_tick =
                tokio::time::Instant::now() + Duration::from_millis(REFRESH_INTERVAL_MS);
            let mut refresh_tick =
                tokio::time::interval_at(first_tick, Duration::from_millis(REFRESH_INTERVAL_MS));
            let mut stop_tick = tokio::time::interval(Duration::from_millis(100));
            let mut etw_rx = etw_tokio_rx;

            // Adapter-reset watchdog. Armed for the first
            // ADAPTER_WATCHDOG_WINDOW_SECS after this monitor task spawns
            // (~immediately after `driver.configure()` returns); fires if
            // `LocalConnectivity::probe()` reports `Offline` for
            // ADAPTER_WATCHDOG_OFFLINE_TICK_THRESHOLD consecutive 500ms
            // ticks (~3s sustained). Catches the case where
            // `Set-NetAdapterAdvancedProperty` calls during interceptor
            // start bounced the NIC and dropped the IPv4 default route,
            // turning what looks like a successful connect into a stuck
            // tunnel for 22+s before the relay-dead path notices.
            let connect_started_at = Instant::now();
            let mut watchdog_offline_ticks: u32 = 0;
            let mut watchdog_armed: bool = true;
            let mut relay_dead_since: Option<Instant> = None;

            loop {
                if stop_flag.load(Ordering::SeqCst) {
                    break;
                }
                tokio::select! {
                    // ETW event-driven path
                    event = async {
                        match etw_rx.as_mut() {
                            Some(rx) => rx.recv().await,
                            None => std::future::pending::<Option<ProcessStartEvent>>().await,
                        }
                    } => {
                        match event {
                            Some(first_event) => {
                                let mut etw_events_received = false;
                                let mut blocked_events: Vec<ProcessStartEvent> = Vec::new();
                                let mut blocked_paths: Vec<String> = Vec::new();

                                // Process the first event (if any) and drain remaining queued events.
                                let mut pending_events: Vec<ProcessStartEvent> = Vec::new();
                                pending_events.push(first_event);
                                if let Some(ref mut rx) = etw_rx {
                                    while let Ok(event) = rx.try_recv() {
                                        pending_events.push(event);
                                    }
                                }

                                for event in &pending_events {
                                    log::info!(
                                        "V3 ETW: Detected {} (PID: {}) - blocking and registering",
                                        event.name,
                                        event.pid
                                    );

                                    // STEP 1: IMMEDIATELY block the process with WFP filter
                                    // This prevents ANY packets (including STUN) from escaping before we're ready
                                    if !event.image_path.is_empty() {
                                        if let Err(e) = super::wfp_block::block_process_by_path(&event.image_path) {
                                            log::warn!(
                                                "V3: WFP block failed for {}: {} (using speculative tunneling)",
                                                event.name,
                                                e
                                            );
                                        } else {
                                            blocked_events.push(event.clone());
                                            blocked_paths.push(event.image_path.clone());
                                        }
                                    } else {
                                        log::warn!(
                                            "V3: Missing image path for {} (PID: {}), cannot apply WFP hold",
                                            event.name,
                                            event.pid
                                        );
                                    }

                                    // STEP 2: Register with the driver's process cache (also wakes cache refresher)
                                    let driver_guard = driver.lock().await;
                                    driver_guard
                                        .register_process_immediate(event.pid, event.name.clone());
                                    drop(driver_guard);
                                    etw_events_received = true;
                                }

                                // CRITICAL: If we received ETW events, IMMEDIATELY refresh connection tables
                                // before releasing the WFP block, to guarantee first-packet tunneling.
                                if etw_events_received {
                                    let pending_after_wait = if blocked_paths.is_empty() {
                                        let mut driver_guard = driver.lock().await;
                                        if let Err(e) = driver_guard.refresh_exclusions() {
                                            log::warn!("V3: Immediate refresh after ETW failed: {}", e);
                                        }
                                        pending_events
                                            .iter()
                                            .filter(|event| !driver_guard.has_cached_connection_for_pid(event.pid))
                                            .map(|event| (event.pid, event.name.clone()))
                                            .collect::<Vec<_>>()
                                    } else {
                                        wait_for_tunnel_process_connections(&driver, &blocked_events).await
                                    };

                                    if pending_after_wait.is_empty() {
                                        log::info!("V3 ETW: Cached process endpoints detected before unblock");
                                    } else if blocked_paths.is_empty() {
                                        log::warn!(
                                            "V3: No WFP hold available; proceeding after single refresh with pending {:?}",
                                            pending_after_wait
                                        );
                                    } else {
                                        log::warn!(
                                            "V3: Releasing ETW hold without cached endpoints after {}ms for {:?}",
                                            ETW_CONNECTION_READY_TIMEOUT_MS,
                                            pending_after_wait
                                        );
                                    }

                                    let mut driver_guard = driver.lock().await;
                                    let running_processes = driver_guard.get_running_tunnel_processes();
                                    let running_names = dedupe_process_names(&running_processes);
                                    drop(driver_guard);

                                    if let Some(ref manager) = process_performance_for_monitor {
                                        let mut guard = manager.lock().await;
                                        guard.sync_targets(&running_processes);
                                    }

                                    // Update UI state promptly when games start/stop
                                    state_handle.send_if_modified(|state| {
                                        if let ConnectionState::Connected { ref mut tunneled_processes, .. } = *state
                                            && *tunneled_processes != running_names {
                                                if !running_names.is_empty() && tunneled_processes.is_empty() {
                                                    log::info!("V3: Game detected, relaying: {:?}", running_names);
                                                } else if running_names.is_empty() && !tunneled_processes.is_empty() {
                                                    log::info!("V3: All games exited");
                                                }
                                                *tunneled_processes = running_names;
                                                return true;
                                            }
                                        false
                                    });

                                    // STEP 3: Remove WFP block filters - packets now flow through VPN relay
                                    for path in blocked_paths {
                                        if let Err(e) = super::wfp_block::unblock_process_by_path(&path) {
                                            log::warn!("V3: WFP unblock failed for {}: {}", path, e);
                                        }
                                    }
                                }
                            }
                            None => {
                                // ETW channel closed (watcher stopped or failed). Fall back to polling only.
                                etw_rx = None;
                                log::warn!("V3: ETW process watcher channel closed (falling back to polling)");
                            }
                        }
                    }

                    // Periodic refresh path
                    _ = refresh_tick.tick() => {
                        // Adapter-reset watchdog: only armed for the first
                        // ADAPTER_WATCHDOG_WINDOW_SECS after connect. Catches
                        // the NIC link-bounce caused by interceptor startup
                        // touching adapter properties — `LocalConnectivity::probe`
                        // goes Offline (`No internet access` in NLM terms) when
                        // the IPv4 default route disappears. Firing here
                        // surfaces a clear retry message in seconds instead of
                        // the ~22s the user otherwise waits for the relay-dead
                        // path to declare the same outcome.
                        //
                        // Two-signal gate: the offline counter only increments
                        // when relay health is non-Healthy as well. A Healthy
                        // relay means we've recently received an inbound
                        // packet through this NIC, which overrides any NLM
                        // false-positive (captive portals, virtual adapters,
                        // hidden-SSID corp networks). See `watchdog_tick`.
                        if watchdog_armed {
                            let probe = super::local_connectivity::probe();
                            let relay_health_now = relay_health_monitor.relay_health();
                            match watchdog_tick(
                                connect_started_at.elapsed(),
                                probe,
                                relay_health_now,
                                watchdog_offline_ticks,
                            ) {
                                WatchdogTickAction::Continue { consecutive_offline_ticks } => {
                                    watchdog_offline_ticks = consecutive_offline_ticks;
                                }
                                WatchdogTickAction::Disarmed => {
                                    watchdog_armed = false;
                                }
                                WatchdogTickAction::Abort { error_message, cleanup_reason } => {
                                    let observed_ticks = watchdog_offline_ticks + 1;
                                    let transitioned = state_handle.send_if_modified(|state| {
                                        if matches!(*state, ConnectionState::Connected { .. }) {
                                            log::error!(
                                                "V3: adapter-reset watchdog fired ({} consecutive offline ticks within {}s of connect) — transitioning Connected → Error",
                                                observed_ticks,
                                                ADAPTER_WATCHDOG_WINDOW_SECS
                                            );
                                            *state = ConnectionState::Error(error_message.clone());
                                            true
                                        } else {
                                            false
                                        }
                                    });

                                    if transitioned {
                                        {
                                            let mut driver_guard = driver.lock().await;
                                            if let Err(e) = driver_guard.close() {
                                                log::warn!(
                                                    "V3: watchdog rollback cleanup — driver.close() returned {}",
                                                    e
                                                );
                                            }
                                        }
                                        super::wfp_block::cleanup();
                                        if let Some(ref auto_router) = auto_router_for_monitor {
                                            auto_router.reset();
                                        }
                                        if let Some(ref manager) = process_performance_for_monitor {
                                            let mut guard = manager.lock().await;
                                            guard.cleanup_all(cleanup_reason);
                                        }
                                        break;
                                    } else {
                                        // State already left Connected — a concurrent
                                        // path (user-initiated disconnect, the relay-
                                        // health monitor beating us to the transition)
                                        // owns teardown. Disarm so the next tick doesn't
                                        // re-enter Abort with the same prior counter and
                                        // spam log::error every 500ms until stop_flag.
                                        watchdog_armed = false;
                                        watchdog_offline_ticks = 0;
                                    }
                                }
                            }
                        }

                        let mut driver_guard = driver.lock().await;
                        match driver_guard.maybe_rebind_on_default_route_change() {
                            Ok(true) => log::info!("V3: Split tunnel adapter re-bound to active interface"),
                            Ok(false) => {}
                            Err(e) => log::warn!("V3: Split tunnel adapter rebind failed: {}", e),
                        }
                        match driver_guard.refresh_exclusions() {
                            Ok(_) => {
                                let running_processes = driver_guard.get_running_tunnel_processes();
                                let running_names = dedupe_process_names(&running_processes);
                                drop(driver_guard);

                                if let Some(ref manager) = process_performance_for_monitor {
                                    let mut guard = manager.lock().await;
                                    guard.sync_targets(&running_processes);
                                }

                                state_handle.send_if_modified(|state| {
                                    if let ConnectionState::Connected { ref mut tunneled_processes, .. } = *state
                                        && *tunneled_processes != running_names {
                                            if !running_names.is_empty() && tunneled_processes.is_empty() {
                                                log::info!("V3: Game detected, relaying: {:?}", running_names);
                                            } else if running_names.is_empty() && !tunneled_processes.is_empty() {
                                                log::info!("V3: All games exited");
                                            }
                                            *tunneled_processes = running_names;
                                            return true;
                                        }
                                    false
                                });
                            }
                            Err(e) => {
                                log::warn!("V3: Exclusion refresh error: {}", e);
                            }
                        }

                        // Sync auto-routing state to connection state
                        if let Some(ref auto_router) = auto_router_for_monitor {
                            let current_auto_region = auto_router.current_region();
                            state_handle.send_if_modified(|state| {
                                if let ConnectionState::Connected { ref mut server_region, .. } = *state
                                    && *server_region != current_auto_region && !current_auto_region.is_empty() {
                                        log::info!(
                                            "Auto-routing: Syncing UI state to region '{}'",
                                            current_auto_region
                                        );
                                        *server_region = current_auto_region;
                                        return true;
                                    }
                                false
                            });
                        }

                        // Check relay health and update connection state for UI visibility
                        {
                            let health = relay_health_monitor.relay_health();

                            // A non-zero `workers_panic_cause` means a
                            // split-tunnel thread failed and zero packets will
                            // ever flow again in this session. The two causes
                            // (see `WorkerPanicCause`) get distinct,
                            // actionable error strings via `worker_panic_error`
                            // — driver-handle loss renders the reinstall-driver
                            // CTA, an internal thread panic renders a plain
                            // reconnect. Previously both collapsed into one
                            // "reinstall driver" message and the UI kept
                            // showing a green check until then.
                            let worker_panic_cause = workers_panic_cause_monitor
                                .as_ref()
                                .and_then(|f| {
                                    WorkerPanicCause::from_u8(f.load(Ordering::Acquire))
                                });

                            if let Some(cause) = worker_panic_cause {
                                let (error_message, cleanup_reason) =
                                    worker_panic_error(cause);
                                let transitioned = state_handle.send_if_modified(|state| {
                                    if matches!(*state, ConnectionState::Connected { .. }) {
                                        log::error!(
                                            "V3: split-tunnel worker failure ({:?}) — transitioning Connected → Error",
                                            cause
                                        );
                                        *state = ConnectionState::Error(error_message.clone());
                                        true
                                    } else {
                                        false
                                    }
                                });
                                // Immediate best-effort cleanup via shared Arcs: closing the
                                // split_tunnel driver triggers `ParallelInterceptor::stop()`
                                // which restores TSO/IPv6 and joins reader/worker threads.
                                // Without this, the adapter would stay in
                                // `MSTCP_FLAG_SENT_RECEIVE_TUNNEL` with no reader draining the
                                // ndisrd queue until the user clicks Disconnect — which makes
                                // all traffic on the physical NIC stall, not just tunnel apps.
                                // ETW watcher, `self.split_tunnel = None`, and `self.config`
                                // live on `&mut self` so they're reconciled on the next
                                // `connect()` / `disconnect()` call; connect() was also patched
                                // to run `cleanup()` first when the prior state was Error.
                                if transitioned {
                                    {
                                        let mut driver_guard = driver.lock().await;
                                        if let Err(e) = driver_guard.close() {
                                            log::warn!(
                                                "V3: recovery cleanup — driver.close() returned {}",
                                                e
                                            );
                                        }
                                    }
                                    super::wfp_block::cleanup();
                                    if let Some(ref auto_router) = auto_router_for_monitor {
                                        auto_router.reset();
                                    }
                                    if let Some(ref manager) = process_performance_for_monitor {
                                        let mut guard = manager.lock().await;
                                        guard.cleanup_all(cleanup_reason);
                                    }
                                    break;
                                }
                            }

                            let sender_panicked = relay_health_monitor.sender_panicked();
                            let relay_dead_grace_elapsed =
                                if health == super::udp_relay::RelayHealthState::Dead
                                    && !sender_panicked
                                {
                                    let dead_since = relay_dead_since.get_or_insert_with(Instant::now);
                                    dead_since.elapsed()
                                        >= Duration::from_secs(RELAY_DEAD_GRACE_SECS)
                                } else {
                                    relay_dead_since = None;
                                    false
                                };
                            let local_connectivity = if health
                                == super::udp_relay::RelayHealthState::Dead
                            {
                                super::local_connectivity::probe()
                            } else {
                                LocalConnectivity::Unknown
                            };
                            match classify_relay_health(
                                health,
                                sender_panicked,
                                local_connectivity,
                                relay_dead_grace_elapsed,
                            ) {
                                RelayHealthAction::Fatal {
                                    error_message,
                                    cleanup_reason,
                                } => {
                                    let transitioned = state_handle.send_if_modified(|state| {
                                        if matches!(*state, ConnectionState::Connected { .. }) {
                                            log::error!(
                                                "V3: Relay health is '{}' - transitioning Connected -> Error",
                                                health.as_str()
                                            );
                                            *state = ConnectionState::Error(error_message.clone());
                                            true
                                        } else {
                                            false
                                        }
                                    });

                                    if transitioned {
                                        {
                                            let mut driver_guard = driver.lock().await;
                                            if let Err(e) = driver_guard.close() {
                                                log::warn!(
                                                    "V3: relay recovery cleanup - driver.close() returned {}",
                                                    e
                                                );
                                            }
                                        }
                                        super::wfp_block::cleanup();
                                        if let Some(ref auto_router) = auto_router_for_monitor {
                                            auto_router.reset();
                                        }
                                        if let Some(ref manager) = process_performance_for_monitor {
                                            let mut guard = manager.lock().await;
                                            guard.cleanup_all(cleanup_reason);
                                        }
                                        break;
                                    }
                                }
                                RelayHealthAction::Continue { relay_status: new_status } => {
                                    state_handle.send_if_modified(|state| {
                                        if let ConnectionState::Connected { ref mut relay_status, .. } = *state
                                            && *relay_status != new_status {
                                                match &new_status {
                                                    Some(status) => log::warn!(
                                                        "V3: Relay health degraded to '{}' - updating UI state",
                                                        status
                                                    ),
                                                    None => {
                                                        if relay_status.is_some() {
                                                            log::info!("V3: Relay health recovered to healthy");
                                                        }
                                                    }
                                                }
                                                *relay_status = new_status;
                                                return true;
                                            }
                                        false
                                    });
                                }
                            }
                        }
                    }

                    // Wake periodically to check stop_flag promptly without spawning tasks.
                    _ = stop_tick.tick() => {}
                }
            }

            log::info!("V3: Process monitor stopped");
        });

        if custom_relay_server.is_none() {
            if let Some(auth_manager) = self.auth_manager.clone() {
                let relay_for_refresh = relay_for_lease_refresh;
                let router_for_refresh = self.auto_router.clone();
                let fallback_region = selected_relay_region.clone();
                let fallback_addr = relay_addr;
                let session_id = relay_for_refresh.session_id_hex();
                let state_for_refresh = Arc::clone(&self.state);
                let terminal_cleanup_requested = Arc::clone(&self.terminal_cleanup_requested);

                self.relay_lease_refresh_handle = Some(tokio::spawn(async move {
                    let mut delay = RELAY_LEASE_REFRESH_INTERVAL;
                    loop {
                        tokio::time::sleep(delay).await;

                        let (region, addr) = router_for_refresh
                            .as_ref()
                            .and_then(|router| router.current_relay())
                            .unwrap_or_else(|| (fallback_region.clone(), fallback_addr));

                        let access_token = {
                            let manager = auth_manager.lock().await;
                            match manager.get_access_token().await {
                                Ok(token) => token,
                                Err(error) => {
                                    if let Some(message) =
                                        terminal_relay_lease_error_message(&error)
                                    {
                                        log::warn!(
                                            "Relay lease ended because the session is no longer authorized: {error}"
                                        );
                                        terminal_cleanup_requested.store(true, Ordering::SeqCst);
                                        relay_for_refresh.stop();
                                        let _ = state_for_refresh
                                            .send_replace(ConnectionState::Error(message));
                                        break;
                                    }
                                    log::warn!(
                                        "Relay lease refresh could not obtain access token: {error}"
                                    );
                                    delay = RELAY_LEASE_RETRY_INTERVAL;
                                    continue;
                                }
                            }
                        };

                        let client = AuthClient::new();

                        match client
                            .get_relay_ticket(&access_token, &region, &session_id)
                            .await
                        {
                            Ok(ticket) => {
                                record_free_tier_quota(&ticket);
                                match relay_for_refresh
                                    .authenticate_addr_with_ticket(&ticket.token, addr)
                                    .await
                                {
                                    Ok(Some(status)) if status.is_authenticated() => {
                                        log::debug!("Renewed relay lease for {region} at {addr}");
                                        delay = RELAY_LEASE_REFRESH_INTERVAL;
                                    }
                                    Ok(Some(status)) => {
                                        log::warn!(
                                            "Relay lease renewal was rejected by {addr}: {}",
                                            status.as_str()
                                        );
                                        delay = RELAY_LEASE_RETRY_INTERVAL;
                                    }
                                    Ok(None) => {
                                        log::warn!("Relay lease renewal timed out for {addr}");
                                        delay = RELAY_LEASE_RETRY_INTERVAL;
                                    }
                                    Err(error) => {
                                        log::warn!(
                                            "Relay lease re-authentication failed for {addr}: {error}"
                                        );
                                        delay = RELAY_LEASE_RETRY_INTERVAL;
                                    }
                                }
                            }
                            Err(error) => {
                                if let Some(message) = terminal_relay_lease_error_message(&error) {
                                    log::warn!(
                                        "Relay lease ended because the server rejected the session: {error}"
                                    );
                                    terminal_cleanup_requested.store(true, Ordering::SeqCst);
                                    relay_for_refresh.stop();
                                    let _ = state_for_refresh
                                        .send_replace(ConnectionState::Error(message));
                                    break;
                                }
                                log::warn!("Relay lease refresh failed for {region}: {error}");
                                delay = RELAY_LEASE_RETRY_INTERVAL;
                            }
                        }
                    }
                }));
            } else {
                log::warn!("Relay lease refresh unavailable because no auth manager is attached");
            }
        }

        log::info!("V3 split tunnel configured - game traffic relayed via UDP");
        Ok((running, relay_auth_mode, selected_relay_region, relay_addr))
    }

    /// Consume a terminal cleanup request raised by the relay lease task.
    ///
    /// The owning desktop task must perform cleanup because the lease task is
    /// itself stored in `relay_lease_refresh_handle`; cleaning up from inside
    /// that task would try to abort and await itself.
    pub fn take_terminal_cleanup_request(&self) -> bool {
        self.terminal_cleanup_requested
            .swap(false, Ordering::SeqCst)
    }

    /// Tear down local session resources after a terminal lease failure while
    /// preserving the Error state already published to the UI.
    pub async fn cleanup_after_terminal_error(&mut self) {
        self.cleanup().await;
        self.release_free_tier_quota().await;
    }

    pub async fn disconnect(&mut self) -> VpnResult<()> {
        log::info!("Disconnecting VPN");
        crate::vpn::bypass_diag::end_session();
        self.set_state(ConnectionState::Disconnecting).await;
        self.cleanup().await;
        self.release_free_tier_quota().await;
        self.set_state(ConnectionState::Disconnected).await;
        log::info!("VPN disconnected");
        Ok(())
    }

    /// Tell the API the session is over so the free-tier counter is settled
    /// against time actually spent connected.
    ///
    /// The server can otherwise only settle a session when the next ticket is
    /// requested, and at that point a 30-second session looks identical to a
    /// full ticket window: it sees a long gap and charges the whole TTL. A few
    /// short sessions would eat a large slice of the daily allowance for time
    /// the user never had.
    ///
    /// Best effort on purpose. This runs on the way out, so a failure is logged
    /// and swallowed — the cost is the old over-charge, never a disconnect that
    /// appears to fail. A hard kill skips it entirely and falls back to the
    /// same old behaviour.
    async fn release_free_tier_quota(&self) {
        let Some(auth_manager) = self.auth_manager.as_ref() else {
            return;
        };

        let token = {
            let auth = auth_manager.lock().await;
            auth.get_access_token().await.ok()
        };
        let Some(token) = token else {
            return;
        };

        match crate::auth::http_client::AuthClient::new()
            .release_relay_quota(&token)
            .await
        {
            Ok(()) => {
                // The budget the UI is showing is now stale in the user's
                // favour; the next ticket refreshes it.
                log::debug!("Free-tier session released");
            }
            Err(e) => {
                log::warn!("Free-tier release failed (usage may be over-counted): {e}");
            }
        }
    }

    async fn cleanup(&mut self) {
        // Stop process monitor
        self.process_monitor_stop.store(true, Ordering::SeqCst);

        if let Some(handle) = self.relay_lease_refresh_handle.take() {
            handle.abort();
            let _ = handle.await;
        }

        // Stop ETW watcher (cleans up ETW session)
        if let Some(mut watcher) = self.etw_watcher.take() {
            log::info!("Stopping ETW process watcher...");
            watcher.stop();
        }

        // Cleanup WFP block filters
        super::wfp_block::cleanup();

        if let Some(mut guard) = self.goodbye_dpi_guard.take() {
            guard.stop();
        }

        if self.bootstrap_dns_repair_applied {
            match crate::roblox_proxy::hosts::remove_overrides_async().await {
                Ok(()) => {
                    self.bootstrap_dns_repair_applied = false;
                }
                Err(e) => {
                    log::warn!("Failed to remove Roblox bootstrap DNS repair: {e}");
                }
            }
        }

        // Reset auto-router
        if let Some(ref auto_router) = self.auto_router {
            auto_router.reset();
        }
        self.auto_router = None;

        if let Some(handle) = self.auto_lookup_handle.take() {
            handle.abort();
            let _ = handle.await;
        }

        if let Some(manager) = self.process_performance_manager.take() {
            let mut guard = manager.lock().await;
            guard.cleanup_all("tunnel_cleanup");
        }

        // Clear split tunnel
        if let Some(ref driver) = self.split_tunnel {
            let mut guard = driver.lock().await;
            if let Err(e) = guard.close() {
                log::warn!("Error closing split tunnel: {}", e);
            }
        }
        self.split_tunnel = None;

        self.config = None;
    }

    pub fn config(&self) -> Option<&VpnConfig> {
        self.config.as_ref()
    }

    /// Switch relay server without disconnecting (Auto Routing).
    ///
    /// This atomically swaps the relay address used by all packet workers.
    /// The split tunnel (ndisapi), process cache, and all worker threads
    /// stay running. Only the relay destination changes.
    ///
    /// NOTE: Currently unused - auto-routing switches happen directly in worker
    /// threads via relay.switch_relay(). This method is kept for future GUI-initiated
    /// manual server switching, as it correctly updates ConnectionState.
    ///
    /// Returns Ok(()) if the switch was successful.
    pub async fn switch_server(
        &self,
        new_relay_addr: std::net::SocketAddr,
        new_region: &str,
    ) -> VpnResult<()> {
        // Must be connected
        if !self.state.borrow().is_connected() {
            return Err(VpnError::Connection(
                "Not connected - cannot switch server".to_string(),
            ));
        }

        // Switch the relay via the split tunnel driver
        let switched = if let Some(ref st) = self.split_tunnel {
            match st.try_lock() {
                Ok(driver) => driver.switch_relay_addr(new_relay_addr),
                Err(_) => {
                    return Err(VpnError::Connection(
                        "Split tunnel locked - try again".to_string(),
                    ));
                }
            }
        } else {
            return Err(VpnError::Connection("No split tunnel active".to_string()));
        };

        if !switched {
            return Err(VpnError::Connection(
                "Failed to switch relay address".to_string(),
            ));
        }

        // Update connection state with new server info
        self.state.send_if_modified(|state| {
            if let ConnectionState::Connected {
                ref mut server_region,
                ref mut server_endpoint,
                ..
            } = *state
            {
                *server_region = new_region.to_string();
                *server_endpoint = new_relay_addr.to_string();
                true
            } else {
                false
            }
        });

        log::info!(
            "Auto-routing: Switched relay to {} ({})",
            new_relay_addr,
            new_region
        );

        Ok(())
    }

    /// Get the current relay address for auto-routing comparison
    pub fn current_relay_addr(&self) -> Option<std::net::SocketAddr> {
        self.split_tunnel.as_ref().and_then(|st| {
            st.try_lock()
                .ok()
                .and_then(|driver| driver.current_relay_addr())
        })
    }

    pub fn is_split_tunnel_active(&self) -> bool {
        self.split_tunnel.is_some()
    }

    pub async fn register_tunnel_process(&self, pid: u32, exe_name: &str) -> VpnResult<()> {
        if let Some(ref driver) = self.split_tunnel {
            let guard = driver.lock().await;
            guard.register_process_immediate(pid, exe_name.to_string());
            Ok(())
        } else {
            Err(VpnError::SplitTunnel("Split tunnel not active".to_string()))
        }
    }

    pub async fn register_tunnel_udp_port(&self, local_port: u16) -> VpnResult<()> {
        if let Some(ref driver) = self.split_tunnel {
            let guard = driver.lock().await;
            guard.register_udp_port_immediate(local_port);
            Ok(())
        } else {
            Err(VpnError::SplitTunnel("Split tunnel not active".to_string()))
        }
    }

    pub async fn refresh_split_tunnel_cache(&self) -> VpnResult<()> {
        if let Some(ref driver) = self.split_tunnel {
            let mut guard = driver.lock().await;
            guard.refresh_exclusions()?;
            Ok(())
        } else {
            Err(VpnError::SplitTunnel("Split tunnel not active".to_string()))
        }
    }

    pub async fn add_tunnel_app(&mut self, exe_name: &str) -> VpnResult<()> {
        if let Some(ref driver) = self.split_tunnel {
            let mut guard = driver.lock().await;
            if let Some(config) = guard.config.as_mut() {
                config.tunnel_apps.insert(exe_name.to_lowercase());
            }
            guard.refresh_exclusions()?;
            Ok(())
        } else {
            Err(VpnError::SplitTunnel("Split tunnel not active".to_string()))
        }
    }

    pub async fn remove_tunnel_app(&mut self, exe_name: &str) -> VpnResult<()> {
        if let Some(ref driver) = self.split_tunnel {
            let mut guard = driver.lock().await;
            if let Some(config) = guard.config.as_mut() {
                config.tunnel_apps.remove(&exe_name.to_lowercase());
            }
            guard.refresh_exclusions()?;
            Ok(())
        } else {
            Err(VpnError::SplitTunnel("Split tunnel not active".to_string()))
        }
    }

    // Legacy compatibility
    pub async fn add_split_tunnel_app(&mut self, exe_path: &str) -> VpnResult<()> {
        self.add_tunnel_app(exe_path).await
    }

    pub async fn remove_split_tunnel_app(&mut self, exe_path: &str) -> VpnResult<()> {
        self.remove_tunnel_app(exe_path).await
    }
}

impl Default for VpnConnection {
    fn default() -> Self {
        Self::new()
    }
}

impl Drop for VpnConnection {
    fn drop(&mut self) {
        self.process_monitor_stop.store(true, Ordering::SeqCst);

        // Stop ETW watcher
        if let Some(mut watcher) = self.etw_watcher.take() {
            watcher.stop();
        }

        if let Some(manager) = self.process_performance_manager.take() {
            if let Ok(mut guard) = manager.try_lock() {
                guard.cleanup_all("vpn_connection_drop");
            } else {
                log::warn!(
                    "Process tuning: manager lock busy during VpnConnection drop; skipping immediate cleanup"
                );
            }
        }

        if let Some(ref driver) = self.split_tunnel
            && let Ok(mut guard) = driver.try_lock()
        {
            let _ = guard.close();
        }

        super::wfp_block::cleanup();

        if let Some(mut guard) = self.goodbye_dpi_guard.take() {
            guard.stop();
        }

        if self.bootstrap_dns_repair_applied
            && let Err(e) = crate::roblox_proxy::hosts::remove_overrides()
        {
            log::warn!("Failed to remove Roblox bootstrap DNS repair during drop: {e}");
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_is_disconnected() {
        let state = ConnectionState::default();
        assert_eq!(state, ConnectionState::Disconnected);
    }

    #[test]
    fn test_is_connected_true_for_connected() {
        let state = ConnectionState::Connected {
            since: Instant::now(),
            server_region: "us-east".to_string(),
            server_endpoint: "1.2.3.4:51820".to_string(),
            assigned_ip: "10.0.0.2".to_string(),
            relay_auth_mode: "authenticated".to_string(),
            split_tunnel_active: true,
            tunneled_processes: vec!["RobloxPlayerBeta.exe".to_string()],
            relay_status: None,
        };
        assert!(state.is_connected());
    }

    #[test]
    fn test_is_connected_false_for_other_states() {
        assert!(!ConnectionState::Disconnected.is_connected());
        assert!(!ConnectionState::FetchingConfig.is_connected());
        assert!(!ConnectionState::ConfiguringSplitTunnel.is_connected());
        assert!(!ConnectionState::Disconnecting.is_connected());
        assert!(!ConnectionState::Error("err".to_string()).is_connected());
    }

    #[test]
    fn test_is_connecting_true_for_connecting_states() {
        assert!(ConnectionState::FetchingConfig.is_connecting());
        assert!(ConnectionState::ConfiguringSplitTunnel.is_connecting());
    }

    #[test]
    fn test_is_connecting_false_for_non_connecting_states() {
        assert!(!ConnectionState::Disconnected.is_connecting());
        assert!(!ConnectionState::Disconnecting.is_connecting());
        assert!(!ConnectionState::Error("err".to_string()).is_connecting());

        let connected = ConnectionState::Connected {
            since: Instant::now(),
            server_region: "eu-west".to_string(),
            server_endpoint: "5.6.7.8:51820".to_string(),
            assigned_ip: "10.0.0.3".to_string(),
            relay_auth_mode: "legacy_fallback".to_string(),
            split_tunnel_active: false,
            tunneled_processes: vec![],
            relay_status: None,
        };
        assert!(!connected.is_connecting());
    }

    #[test]
    fn test_is_error() {
        assert!(ConnectionState::Error("something broke".to_string()).is_error());
        assert!(!ConnectionState::Disconnected.is_error());
        assert!(!ConnectionState::FetchingConfig.is_error());
    }

    #[test]
    fn test_error_message_some_for_error() {
        let state = ConnectionState::Error("timeout".to_string());
        assert_eq!(state.error_message(), Some("timeout"));
    }

    #[test]
    fn test_error_message_none_for_other_states() {
        assert_eq!(ConnectionState::Disconnected.error_message(), None);
        assert_eq!(ConnectionState::FetchingConfig.error_message(), None);
        assert_eq!(
            ConnectionState::ConfiguringSplitTunnel.error_message(),
            None
        );
        assert_eq!(ConnectionState::Disconnecting.error_message(), None);

        let connected = ConnectionState::Connected {
            since: Instant::now(),
            server_region: "us-west".to_string(),
            server_endpoint: "1.2.3.4:51820".to_string(),
            assigned_ip: "10.0.0.2".to_string(),
            relay_auth_mode: "legacy_fallback".to_string(),
            split_tunnel_active: false,
            tunneled_processes: vec![],
            relay_status: None,
        };
        assert_eq!(connected.error_message(), None);
    }

    #[test]
    fn test_status_text_all_variants() {
        assert_eq!(ConnectionState::Disconnected.status_text(), "Disconnected");
        assert_eq!(
            ConnectionState::FetchingConfig.status_text(),
            "Resolving relay endpoint..."
        );
        assert_eq!(
            ConnectionState::ConfiguringSplitTunnel.status_text(),
            "Configuring split tunnel..."
        );
        assert_eq!(
            ConnectionState::Disconnecting.status_text(),
            "Disconnecting..."
        );
        assert_eq!(
            ConnectionState::Error("x".to_string()).status_text(),
            "Error"
        );

        let connected = ConnectionState::Connected {
            since: Instant::now(),
            server_region: "us-east".to_string(),
            server_endpoint: "1.2.3.4:51820".to_string(),
            assigned_ip: "10.0.0.2".to_string(),
            relay_auth_mode: "authenticated".to_string(),
            split_tunnel_active: true,
            tunneled_processes: vec![],
            relay_status: None,
        };
        assert_eq!(connected.status_text(), "Connected");
    }

    #[test]
    fn test_vpn_connection_new_starts_disconnected() {
        let conn = VpnConnection::new();
        let rx = conn.state_handle();
        assert_eq!(*rx.borrow(), ConnectionState::Disconnected);
    }

    #[test]
    fn no_toggles_keeps_plain_vpn_behavior() {
        let flags = resolve_tunnel_routing_flags(false, false);

        assert!(!flags.api_tunneling);
        assert!(flags.udp_tunneling);
    }

    #[test]
    fn full_ban_bypass_relays_control_plane_and_gameplay_udp() {
        // Egypt-style full block: nothing can be trusted to the direct path,
        // so full bypass alone relays gameplay UDP too (it used to require
        // also enabling Route Assist, which confused users).
        let flags = resolve_tunnel_routing_flags(false, true);

        assert!(flags.api_tunneling);
        assert!(flags.udp_tunneling);
    }

    #[test]
    fn route_assist_without_bypass_keeps_existing_udp_relay_behavior() {
        let flags = resolve_tunnel_routing_flags(true, false);

        assert!(flags.api_tunneling);
        assert!(flags.udp_tunneling);
    }

    fn candidate(region: &str, latency_ms: u32) -> (String, SocketAddr, Option<u32>) {
        (
            region.to_string(),
            "127.0.0.1:51820".parse().unwrap(),
            Some(latency_ms),
        )
    }

    #[test]
    fn relay_choice_prefers_the_faster_region_outside_the_tie_band() {
        // Occupancy must never send anyone to a slower region. 23ms vs 115ms is
        // far outside the band, so latency decides regardless of load.
        let candidates = [candidate("mumbai", 23), candidate("tokyo", 115)];
        let picked = pick_lowest_latency_server(candidates.iter()).unwrap();
        assert_eq!(picked.0, "mumbai");
    }

    #[test]
    fn relay_choice_keeps_the_fastest_when_load_is_unknown() {
        // Every candidate has unknown occupancy, so they all land in the same
        // bucket and latency breaks the tie. This is the old behaviour, and it
        // must not change until real data exists.
        let _guard = load_test_guard();
        crate::vpn::servers::clear_relay_load_for_test();

        let candidates = [candidate("mumbai", 23), candidate("mumbai-02", 25)];
        let picked = pick_lowest_latency_server(candidates.iter()).unwrap();
        assert_eq!(picked.0, "mumbai");
    }

    /// Take the registry lock, recovering it if an earlier test panicked while
    /// holding it. A poisoned lock is not a reason to fail every later test.
    fn load_test_guard() -> std::sync::MutexGuard<'static, ()> {
        crate::vpn::servers::RELAY_LOAD_TEST_LOCK
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }

    fn ranked(region: &str, ip: &str, latency_ms: Option<u32>) -> RankedRelayCandidate {
        RankedRelayCandidate::from_candidate((
            region.to_string(),
            format!("{ip}:51820").parse().unwrap(),
            latency_ms,
        ))
    }

    fn ranked_regions(mut candidates: Vec<RankedRelayCandidate>) -> Vec<String> {
        sort_ranked_candidates(&mut candidates);
        candidates.into_iter().map(|c| c.region).collect()
    }

    #[test]
    fn live_ranking_sends_new_sessions_to_the_quieter_twin() {
        // The regression this exists for. mumbai-03 and mumbai-04 sit in the
        // same availability zone, so their latencies are 2ms apart and the sort
        // was deterministic: every client picked mumbai-03, and mumbai-04 took
        // zero traffic for two days while mumbai-03 ran 80% through its bundle.
        let _guard = load_test_guard();
        crate::vpn::servers::set_relay_load_for_test(&[
            ("mumbai-03", Some(60), false),
            ("mumbai-04", Some(0), false),
        ]);

        let order = ranked_regions(vec![
            ranked("mumbai-03", "10.0.0.3", Some(23)),
            ranked("mumbai-04", "10.0.0.4", Some(25)),
        ]);

        assert_eq!(order.first().map(String::as_str), Some("mumbai-04"));
        crate::vpn::servers::clear_relay_load_for_test();
    }

    #[test]
    fn live_ranking_never_trades_a_region_for_occupancy() {
        // An empty box in the wrong country is not a better box. 23ms vs 60ms
        // is far outside the tie band, so latency decides outright.
        let _guard = load_test_guard();
        crate::vpn::servers::set_relay_load_for_test(&[
            ("mumbai-03", Some(90), false),
            ("singapore-04", Some(0), false),
        ]);

        let order = ranked_regions(vec![
            ranked("mumbai-03", "10.0.0.3", Some(23)),
            ranked("singapore-04", "10.0.1.4", Some(60)),
        ]);

        assert_eq!(order.first().map(String::as_str), Some("mumbai-03"));
        crate::vpn::servers::clear_relay_load_for_test();
    }

    #[test]
    fn live_ranking_treats_a_silent_relay_as_full() {
        // mumbai-04 has stopped reporting. Unknown occupancy must rank worst,
        // never best, or a relay becomes most attractive precisely when it has
        // gone wrong.
        let _guard = load_test_guard();
        crate::vpn::servers::set_relay_load_for_test(&[("mumbai-03", Some(40), false)]);

        let order = ranked_regions(vec![
            ranked("mumbai-04", "10.0.0.4", Some(23)),
            ranked("mumbai-03", "10.0.0.3", Some(25)),
        ]);

        assert_eq!(order.first().map(String::as_str), Some("mumbai-03"));
        crate::vpn::servers::clear_relay_load_for_test();
    }

    #[test]
    fn live_ranking_breaks_a_dead_heat_on_cost() {
        // Same speed, same occupancy bucket. The only thing left to separate
        // them is which one bills per gigabyte.
        let _guard = load_test_guard();
        crate::vpn::servers::set_relay_load_for_test(&[
            ("germany-03", Some(2), true),
            ("germany-04", Some(2), false),
        ]);

        let order = ranked_regions(vec![
            ranked("germany-03", "10.1.0.3", Some(30)),
            ranked("germany-04", "10.1.0.4", Some(30)),
        ]);

        assert_eq!(order.first().map(String::as_str), Some("germany-04"));
        crate::vpn::servers::clear_relay_load_for_test();
    }

    #[test]
    fn live_ranking_keeps_probed_candidates_ahead_of_unprobed_ones() {
        // Occupancy must not disturb the existing precedence: once any probe
        // has succeeded, a measured latency outranks a remembered one even when
        // the remembered number looks better.
        let _guard = load_test_guard();
        crate::vpn::servers::set_relay_load_for_test(&[
            ("mumbai-03", Some(0), false),
            ("mumbai-04", Some(60), false),
        ]);

        let mut candidates = vec![
            ranked("mumbai-03", "10.0.0.3", Some(10)),
            ranked("mumbai-04", "10.0.0.4", Some(90)),
        ];
        apply_probe_measurements(
            &mut candidates,
            &[RelayProbeMeasurement {
                region: "mumbai-04".to_string(),
                addr: "10.0.0.4:51820".parse().unwrap(),
                latency_ms: Some(90),
            }],
        );

        sort_ranked_candidates(&mut candidates);
        assert_eq!(candidates[0].region, "mumbai-04");
        crate::vpn::servers::clear_relay_load_for_test();
    }

    #[test]
    fn live_ranking_is_deterministic_without_any_measurement() {
        // Nothing measured and nothing known. The order still has to be stable,
        // or two clients with identical inputs disagree about the fleet.
        let _guard = load_test_guard();
        crate::vpn::servers::clear_relay_load_for_test();

        let order = ranked_regions(vec![
            ranked("mumbai-04", "10.0.0.4", None),
            ranked("mumbai-03", "10.0.0.3", None),
        ]);

        assert_eq!(order, vec!["mumbai-03".to_string(), "mumbai-04".to_string()]);
    }

    #[test]
    fn relay_choice_ignores_candidates_without_a_latency_sample() {
        let candidates = [
            (
                "unmeasured".to_string(),
                "127.0.0.1:51820".parse().unwrap(),
                None,
            ),
            candidate("mumbai", 23),
        ];
        let picked = pick_lowest_latency_server(candidates.iter()).unwrap();
        assert_eq!(picked.0, "mumbai");
    }

    #[test]
    fn relay_choice_returns_none_when_nothing_was_measured() {
        let candidates = [(
            "unmeasured".to_string(),
            "127.0.0.1:51820".parse().unwrap(),
            None,
        )];
        assert!(pick_lowest_latency_server(candidates.iter()).is_none());
    }

    #[test]
    fn test_dead_relay_during_grace_stays_connected_status() {
        let action = classify_relay_health(
            super::super::udp_relay::RelayHealthState::Dead,
            false,
            LocalConnectivity::Unknown,
            false,
        );

        assert_eq!(
            action,
            RelayHealthAction::Continue {
                relay_status: Some("dead".to_string()),
            }
        );
    }

    #[test]
    fn test_dead_relay_after_grace_is_fatal() {
        let action = classify_relay_health(
            super::super::udp_relay::RelayHealthState::Dead,
            false,
            LocalConnectivity::Unknown,
            true,
        );

        match action {
            RelayHealthAction::Fatal {
                error_message,
                cleanup_reason,
            } => {
                assert!(error_message.contains("relay stopped returning traffic"));
                assert_eq!(cleanup_reason, "relay_dead_recovery");
            }
            RelayHealthAction::Continue { .. } => panic!("dead relay must not remain connected"),
        }
    }

    #[test]
    fn test_dead_relay_with_internet_offline_blames_local_network() {
        let action = classify_relay_health(
            super::super::udp_relay::RelayHealthState::Dead,
            false,
            LocalConnectivity::Offline,
            false,
        );

        match action {
            RelayHealthAction::Fatal {
                error_message,
                cleanup_reason,
            } => {
                assert!(
                    error_message.contains("Internet connection lost"),
                    "expected offline message, got: {error_message}"
                );
                assert!(
                    !error_message.contains("choose another relay"),
                    "must not advise picking another relay when device is offline"
                );
                assert_eq!(cleanup_reason, "internet_lost_recovery");
            }
            RelayHealthAction::Continue { .. } => {
                panic!("dead relay must not remain connected even when offline")
            }
        }
    }

    #[test]
    fn test_dead_relay_with_internet_reachable_still_blames_relay() {
        // Negative test for the offline-detection branch: when the OS
        // confirms the device is online, a dead relay must still be
        // surfaced as a relay failure (the user really should pick another
        // relay). This guards against the offline path masking real relay
        // outages.
        let action = classify_relay_health(
            super::super::udp_relay::RelayHealthState::Dead,
            false,
            LocalConnectivity::Reachable,
            true,
        );

        match action {
            RelayHealthAction::Fatal {
                error_message,
                cleanup_reason,
            } => {
                assert!(error_message.contains("relay stopped returning traffic"));
                assert!(error_message.contains("choose another relay"));
                assert_eq!(cleanup_reason, "relay_dead_recovery");
            }
            RelayHealthAction::Continue { .. } => panic!("dead relay must not remain connected"),
        }
    }

    #[test]
    fn test_stale_relay_health_remains_connected_status() {
        let action = classify_relay_health(
            super::super::udp_relay::RelayHealthState::Stale,
            false,
            LocalConnectivity::Unknown,
            false,
        );

        assert_eq!(
            action,
            RelayHealthAction::Continue {
                relay_status: Some("stale".to_string()),
            }
        );
    }

    #[test]
    fn test_stale_relay_health_ignores_offline_hint() {
        // A stale relay must not be escalated to a fatal "internet lost"
        // teardown just because the OS hint happens to read Offline at the
        // probe instant. Only Dead transitions consult the connectivity
        // hint; Stale stays a continue.
        let action = classify_relay_health(
            super::super::udp_relay::RelayHealthState::Stale,
            false,
            LocalConnectivity::Offline,
            false,
        );

        assert_eq!(
            action,
            RelayHealthAction::Continue {
                relay_status: Some("stale".to_string()),
            }
        );
    }

    #[test]
    fn test_no_traffic_yet_relay_health_does_not_trigger_recovery() {
        let action = classify_relay_health(
            super::super::udp_relay::RelayHealthState::NoTrafficYet,
            false,
            LocalConnectivity::Unknown,
            false,
        );

        assert_eq!(action, RelayHealthAction::Continue { relay_status: None });
    }

    #[test]
    fn test_sender_panicked_is_fatal_even_when_relay_health_looks_ok() {
        // A panicked relay sender thread drops every outbound packet, but the
        // keepalive bookkeeping that escalates `relay_health` to `Dead` lags
        // ~60s behind. The monitor must tear the session down immediately on
        // the `sender_panicked` signal instead of waiting for that timeout.
        for health in [
            super::super::udp_relay::RelayHealthState::Healthy,
            super::super::udp_relay::RelayHealthState::NoTrafficYet,
            super::super::udp_relay::RelayHealthState::Stale,
        ] {
            let action = classify_relay_health(health, true, LocalConnectivity::Unknown, false);
            match action {
                RelayHealthAction::Fatal {
                    error_message,
                    cleanup_reason,
                } => {
                    assert!(
                        error_message.contains("outbound relay path failed"),
                        "expected sender-panic message, got: {error_message}"
                    );
                    assert_eq!(cleanup_reason, "relay_sender_panicked");
                }
                RelayHealthAction::Continue { .. } => {
                    panic!("a panicked sender must not remain connected (health={health:?})")
                }
            }
        }
    }

    #[test]
    fn test_sender_panicked_keeps_cleanup_reason_when_relay_also_dead() {
        // Positive race fallback for W1: if the sender failure and relay-dead
        // heuristic are both visible in the same monitor tick, preserve the
        // structured sender-failure cleanup reason instead of masking it as a
        // generic dead relay.
        let action = classify_relay_health(
            super::super::udp_relay::RelayHealthState::Dead,
            true,
            LocalConnectivity::Reachable,
            false,
        );

        match action {
            RelayHealthAction::Fatal {
                error_message,
                cleanup_reason,
            } => {
                assert!(error_message.contains("outbound relay path failed"));
                assert_eq!(cleanup_reason, "relay_sender_panicked");
            }
            RelayHealthAction::Continue { .. } => {
                panic!("a panicked sender must not remain connected even when relay is dead")
            }
        }
    }

    #[test]
    fn test_healthy_relay_without_sender_panic_stays_connected() {
        // Negative companion to the test above: the fatal path must fire only
        // for the actual `sender_panicked` signal, not for an otherwise
        // healthy relay. Guards against the W1 fix over-triggering.
        let action = classify_relay_health(
            super::super::udp_relay::RelayHealthState::Healthy,
            false,
            LocalConnectivity::Unknown,
            false,
        );
        assert_eq!(action, RelayHealthAction::Continue { relay_status: None });
    }

    #[test]
    fn test_worker_panic_error_reader_handle_lost_matches_driver_missing_ui_contract() {
        // `isDriverMissing()` in connectState.ts substring-matches BOTH
        // phrases (case-insensitive) to render the reinstall-driver CTA.
        let (message, cleanup_reason) = worker_panic_error(WorkerPanicCause::ReaderHandleLost);
        let lower = message.to_lowercase();
        assert!(
            lower.contains("split tunnel driver not available"),
            "ReaderHandleLost message must trip isDriverMissing(): {message}"
        );
        assert!(
            lower.contains("windows packet filter driver"),
            "ReaderHandleLost message must trip isDriverMissing(): {message}"
        );
        assert_eq!(cleanup_reason, "workers_panicked_recovery");
    }

    #[test]
    fn test_worker_panic_error_internal_thread_failed_avoids_driver_missing_ui_contract() {
        // An internal thread panic is NOT a missing driver — the message must
        // NOT trip `isDriverMissing()`, so the UI offers a plain reconnect
        // instead of a misleading reinstall-driver prompt.
        let (message, cleanup_reason) = worker_panic_error(WorkerPanicCause::InternalThreadFailed);
        let lower = message.to_lowercase();
        assert!(
            !lower.contains("split tunnel driver not available"),
            "InternalThreadFailed message must not trip isDriverMissing(): {message}"
        );
        assert!(
            !lower.contains("windows packet filter driver"),
            "InternalThreadFailed message must not trip isDriverMissing(): {message}"
        );
        assert_eq!(cleanup_reason, "worker_thread_failed_recovery");
    }

    #[test]
    fn test_worker_panic_cause_u8_round_trips() {
        for cause in [
            WorkerPanicCause::ReaderHandleLost,
            WorkerPanicCause::InternalThreadFailed,
        ] {
            assert_eq!(WorkerPanicCause::from_u8(cause.as_u8()), Some(cause));
        }
        // 0 is the "still running" sentinel and must never decode to a cause.
        assert_eq!(WorkerPanicCause::from_u8(0), None);
        assert_eq!(WorkerPanicCause::from_u8(99), None);
    }

    /// Default relay health for tests where the relay-health gate isn't
    /// the variable under test. `NoTrafficYet` is what the relay reports
    /// during the early connect window before the first inbound packet,
    /// which matches the realistic scenario the watchdog is designed for.
    const TEST_RELAY_NOT_HEALTHY: super::super::udp_relay::RelayHealthState =
        super::super::udp_relay::RelayHealthState::NoTrafficYet;

    #[test]
    fn test_watchdog_continues_on_first_offline_tick() {
        // One offline tick alone must not fire — we only abort on a sustained
        // outage. The counter should bump from 0 to 1 and the caller should
        // store it for next tick.
        let action = watchdog_tick(
            Duration::from_secs(1),
            LocalConnectivity::Offline,
            TEST_RELAY_NOT_HEALTHY,
            0,
        );

        assert_eq!(
            action,
            WatchdogTickAction::Continue {
                consecutive_offline_ticks: 1,
            }
        );
    }

    #[test]
    fn test_watchdog_does_not_fire_on_brief_link_flap() {
        // A brief Offline → Reachable sequence must NOT push the watchdog past
        // its threshold. This covers Wi-Fi handover, momentary route refresh,
        // sleep/resume settle: all transient and should be ignored.
        let after_offline_1 = watchdog_tick(
            Duration::from_secs(1),
            LocalConnectivity::Offline,
            TEST_RELAY_NOT_HEALTHY,
            0,
        );
        let count_after_offline = match after_offline_1 {
            WatchdogTickAction::Continue {
                consecutive_offline_ticks,
            } => consecutive_offline_ticks,
            other => panic!("expected Continue on first offline tick, got {:?}", other),
        };

        let after_offline_2 = watchdog_tick(
            Duration::from_secs(2),
            LocalConnectivity::Offline,
            TEST_RELAY_NOT_HEALTHY,
            count_after_offline,
        );
        let count_after_offline_2 = match after_offline_2 {
            WatchdogTickAction::Continue {
                consecutive_offline_ticks,
            } => consecutive_offline_ticks,
            other => panic!("expected Continue on second offline tick, got {:?}", other),
        };

        // Reachable must reset the counter to zero, not merely continue.
        let after_reachable = watchdog_tick(
            Duration::from_secs(3),
            LocalConnectivity::Reachable,
            TEST_RELAY_NOT_HEALTHY,
            count_after_offline_2,
        );
        assert_eq!(
            after_reachable,
            WatchdogTickAction::Continue {
                consecutive_offline_ticks: 0,
            },
            "Reachable must reset the consecutive-offline counter to zero (got {:?})",
            after_reachable
        );
    }

    #[test]
    fn test_watchdog_fires_on_sustained_offline() {
        // Hit the threshold exactly. The threshold is the number of
        // consecutive Offline ticks required; with the 500ms refresh tick
        // that's 3s sustained — a structured marker that the IPv4 default
        // route really has gone away, not just a flap.
        let mut count = 0u32;
        for tick in 1..ADAPTER_WATCHDOG_OFFLINE_TICK_THRESHOLD {
            let elapsed = Duration::from_millis(500 * tick as u64);
            match watchdog_tick(
                elapsed,
                LocalConnectivity::Offline,
                TEST_RELAY_NOT_HEALTHY,
                count,
            ) {
                WatchdogTickAction::Continue {
                    consecutive_offline_ticks,
                } => count = consecutive_offline_ticks,
                other => panic!(
                    "expected Continue at tick {} (count {}), got {:?}",
                    tick, count, other
                ),
            }
        }

        let final_elapsed =
            Duration::from_millis(500 * ADAPTER_WATCHDOG_OFFLINE_TICK_THRESHOLD as u64);
        let action = watchdog_tick(
            final_elapsed,
            LocalConnectivity::Offline,
            TEST_RELAY_NOT_HEALTHY,
            count,
        );

        match action {
            WatchdogTickAction::Abort {
                error_message,
                cleanup_reason,
            } => {
                assert_eq!(cleanup_reason, ADAPTER_RESET_ROLLBACK_REASON);
                assert!(
                    error_message.contains("rolled back"),
                    "expected user-facing 'rolled back' wording, got: {error_message}"
                );
                assert!(
                    error_message.contains("try connecting again"),
                    "expected retry hint, got: {error_message}"
                );
            }
            other => panic!(
                "expected Abort at threshold (count was about to become {}), got {:?}",
                ADAPTER_WATCHDOG_OFFLINE_TICK_THRESHOLD, other
            ),
        }
    }

    #[test]
    fn test_watchdog_does_not_fire_on_unknown_probe() {
        // `Unknown` is treated as a probe failure (NLM API hung,
        // non-Windows build, hint=Unknown, hint=Hidden), NOT as offline.
        // Mirrors the existing semantic in `classify_relay_health` — a
        // flaky NLM API must not be allowed to abort an otherwise-healthy
        // connect.
        let mut count = 0u32;
        for tick in 1..(ADAPTER_WATCHDOG_OFFLINE_TICK_THRESHOLD * 4) {
            let elapsed = Duration::from_millis(500 * tick as u64);
            match watchdog_tick(
                elapsed,
                LocalConnectivity::Unknown,
                TEST_RELAY_NOT_HEALTHY,
                count,
            ) {
                WatchdogTickAction::Continue {
                    consecutive_offline_ticks,
                } => {
                    assert_eq!(
                        consecutive_offline_ticks, 0,
                        "Unknown probe must keep the counter at 0, got {} at tick {}",
                        consecutive_offline_ticks, tick
                    );
                    count = consecutive_offline_ticks;
                }
                WatchdogTickAction::Disarmed => {
                    // Eventually the window will pass (at 30s) — that's fine,
                    // it just means we ran the loop long enough. The key
                    // assertion is "no Abort variant ever surfaced".
                    return;
                }
                WatchdogTickAction::Abort { .. } => panic!(
                    "Unknown probe must never abort the watchdog (tick {})",
                    tick
                ),
            }
        }
    }

    #[test]
    fn test_watchdog_disarms_after_window_passes() {
        // Even with the counter pre-loaded above threshold, once the window
        // has elapsed the watchdog must return Disarmed and stop firing —
        // mid-session relay-health monitoring takes over.
        let elapsed = Duration::from_secs(ADAPTER_WATCHDOG_WINDOW_SECS);
        let action = watchdog_tick(
            elapsed,
            LocalConnectivity::Offline,
            TEST_RELAY_NOT_HEALTHY,
            ADAPTER_WATCHDOG_OFFLINE_TICK_THRESHOLD + 100,
        );

        assert_eq!(
            action,
            WatchdogTickAction::Disarmed,
            "watchdog must disarm at exactly the window boundary, even if probe is Offline"
        );
    }

    #[test]
    fn test_watchdog_disarms_well_after_window_for_offline_probe() {
        // Negative test paired with the previous one: an Offline probe ten
        // minutes into the session must NOT cause the watchdog to abort.
        // Adapter-reset rollback is a connect-window concept; sustained
        // offlines mid-session are a different problem (handled by the
        // existing relay-health classifier).
        let elapsed = Duration::from_secs(600);
        let action = watchdog_tick(
            elapsed,
            LocalConnectivity::Offline,
            TEST_RELAY_NOT_HEALTHY,
            0,
        );

        assert_eq!(
            action,
            WatchdogTickAction::Disarmed,
            "watchdog must stay disarmed long after the connect window — sustained offline is a different code path"
        );
    }

    #[test]
    fn test_watchdog_reachable_inside_window_resets_counter() {
        // Even if we're 5 ticks into a 6-tick threshold, a single Reachable
        // probe must clear the counter — that's the whole point of
        // requiring *consecutive* offline ticks, not cumulative ones.
        let action = watchdog_tick(
            Duration::from_secs(2),
            LocalConnectivity::Reachable,
            TEST_RELAY_NOT_HEALTHY,
            ADAPTER_WATCHDOG_OFFLINE_TICK_THRESHOLD - 1,
        );

        assert_eq!(
            action,
            WatchdogTickAction::Continue {
                consecutive_offline_ticks: 0,
            }
        );
    }

    #[test]
    fn test_watchdog_does_not_fire_when_relay_is_healthy() {
        // Relay-health gate (Codex P1): NLM Offline alone is a heuristic
        // and can be wrong on captive/filtered networks, virtual-adapter
        // configs, and certain Wi-Fi drivers. `RelayHealthState::Healthy`
        // means we've recently received an inbound packet from the relay
        // — positive ground truth that internet is working through this
        // NIC right now. In that case, even a sustained Offline NLM
        // signal must NOT push the watchdog past threshold.
        use super::super::udp_relay::RelayHealthState;
        let mut count = 0u32;
        for tick in 1..(ADAPTER_WATCHDOG_OFFLINE_TICK_THRESHOLD * 4) {
            let elapsed = Duration::from_millis(500 * tick as u64);
            match watchdog_tick(
                elapsed,
                LocalConnectivity::Offline,
                RelayHealthState::Healthy,
                count,
            ) {
                WatchdogTickAction::Continue {
                    consecutive_offline_ticks,
                } => {
                    assert_eq!(
                        consecutive_offline_ticks, 0,
                        "relay Healthy must keep the counter at 0 even when probe is Offline (tick {}, count {})",
                        tick, consecutive_offline_ticks
                    );
                    count = consecutive_offline_ticks;
                }
                WatchdogTickAction::Disarmed => return,
                WatchdogTickAction::Abort { .. } => panic!(
                    "watchdog must not fire when relay is Healthy (tick {})",
                    tick
                ),
            }
        }
    }

    #[test]
    fn test_watchdog_resets_on_relay_recovery_to_healthy() {
        // Counter sits one short of threshold (relay was Stale, NLM Offline,
        // counter has been climbing). Then the relay flips back to Healthy
        // — internet has recovered through some other path before NLM
        // caught up — the next tick must reset the counter to 0 and not
        // fire. Guards against stale state racing the recovery.
        use super::super::udp_relay::RelayHealthState;
        let action = watchdog_tick(
            Duration::from_secs(2),
            LocalConnectivity::Offline,
            RelayHealthState::Healthy,
            ADAPTER_WATCHDOG_OFFLINE_TICK_THRESHOLD - 1,
        );

        assert_eq!(
            action,
            WatchdogTickAction::Continue {
                consecutive_offline_ticks: 0,
            },
            "relay flipping back to Healthy must reset the offline-tick counter"
        );
    }

    #[test]
    fn test_vpn_connection_default_is_new() {
        let conn = VpnConnection::default();
        let rx = conn.state_handle();
        assert_eq!(*rx.borrow(), ConnectionState::Disconnected);
    }

    #[test]
    fn test_vpn_connection_no_config_initially() {
        let conn = VpnConnection::new();
        assert!(conn.config().is_none());
        assert!(conn.get_config_id().is_none());
    }

    #[test]
    fn test_vpn_connection_split_tunnel_not_active_initially() {
        let conn = VpnConnection::new();
        assert!(!conn.is_split_tunnel_active());
    }

    fn parse_addr(addr: &str) -> SocketAddr {
        addr.parse().expect("invalid test socket addr")
    }

    #[test]
    fn test_resolve_relay_server_exact_match() {
        let available_servers = vec![
            (
                "germany".to_string(),
                parse_addr("10.0.0.1:51821"),
                Some(30),
            ),
            (
                "germany-01".to_string(),
                parse_addr("10.0.0.2:51821"),
                Some(8),
            ),
        ];

        let resolved = resolve_relay_server_for_region("germany", &available_servers, None);
        assert_eq!(
            resolved,
            Some(("germany-01".to_string(), parse_addr("10.0.0.2:51821")))
        );
    }

    #[test]
    fn test_resolve_relay_server_prefix_fallback() {
        let available_servers = vec![
            (
                "germany-01".to_string(),
                parse_addr("10.0.0.11:51821"),
                Some(8),
            ),
            (
                "germany-03".to_string(),
                parse_addr("10.0.0.13:51821"),
                Some(12),
            ),
        ];

        let resolved = resolve_relay_server_for_region("germany", &available_servers, None);
        assert_eq!(
            resolved,
            Some(("germany-01".to_string(), parse_addr("10.0.0.11:51821")))
        );
    }

    #[test]
    fn test_resolve_relay_server_returns_none_when_unavailable() {
        let available_servers = vec![
            (
                "tokyo-01".to_string(),
                parse_addr("10.0.1.1:51821"),
                Some(20),
            ),
            (
                "paris-03".to_string(),
                parse_addr("10.0.1.2:51821"),
                Some(14),
            ),
        ];

        let resolved = resolve_relay_server_for_region("germany", &available_servers, None);
        assert_eq!(resolved, None);
    }

    #[test]
    fn test_resolve_relay_server_prefers_lowest_known_latency() {
        let available_servers = vec![
            ("paris-02".to_string(), parse_addr("10.0.2.2:51821"), None),
            (
                "paris-01".to_string(),
                parse_addr("10.0.2.1:51821"),
                Some(17),
            ),
            (
                "paris-03".to_string(),
                parse_addr("10.0.2.3:51821"),
                Some(9),
            ),
        ];

        let resolved = resolve_relay_server_for_region("paris", &available_servers, None);
        assert_eq!(
            resolved,
            Some(("paris-03".to_string(), parse_addr("10.0.2.3:51821")))
        );
    }

    #[test]
    fn test_resolve_relay_server_forced_server_used() {
        let available_servers = vec![
            (
                "germany-01".to_string(),
                parse_addr("10.0.0.1:51821"),
                Some(5),
            ),
            (
                "germany-02".to_string(),
                parse_addr("10.0.0.2:51821"),
                Some(20),
            ),
            (
                "germany-03".to_string(),
                parse_addr("10.0.0.3:51821"),
                Some(50),
            ),
        ];

        // Force germany-03 even though it has the worst latency
        let resolved =
            resolve_relay_server_for_region("germany", &available_servers, Some("germany-03"));
        assert_eq!(
            resolved,
            Some(("germany-03".to_string(), parse_addr("10.0.0.3:51821")))
        );
    }

    #[test]
    fn test_resolve_relay_server_forced_server_not_found_falls_back() {
        let available_servers = vec![
            (
                "germany-01".to_string(),
                parse_addr("10.0.0.1:51821"),
                Some(5),
            ),
            (
                "germany-02".to_string(),
                parse_addr("10.0.0.2:51821"),
                Some(20),
            ),
        ];

        // Force a server that doesn't exist — should fall back to best latency
        let resolved =
            resolve_relay_server_for_region("germany", &available_servers, Some("germany-99"));
        assert_eq!(
            resolved,
            Some(("germany-01".to_string(), parse_addr("10.0.0.1:51821")))
        );
    }

    #[test]
    fn test_resolved_forced_server_matches_selected_region_pin() {
        let relay_candidates = vec![(
            "germany-02".to_string(),
            parse_addr("10.0.0.2:51821"),
            Some(20),
        )];

        assert_eq!(
            resolved_forced_server(Some("germany-02"), &relay_candidates),
            Some("germany-02".to_string())
        );
    }

    #[test]
    fn test_resolved_forced_server_ignores_stale_pin_after_fallback() {
        let relay_candidates = vec![
            (
                "germany-01".to_string(),
                parse_addr("10.0.0.1:51821"),
                Some(5),
            ),
            (
                "germany-02".to_string(),
                parse_addr("10.0.0.2:51821"),
                Some(20),
            ),
        ];

        assert_eq!(
            resolved_forced_server(Some("germany-99"), &relay_candidates),
            None
        );
    }

    #[test]
    fn test_resolved_forced_server_does_not_treat_unrelated_pin_as_active() {
        let relay_candidates = vec![(
            "germany-02".to_string(),
            parse_addr("10.0.0.2:51821"),
            Some(20),
        )];

        assert_eq!(
            resolved_forced_server(Some("singapore-01"), &relay_candidates),
            None
        );
    }

    #[test]
    fn test_resolve_relay_server_us_region_prefix_matching() {
        // Regression test: US servers use "us-east-nj", "us-west-la" naming.
        // The gaming region IDs are "us-east", "us-west", "us-central".
        // Prefix matching "us-east-" must find "us-east-nj".
        let available_servers = vec![
            (
                "us-east-nj".to_string(),
                parse_addr("108.61.7.6:51821"),
                Some(30),
            ),
            (
                "us-west-la".to_string(),
                parse_addr("45.63.55.139:51821"),
                Some(45),
            ),
            (
                "us-central-dallas".to_string(),
                parse_addr("108.61.205.6:51821"),
                Some(40),
            ),
        ];

        // "us-east" has no exact match -> falls to prefix "us-east-" -> finds "us-east-nj"
        let resolved = resolve_relay_server_for_region("us-east", &available_servers, None);
        assert_eq!(
            resolved,
            Some(("us-east-nj".to_string(), parse_addr("108.61.7.6:51821")))
        );

        let resolved = resolve_relay_server_for_region("us-west", &available_servers, None);
        assert_eq!(
            resolved,
            Some(("us-west-la".to_string(), parse_addr("45.63.55.139:51821")))
        );

        let resolved = resolve_relay_server_for_region("us-central", &available_servers, None);
        assert_eq!(
            resolved,
            Some((
                "us-central-dallas".to_string(),
                parse_addr("108.61.205.6:51821")
            ))
        );
    }

    #[test]
    fn test_resolve_relay_server_legacy_america_finds_nothing() {
        // Documents the bug: "america" as a region name finds no servers
        // in the current API naming scheme.
        let available_servers = vec![
            (
                "us-east-nj".to_string(),
                parse_addr("108.61.7.6:51821"),
                Some(30),
            ),
            (
                "us-west-la".to_string(),
                parse_addr("45.63.55.139:51821"),
                Some(45),
            ),
        ];

        let resolved = resolve_relay_server_for_region("america", &available_servers, None);
        assert_eq!(resolved, None);
    }

    #[test]
    fn test_resolve_relay_server_with_probe_uses_probe_when_latencies_unknown() {
        let available_servers = vec![
            ("germany-01".to_string(), parse_addr("10.0.0.1:51821"), None),
            ("germany-02".to_string(), parse_addr("10.0.0.2:51821"), None),
        ];
        let mut candidates = ranked_candidates_from_raw(relay_candidates_for_region(
            "germany",
            &available_servers,
            None,
        ));
        apply_probe_measurements(
            &mut candidates,
            &[RelayProbeMeasurement {
                region: "germany-02".to_string(),
                addr: parse_addr("10.0.0.2:51821"),
                latency_ms: Some(12),
            }],
        );
        let resolved = resolve_relay_server_from_candidates(&candidates);

        assert_eq!(
            resolved,
            Some(("germany-02".to_string(), parse_addr("10.0.0.2:51821")))
        );
    }

    #[test]
    fn test_resolve_relay_server_with_probe_uses_probe_when_latency_is_incomplete() {
        let available_servers = vec![
            (
                "germany-01".to_string(),
                parse_addr("10.0.0.1:51821"),
                Some(8),
            ),
            ("germany-02".to_string(), parse_addr("10.0.0.2:51821"), None),
        ];
        let mut candidates = ranked_candidates_from_raw(relay_candidates_for_region(
            "germany",
            &available_servers,
            None,
        ));
        apply_probe_measurements(
            &mut candidates,
            &[RelayProbeMeasurement {
                region: "germany-02".to_string(),
                addr: parse_addr("10.0.0.2:51821"),
                latency_ms: Some(5),
            }],
        );
        let resolved = resolve_relay_server_from_candidates(&candidates);

        assert_eq!(
            resolved,
            Some(("germany-02".to_string(), parse_addr("10.0.0.2:51821")))
        );
    }

    #[test]
    fn test_resolve_relay_server_with_probe_skips_probe_when_latencies_complete() {
        let available_servers = vec![
            (
                "germany-01".to_string(),
                parse_addr("10.0.0.1:51821"),
                Some(11),
            ),
            (
                "germany-02".to_string(),
                parse_addr("10.0.0.2:51821"),
                Some(6),
            ),
        ];
        let candidates = ranked_candidates_from_raw(relay_candidates_for_region(
            "germany",
            &available_servers,
            None,
        ));
        let resolved = resolve_relay_server_from_candidates(&candidates);

        assert_eq!(
            resolved,
            Some(("germany-02".to_string(), parse_addr("10.0.0.2:51821")))
        );
    }

    #[test]
    fn test_relay_candidates_for_region_merges_exact_and_sibling_servers() {
        let available_servers = vec![
            (
                "singapore".to_string(),
                parse_addr("10.0.0.1:51821"),
                Some(20),
            ),
            (
                "singapore-02".to_string(),
                parse_addr("10.0.0.2:51821"),
                Some(9),
            ),
            ("tokyo".to_string(), parse_addr("10.0.1.1:51821"), Some(30)),
        ];

        let candidates = relay_candidates_for_region("singapore", &available_servers, None);
        assert_eq!(candidates.len(), 2);
        assert!(
            candidates
                .iter()
                .any(|(region, _, _)| region == "singapore")
        );
        assert!(
            candidates
                .iter()
                .any(|(region, _, _)| region == "singapore-02")
        );
    }

    #[test]
    fn test_resolve_relay_server_prefers_sibling_over_canonical_when_latency_lower() {
        let available_servers = vec![
            (
                "singapore".to_string(),
                parse_addr("10.0.0.1:51821"),
                Some(20),
            ),
            (
                "singapore-02".to_string(),
                parse_addr("10.0.0.2:51821"),
                Some(9),
            ),
        ];

        let resolved = resolve_relay_server_for_region("singapore", &available_servers, None);
        assert_eq!(
            resolved,
            Some(("singapore-02".to_string(), parse_addr("10.0.0.2:51821")))
        );
    }

    #[test]
    fn test_resolve_relay_server_falls_back_to_cached_latency_when_all_probes_fail() {
        let available_servers = vec![
            (
                "germany-01".to_string(),
                parse_addr("10.0.0.1:51821"),
                Some(14),
            ),
            (
                "germany-02".to_string(),
                parse_addr("10.0.0.2:51821"),
                Some(8),
            ),
        ];
        let candidates = ranked_candidates_from_raw(relay_candidates_for_region(
            "germany",
            &available_servers,
            None,
        ));

        let resolved = resolve_relay_server_from_candidates(&candidates);
        assert_eq!(
            resolved,
            Some(("germany-02".to_string(), parse_addr("10.0.0.2:51821")))
        );
    }

    #[test]
    fn test_resolve_relay_server_falls_back_to_deterministic_order_when_no_latency_exists() {
        let available_servers = vec![
            ("germany-02".to_string(), parse_addr("10.0.0.2:51821"), None),
            ("germany-01".to_string(), parse_addr("10.0.0.1:51821"), None),
        ];
        let candidates = ranked_candidates_from_raw(relay_candidates_for_region(
            "germany",
            &available_servers,
            None,
        ));

        let resolved = resolve_relay_server_from_candidates(&candidates);
        assert_eq!(
            resolved,
            Some(("germany-01".to_string(), parse_addr("10.0.0.1:51821")))
        );
    }

    #[test]
    fn test_auto_routing_probe_sample_count_is_five() {
        assert_eq!(AUTO_ROUTING_PING_SAMPLES, 5);
    }

    #[test]
    fn test_average_probe_latency_returns_none_for_empty_samples() {
        assert_eq!(average_probe_latency(&[]), None);
    }

    #[test]
    fn test_average_probe_latency_computes_integer_average() {
        assert_eq!(average_probe_latency(&[10, 20, 30, 40, 50]), Some(30));
    }

    #[test]
    fn test_average_probe_latency_truncates_fractional_values() {
        assert_eq!(average_probe_latency(&[1, 2, 2]), Some(1));
    }

    #[test]
    fn test_relay_ticket_ban_detection_uses_structured_error_only() {
        assert_eq!(
            relay_ticket_ban_reason(&AuthError::UserBanned(": abuse".to_string())),
            Some(": abuse".to_string())
        );
        assert_eq!(
            relay_ticket_ban_reason(&AuthError::ApiError(
                r#"{"error":"user_banned appears in a log","code":"internal_error"}"#.to_string()
            )),
            None
        );
    }

    #[test]
    fn test_select_candidate_after_preflight_prefers_authenticated_candidate() {
        let attempts = vec![
            RelayCandidateAttempt {
                region: "germany-01".to_string(),
                addr: parse_addr("10.0.0.1:51821"),
                authenticated: false,
                policy_known: true,
                auth_required: false,
                preflight_mode: RelayPreflightMode::Legacy,
                queue_full_mode: RelayQueueFullMode::Bypass,
            },
            RelayCandidateAttempt {
                region: "germany-02".to_string(),
                addr: parse_addr("10.0.0.2:51821"),
                authenticated: true,
                policy_known: true,
                auth_required: true,
                preflight_mode: RelayPreflightMode::Legacy,
                queue_full_mode: RelayQueueFullMode::Drop,
            },
            RelayCandidateAttempt {
                region: "germany-03".to_string(),
                addr: parse_addr("10.0.0.3:51821"),
                authenticated: false,
                policy_known: true,
                auth_required: true,
                preflight_mode: RelayPreflightMode::Legacy,
                queue_full_mode: RelayQueueFullMode::Bypass,
            },
        ];

        let selected = select_candidate_after_preflight(&attempts).unwrap();
        assert_eq!(
            selected,
            (
                "germany-02".to_string(),
                parse_addr("10.0.0.2:51821"),
                RelayQueueFullMode::Drop
            )
        );
    }

    #[test]
    fn test_select_candidate_after_preflight_legacy_falls_back_to_first() {
        let attempts = vec![
            RelayCandidateAttempt {
                region: "germany-01".to_string(),
                addr: parse_addr("10.0.0.1:51821"),
                authenticated: false,
                policy_known: true,
                auth_required: false,
                preflight_mode: RelayPreflightMode::Legacy,
                queue_full_mode: RelayQueueFullMode::Bypass,
            },
            RelayCandidateAttempt {
                region: "germany-02".to_string(),
                addr: parse_addr("10.0.0.2:51821"),
                authenticated: false,
                policy_known: true,
                auth_required: false,
                preflight_mode: RelayPreflightMode::Legacy,
                queue_full_mode: RelayQueueFullMode::Drop,
            },
        ];

        let selected = select_candidate_after_preflight(&attempts).unwrap();
        assert_eq!(
            selected,
            (
                "germany-01".to_string(),
                parse_addr("10.0.0.1:51821"),
                RelayQueueFullMode::Bypass
            )
        );
    }

    #[test]
    fn test_select_candidate_after_preflight_enforce_rejects_fallback() {
        let attempts = vec![RelayCandidateAttempt {
            region: "germany-01".to_string(),
            addr: parse_addr("10.0.0.1:51821"),
            authenticated: false,
            policy_known: true,
            auth_required: false,
            preflight_mode: RelayPreflightMode::Enforce,
            queue_full_mode: RelayQueueFullMode::Bypass,
        }];

        let error = select_candidate_after_preflight(&attempts)
            .expect_err("enforced preflight should reject fallback");
        assert_eq!(error, CONNECT_FAIL_PREFLIGHT_ENFORCED);
    }

    #[test]
    fn test_select_candidate_after_preflight_auth_required_rejects_legacy_fallback() {
        let attempts = vec![RelayCandidateAttempt {
            region: "germany-01".to_string(),
            addr: parse_addr("10.0.0.1:51821"),
            authenticated: false,
            policy_known: true,
            auth_required: true,
            preflight_mode: RelayPreflightMode::Legacy,
            queue_full_mode: RelayQueueFullMode::Bypass,
        }];

        let error = select_candidate_after_preflight(&attempts)
            .expect_err("required auth should reject unauthenticated legacy fallback");
        assert_eq!(error, CONNECT_FAIL_AUTH_REQUIRED);
    }

    #[test]
    fn test_select_candidate_after_preflight_strictest_policy_rejects_fallback() {
        let attempts = vec![
            RelayCandidateAttempt {
                region: "germany-01".to_string(),
                addr: parse_addr("10.0.0.1:51821"),
                authenticated: false,
                policy_known: true,
                auth_required: false,
                preflight_mode: RelayPreflightMode::Legacy,
                queue_full_mode: RelayQueueFullMode::Bypass,
            },
            RelayCandidateAttempt {
                region: "germany-02".to_string(),
                addr: parse_addr("10.0.0.2:51821"),
                authenticated: false,
                policy_known: true,
                auth_required: true,
                preflight_mode: RelayPreflightMode::Legacy,
                queue_full_mode: RelayQueueFullMode::Drop,
            },
        ];

        let error = select_candidate_after_preflight(&attempts)
            .expect_err("auth-required candidate should reject unauthenticated fallback");
        assert_eq!(error, CONNECT_FAIL_AUTH_REQUIRED);
    }

    #[test]
    fn test_select_candidate_after_preflight_all_unknown_policy_allows_marked_fallback() {
        let attempts = vec![RelayCandidateAttempt {
            region: "germany-01".to_string(),
            addr: parse_addr("10.0.0.1:51821"),
            authenticated: false,
            policy_known: false,
            auth_required: false,
            preflight_mode: RelayPreflightMode::Legacy,
            queue_full_mode: RelayQueueFullMode::Bypass,
        }];

        let selected = select_candidate_after_preflight(&attempts)
            .expect("unknown policy alone should not block legacy fallback");
        assert_eq!(
            selected,
            (
                "germany-01".to_string(),
                parse_addr("10.0.0.1:51821"),
                RelayQueueFullMode::Bypass
            )
        );
    }

    #[test]
    fn test_select_candidate_after_preflight_auth_policy_beats_unknown_policy() {
        let attempts = vec![
            RelayCandidateAttempt {
                region: "germany-01".to_string(),
                addr: parse_addr("10.0.0.1:51821"),
                authenticated: false,
                policy_known: false,
                auth_required: false,
                preflight_mode: RelayPreflightMode::Legacy,
                queue_full_mode: RelayQueueFullMode::Bypass,
            },
            RelayCandidateAttempt {
                region: "germany-02".to_string(),
                addr: parse_addr("10.0.0.2:51821"),
                authenticated: false,
                policy_known: true,
                auth_required: true,
                preflight_mode: RelayPreflightMode::Legacy,
                queue_full_mode: RelayQueueFullMode::Drop,
            },
        ];

        let error = select_candidate_after_preflight(&attempts)
            .expect_err("structured auth-required policy must still reject fallback");
        assert_eq!(error, CONNECT_FAIL_AUTH_REQUIRED);
    }

    #[test]
    fn test_select_candidate_after_preflight_enforced_policy_beats_unknown_policy() {
        let attempts = vec![
            RelayCandidateAttempt {
                region: "germany-01".to_string(),
                addr: parse_addr("10.0.0.1:51821"),
                authenticated: false,
                policy_known: false,
                auth_required: false,
                preflight_mode: RelayPreflightMode::Legacy,
                queue_full_mode: RelayQueueFullMode::Bypass,
            },
            RelayCandidateAttempt {
                region: "germany-02".to_string(),
                addr: parse_addr("10.0.0.2:51821"),
                authenticated: false,
                policy_known: true,
                auth_required: false,
                preflight_mode: RelayPreflightMode::Enforce,
                queue_full_mode: RelayQueueFullMode::Drop,
            },
        ];

        let error = select_candidate_after_preflight(&attempts)
            .expect_err("structured enforced preflight must still reject fallback");
        assert_eq!(error, CONNECT_FAIL_PREFLIGHT_ENFORCED);
    }
}
