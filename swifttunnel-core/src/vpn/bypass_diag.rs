//! Routing diagnostics for the country-ban bypass modes.
//!
//! Users behind a national block report that the Roblox website will not open,
//! that in-game images and the Esc menu are missing, and that games are slow to
//! load, all while the bypass is switched on. The existing packet logging only
//! fires on the relay path, so the one thing nobody can see is what went
//! **direct** and why — which is exactly where a blocked user's traffic dies.
//!
//! This records one line per distinct destination, both relayed and direct,
//! with the facts needed to settle the open questions:
//!
//! * whether a browser's Roblox connection matched a pinned bootstrap IP (if it
//!   did not, the browser resolved the name itself and the hosts-file pin was
//!   bypassed, which would explain the website failing while the app works)
//! * whether Roblox's own HTTP/3 (UDP/443) asset traffic is being left direct,
//!   which would explain missing thumbnails and menus under a block
//!
//! It is deliberately evidence-gathering only: nothing here changes routing.
//!
//! ## Cost
//!
//! This sits on the per-packet path, so it has to be close to free when idle.
//! The guard is a single relaxed atomic load, and past that the dedupe set is
//! thread-local, so there is no lock and no allocation once a destination has
//! been seen. Output is capped twice over: per thread by the set's own limit,
//! and globally by a line budget, so a long session cannot fill the disk.

use std::cell::RefCell;
use std::collections::HashSet;
use std::net::Ipv4Addr;
use std::sync::atomic::{AtomicBool, AtomicU32, Ordering};

/// Distinct destinations remembered per worker thread before it stops logging.
const PER_THREAD_DESTINATIONS: usize = 192;

/// Total lines the whole session may emit.
///
/// A blocked user reproduces this in under a minute, so a few hundred lines is
/// plenty. The cap is what stops a long session from turning the log into a
/// packet capture.
const GLOBAL_LINE_BUDGET: u32 = 400;

static ENABLED: AtomicBool = AtomicBool::new(false);
static LINES_WRITTEN: AtomicU32 = AtomicU32::new(0);

thread_local! {
    static SEEN: RefCell<HashSet<u64>> = RefCell::new(HashSet::new());
}

/// Which bypass the session is running, for the log header.
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum BypassMode {
    FullCountryBan,
    RouteAssist,
    /// Neither bypass on: gameplay UDP relayed, Roblox TCP left direct. Worth
    /// recording because problems reported here (a missing in-game mic, for
    /// one) are about what gets relayed, and nothing was logging that.
    Plain,
}

impl BypassMode {
    fn label(self) -> &'static str {
        match self {
            BypassMode::FullCountryBan => "full-country-ban",
            BypassMode::RouteAssist => "route-assist",
            BypassMode::Plain => "plain",
        }
    }
}

/// Turn diagnostics on for a session and record which mode it is.
///
/// Every tunnel session records now, not just the bypass modes. The cost is a
/// single relaxed atomic load per packet on the fast path, and the output is
/// capped, so the previous gate bought very little and hid the sessions where
/// the routing questions actually come from.
pub fn begin_session(mode: BypassMode, pinned_ip_count: usize) {
    LINES_WRITTEN.store(0, Ordering::Relaxed);
    ENABLED.store(true, Ordering::Relaxed);
    log::info!(
        "[bypass-diag] session start mode={} pinned_ips={} \
         (recording relay/direct decisions per destination, max {} lines)",
        mode.label(),
        pinned_ip_count,
        GLOBAL_LINE_BUDGET
    );
}

pub fn end_session() {
    if ENABLED.swap(false, Ordering::Relaxed) {
        log::info!(
            "[bypass-diag] session end, {} decision lines recorded",
            LINES_WRITTEN.load(Ordering::Relaxed)
        );
    }
}

#[inline(always)]
pub fn is_enabled() -> bool {
    ENABLED.load(Ordering::Relaxed)
}

/// Everything known about one routing decision.
pub struct Decision<'a> {
    pub dst_ip: Ipv4Addr,
    pub dst_port: u16,
    pub protocol: &'a str,
    pub relayed: bool,
    /// Process that owns the socket, when it could be resolved.
    pub owner: Option<&'a str>,
    pub owner_is_tunnel_app: bool,
    pub owner_is_browser: bool,
    /// Destination matched an IP SwiftTunnel resolved and pinned in the hosts
    /// file. A browser connection that misses this resolved the name itself.
    pub matched_bootstrap_pin: bool,
    /// Destination is inside the hardcoded Roblox game-server ranges. Roblox's
    /// website is fronted by Cloudflare and is deliberately not in them.
    pub in_roblox_ranges: bool,
    /// Destination was explicitly pinned to stay direct.
    pub pinned_direct: bool,
}

/// Record one decision, at most once per destination per thread.
#[inline]
pub fn record(decision: Decision<'_>) {
    if !is_enabled() {
        return;
    }
    if LINES_WRITTEN.load(Ordering::Relaxed) >= GLOBAL_LINE_BUDGET {
        return;
    }

    let key = key_for(
        decision.dst_ip,
        decision.dst_port,
        decision.protocol,
        decision.relayed,
    );

    let is_new = SEEN.with(|seen| {
        let Ok(mut seen) = seen.try_borrow_mut() else {
            return false;
        };
        if seen.len() >= PER_THREAD_DESTINATIONS {
            return false;
        }
        seen.insert(key)
    });
    if !is_new {
        return;
    }

    // Claim a line before writing so concurrent workers cannot overshoot.
    if LINES_WRITTEN.fetch_add(1, Ordering::Relaxed) >= GLOBAL_LINE_BUDGET {
        return;
    }

    log::info!(
        "[bypass-diag] {} {}:{} proto={} owner={} tunnel_app={} browser={} \
         pin_match={} roblox_range={} pinned_direct={}",
        if decision.relayed { "RELAY " } else { "DIRECT" },
        decision.dst_ip,
        decision.dst_port,
        decision.protocol,
        decision.owner.unwrap_or("unknown"),
        decision.owner_is_tunnel_app,
        decision.owner_is_browser,
        decision.matched_bootstrap_pin,
        decision.in_roblox_ranges,
        decision.pinned_direct,
    );
}

fn key_for(ip: Ipv4Addr, port: u16, protocol: &str, relayed: bool) -> u64 {
    let ip = u32::from(ip) as u64;
    let proto = protocol.as_bytes().first().copied().unwrap_or(0) as u64;
    (ip << 32) | ((port as u64) << 16) | (proto << 8) | (relayed as u64)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{Mutex, MutexGuard};

    /// The counters are process-global, so these cases cannot run in parallel
    /// with each other. Serialise them and reset the shared state on entry.
    static TEST_LOCK: Mutex<()> = Mutex::new(());

    fn isolated() -> MutexGuard<'static, ()> {
        let guard = TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        LINES_WRITTEN.store(0, Ordering::Relaxed);
        SEEN.with(|s| s.borrow_mut().clear());
        guard
    }

    fn sample(relayed: bool) -> Decision<'static> {
        Decision {
            dst_ip: Ipv4Addr::new(104, 18, 2, 63),
            dst_port: 443,
            protocol: "tcp",
            relayed,
            owner: Some("chrome.exe"),
            owner_is_tunnel_app: false,
            owner_is_browser: true,
            matched_bootstrap_pin: false,
            in_roblox_ranges: false,
            pinned_direct: false,
        }
    }

    #[test]
    fn records_nothing_while_disabled() {
        let _guard = isolated();
        ENABLED.store(false, Ordering::Relaxed);

        record(sample(false));

        assert_eq!(LINES_WRITTEN.load(Ordering::Relaxed), 0);
    }

    #[test]
    fn logs_a_destination_once_per_outcome() {
        let _guard = isolated();
        ENABLED.store(true, Ordering::Relaxed);

        record(sample(false));
        record(sample(false));
        record(sample(false));
        assert_eq!(
            LINES_WRITTEN.load(Ordering::Relaxed),
            1,
            "repeats suppressed"
        );

        // The same destination flipping to relayed is a different fact and is
        // worth a second line: it is how a mid-session demotion shows up.
        record(sample(true));
        assert_eq!(LINES_WRITTEN.load(Ordering::Relaxed), 2);

        ENABLED.store(false, Ordering::Relaxed);
    }

    #[test]
    fn stops_at_the_line_budget() {
        let _guard = isolated();
        ENABLED.store(true, Ordering::Relaxed);

        for octet in 0..255u8 {
            let mut d = sample(false);
            d.dst_ip = Ipv4Addr::new(10, 0, 0, octet);
            record(d);
        }

        let written = LINES_WRITTEN.load(Ordering::Relaxed);
        assert!(written <= GLOBAL_LINE_BUDGET, "budget respected: {written}");
        // The per-thread destination cap bites first here, which is the point:
        // one worker cannot monopolise the budget.
        assert!(
            written as usize <= PER_THREAD_DESTINATIONS,
            "per-thread cap respected: {written}"
        );

        ENABLED.store(false, Ordering::Relaxed);
    }

    #[test]
    fn distinguishes_protocol_and_port() {
        let _guard = isolated();
        ENABLED.store(true, Ordering::Relaxed);

        let mut tcp = sample(false);
        tcp.protocol = "tcp";
        record(tcp);

        // UDP/443 to the same address is the HTTP/3 case and must not be
        // collapsed into the TCP line.
        let mut udp = sample(false);
        udp.protocol = "udp";
        record(udp);

        assert_eq!(LINES_WRITTEN.load(Ordering::Relaxed), 2);
        ENABLED.store(false, Ordering::Relaxed);
    }
}
