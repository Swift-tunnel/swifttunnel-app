//! Lock-Free Process Cache - RCU-style read-copy-update pattern
//!
//! Achieves <0.1ms lookup latency by eliminating locks entirely:
//! - Single writer thread creates new snapshots atomically
//! - Multiple reader threads access snapshots without any locks
//! - Uses arc-swap for safe atomic Arc operations (NO use-after-free!)
//!
//! BSOD FIX (v0.7.2): Replaced unsafe AtomicPtr with arc-swap crate.
//! The old implementation had a race condition where the writer could
//! free memory while readers were still accessing it, causing
//! IRQL_NOT_LESS_OR_EQUAL kernel crashes.
//!
//! V2 ROUTING (v0.7.3): Added ExitLag-style hybrid routing that checks
//! both process ownership AND destination IP ranges.

use super::process_tracker::{ConnectionKey, Protocol, TrackerStats};
use crate::process_names::process_name_matches_any_tunnel_app;
use ahash::{AHashMap, AHashSet};
use arc_swap::ArcSwap;
use parking_lot::Mutex;
use std::collections::{HashMap, HashSet};
use std::net::Ipv4Addr;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

// ============================================================================
// GAME SERVER IP RANGES (for V2 hybrid routing)
// ============================================================================

/// Roblox game server IP ranges - Complete list from AS22697/AS11281
///
/// Sources:
/// - https://devforum.roblox.com/t/all-of-robloxs-ip-ranges-ipv4-ipv6-2023/2527578
/// - https://devforum.roblox.com/t/roblox-server-region-a-list-of-roblox-ip-ranges/3094401
/// - BGP data from bgp.he.net for AS22697
///
/// Note: 128.116.0.0/17 covers ALL regional game servers worldwide.
/// The other ranges are for secondary servers and China (Luobu).
const ROBLOX_RANGES: &[(u32, u32, u32)] = &[
    // ============ PRIMARY GAME SERVERS ============
    // This single /17 covers ALL regional game servers:
    // NA: Seattle, LA, San Jose, Dallas, Chicago, Atlanta, Miami, Ashburn, NYC, Portland
    // EU: London, Frankfurt, Amsterdam, Paris, Warsaw
    // APAC: Singapore, Tokyo, Hong Kong, Mumbai, Sydney
    // SA: São Paulo
    (0x80740000, 0xFFFF8000, 17), // 128.116.0.0/17
    // ============ SECONDARY GAME SERVERS ============
    // San Jose/Palo Alto secondary servers
    (0xD1CE2800, 0xFFFFF800, 21), // 209.206.40.0/21
    // ============ ASIA-PACIFIC ============
    (0x678C1C00, 0xFFFFFE00, 23), // 103.140.28.0/23 - APAC servers
    // ============ CHINA (LUOBU) ============
    (0x678EDC00, 0xFFFFFE00, 23), // 103.142.220.0/23 - Luobu China
    // ============ API/MATCHMAKING ============
    // These handle authentication, matchmaking, and game joining
    (0x17ADC000, 0xFFFFFF00, 24), // 23.173.192.0/24
    (0x8DC10300, 0xFFFFFF00, 24), // 141.193.3.0/24
    (0xCDC93E00, 0xFFFFFF00, 24), // 205.201.62.0/24
    // ============ INFRASTRUCTURE ============
    (0xCC09B800, 0xFFFFFF00, 24), // 204.9.184.0/24
    (0xCC0DA800, 0xFFFFFC00, 22), // 204.13.168.0/22 (covers .168-.171)
    (0xCC0DAC00, 0xFFFFFE00, 23), // 204.13.172.0/23 (covers .172-.173)
];

/// Validate that a mask is a valid CIDR mask for the given prefix length
/// A valid CIDR mask has all 1s on the left and all 0s on the right
#[inline(always)]
const fn is_valid_cidr_mask(mask: u32, prefix: u32) -> bool {
    if prefix > 32 {
        return false;
    }
    if prefix == 0 {
        return mask == 0;
    }
    let expected = !0u32 << (32 - prefix);
    mask == expected
}

// Compile-time validation of ROBLOX_RANGES masks
// This ensures all hardcoded masks are valid CIDR masks
// Uses ROBLOX_RANGES directly to avoid duplication and ensure all entries are validated
const _: () = {
    let mut i = 0;
    while i < ROBLOX_RANGES.len() {
        let (_network, mask, prefix) = ROBLOX_RANGES[i];
        assert!(
            is_valid_cidr_mask(mask, prefix),
            "Invalid CIDR mask in ROBLOX_RANGES"
        );
        i += 1;
    }
};

/// Check if an IP address is within a CIDR range
#[inline(always)]
fn ip_in_range(ip: Ipv4Addr, network: u32, mask: u32) -> bool {
    let ip_u32 = u32::from(ip);
    (ip_u32 & mask) == (network & mask)
}

/// Check if destination is a Roblox game server
/// Returns true if:
/// - IP is in known Roblox server ranges
/// - Protocol is UDP
#[inline(always)]
pub fn is_roblox_game_server(
    dst_ip: Ipv4Addr,
    _dst_port: u16,
    protocol: Protocol,
    api_tunneling: bool,
) -> bool {
    match protocol {
        Protocol::Udp => {}
        Protocol::Tcp if api_tunneling => {}
        _ => return false,
    }

    // Check IP ranges
    for &(network, mask, _prefix) in ROBLOX_RANGES {
        if ip_in_range(dst_ip, network, mask) {
            return true;
        }
    }

    false
}

/// Check if traffic is likely game traffic (FULLY PERMISSIVE for trusted processes)
///
/// This is used when we KNOW the packet is from a Roblox process.
/// We trust the process detection and tunnel ALL UDP traffic from it.
///
/// This fixes Error 277/279 issues where initial STUN traffic (port 3478)
/// or other UDP traffic to non-standard ports was being bypassed, causing
/// the game connection to fail.
///
/// UDP from Roblox includes:
/// - Game server traffic (ports 49152-65535)
/// - STUN for NAT traversal (port 3478)
/// - Voice chat
/// - Any other UDP the game needs
#[inline(always)]
pub fn is_likely_game_traffic(_dst_port: u16, protocol: Protocol, api_tunneling: bool) -> bool {
    match protocol {
        Protocol::Udp => true,
        Protocol::Tcp => api_tunneling,
        _ => false,
    }
}

/// Check if destination is any known game server (extensible for future games)
#[inline(always)]
pub fn is_game_server(
    dst_ip: Ipv4Addr,
    dst_port: u16,
    protocol: Protocol,
    api_tunneling: bool,
) -> bool {
    // SwiftTunnel currently supports Roblox process routing only.
    is_roblox_game_server(dst_ip, dst_port, protocol, api_tunneling)
}

// ============================================================================
// ON-DEMAND PID LOOKUP (for first-packet guarantee)
// ============================================================================

/// Get process name by PID using Windows API
///
/// Uses K32GetProcessImageFileNameW for fast process name lookup.
/// This is called when on-demand PID lookup succeeds but the PID isn't
/// in the cached snapshot (stale snapshot race condition).
#[cfg(windows)]
fn get_process_name_by_pid_fast(pid: u32) -> Option<String> {
    use windows::Win32::Foundation::{CloseHandle, HANDLE};
    use windows::Win32::System::ProcessStatus::K32GetProcessImageFileNameW;
    use windows::Win32::System::Threading::{OpenProcess, PROCESS_QUERY_LIMITED_INFORMATION};

    unsafe {
        // Open process with minimal permissions
        let handle = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, false, pid).ok()?;

        if handle.is_invalid() {
            return None;
        }

        // Get process image file name (NT path like \Device\HarddiskVolume3\...\RobloxPlayerBeta.exe)
        let mut buffer = [0u16; 512];
        let len = K32GetProcessImageFileNameW(handle, &mut buffer);

        let _ = CloseHandle(handle);

        if len == 0 {
            return None;
        }

        let path = String::from_utf16_lossy(&buffer[..len as usize]);

        // Extract just the filename from the full path
        path.rsplit('\\').next().map(|s| s.to_string())
    }
}

#[cfg(not(windows))]
fn get_process_name_by_pid_fast(_pid: u32) -> Option<String> {
    None
}

/// Immutable snapshot of process state
///
/// Once created, this is NEVER modified. Readers can safely access
/// without any synchronization. New snapshots replace old ones atomically.
#[derive(Clone)]
pub struct ProcessSnapshot {
    /// Connection cache: (local_ip, local_port, protocol) → PID
    /// Uses ahash for faster lookups on the packet hot path (~2-5x vs SipHash)
    pub connections: AHashMap<ConnectionKey, u32>,
    /// PID → process name (lowercase)
    pub pid_names: AHashMap<u32, String>,
    /// Apps that should be tunneled (lowercase)
    pub tunnel_apps: AHashSet<String>,
    /// PIDs that belong to a tunnel app (precomputed from `pid_names` + `tunnel_apps`)
    pub tunnel_pids: AHashSet<u32>,
    /// UDP local ports explicitly marked as tunnel-owned.
    pub explicit_tunnel_udp_ports: AHashSet<u16>,
    /// TCP local ports explicitly marked as tunnel-owned (for API tunneling).
    ///
    /// When API tunneling is enabled, TCP ports belonging to Roblox processes
    /// are registered here so they persist across snapshot refreshes and
    /// don't rely on stale connection-table lookups.
    pub explicit_tunnel_tcp_ports: AHashSet<u16>,
    /// UDP source ports owned by tunnel processes, including explicitly pinned ports.
    pub tunnel_udp_ports: AHashSet<u16>,
    /// TCP source ports currently owned by tunnel processes.
    pub tunnel_tcp_ports: AHashSet<u16>,
    /// Snapshot version (monotonically increasing)
    pub version: u64,
    /// Timestamp when snapshot was created
    pub created_at: std::time::Instant,
}

impl ProcessSnapshot {
    fn compute_tunnel_pids(
        pid_names: &AHashMap<u32, String>,
        tunnel_apps: &AHashSet<String>,
    ) -> AHashSet<u32> {
        let mut tunnel_pids = AHashSet::new();

        for (&pid, name) in pid_names {
            if process_name_matches_any_tunnel_app(name, tunnel_apps) {
                tunnel_pids.insert(pid);
            }
        }

        tunnel_pids
    }

    fn compute_tunnel_ports(
        connections: &AHashMap<ConnectionKey, u32>,
        tunnel_pids: &AHashSet<u32>,
        explicit_tunnel_udp_ports: &AHashSet<u16>,
        explicit_tunnel_tcp_ports: &AHashSet<u16>,
    ) -> (AHashSet<u16>, AHashSet<u16>) {
        let mut tunnel_udp_ports = explicit_tunnel_udp_ports.clone();
        let mut tunnel_tcp_ports = explicit_tunnel_tcp_ports.clone();

        for (key, pid) in connections {
            if !tunnel_pids.contains(pid) {
                continue;
            }

            match key.protocol {
                Protocol::Udp => {
                    tunnel_udp_ports.insert(key.local_port);
                }
                Protocol::Tcp => {
                    tunnel_tcp_ports.insert(key.local_port);
                }
            }
        }

        (tunnel_udp_ports, tunnel_tcp_ports)
    }

    /// Create empty snapshot
    pub fn empty(tunnel_apps: AHashSet<String>) -> Self {
        Self {
            connections: AHashMap::new(),
            pid_names: AHashMap::new(),
            tunnel_apps,
            tunnel_pids: AHashSet::new(),
            explicit_tunnel_udp_ports: AHashSet::new(),
            explicit_tunnel_tcp_ports: AHashSet::new(),
            tunnel_udp_ports: AHashSet::new(),
            tunnel_tcp_ports: AHashSet::new(),
            version: 0,
            created_at: std::time::Instant::now(),
        }
    }

    /// Check if connection should be tunneled (no locks!)
    ///
    /// V1 Mode: Process-based only
    ///   - Tunnel if source process is a tunnel app
    ///
    /// V2 Mode: Hybrid (ExitLag-style)
    ///   - Tunnel if source process is a tunnel app
    ///   - AND destination is a known game server IP
    ///   - AND protocol is UDP
    #[inline(always)]
    pub fn should_tunnel(&self, local_ip: Ipv4Addr, local_port: u16, protocol: Protocol) -> bool {
        // V1 mode: just check process (original behavior)
        self.is_tunnel_connection(local_ip, local_port, protocol)
    }

    /// Fallback check for tunnel ownership by source port.
    ///
    /// This is a miss-path helper used when exact `(ip, port, protocol)` cache lookup
    /// fails but we still want to recover tunnel routing for packets emitted by a
    /// known tunnel app that may have shifted local IP representation.
    #[inline]
    pub fn should_tunnel_by_port_fallback(
        &self,
        local_port: u16,
        protocol: Protocol,
        api_tunneling: bool,
    ) -> bool {
        match protocol {
            Protocol::Udp => self.tunnel_udp_ports.contains(&local_port),
            Protocol::Tcp => api_tunneling && self.tunnel_tcp_ports.contains(&local_port),
        }
    }

    /// Check if connection should be tunneled with destination info
    ///
    /// PERMISSIVE MODE (v0.9.5):
    /// - If process IS a tunnel app → use permissive check (all UDP)
    /// - If process is NOT detected → use strict check (known IP ranges + port)
    ///
    /// This fixes the "zero traffic" bug where Roblox connects to servers
    /// on new IPs that aren't in our hardcoded list yet.
    #[inline(always)]
    pub fn should_tunnel_v2(
        &self,
        local_ip: Ipv4Addr,
        local_port: u16,
        protocol: Protocol,
        dst_ip: Ipv4Addr,
        dst_port: u16,
        api_tunneling: bool,
    ) -> bool {
        // First check: Is this from a tunnel app?
        let is_tunnel_app = self.is_tunnel_connection(local_ip, local_port, protocol);

        // If we KNOW it's a tunnel app, trust it and tunnel its UDP traffic
        // even if the destination IP isn't in our known list.
        // This handles new Roblox server deployments gracefully.
        if is_tunnel_app {
            return is_likely_game_traffic(dst_port, protocol, api_tunneling);
        }

        // Process not detected - use strict IP range check for speculative tunneling.
        // This remains UDP-only. TCP API tunneling must be tied to a detected
        // tunnel process or a tunnel-owned source port, otherwise arbitrary
        // Roblox web traffic from other apps can be routed through the relay.
        protocol == Protocol::Udp && is_game_server(dst_ip, dst_port, protocol, api_tunneling)
    }

    /// Check if connection belongs to a tunnel app (internal helper)
    ///
    /// Checks the process cache for PID ownership. Does NOT perform
    /// expensive on-demand IP Helper API lookups (GetExtendedTcpTable/UdpTable)
    /// as those can block and cause system freezes when combined with
    /// ndisapi packet interception. Instead, relies on speculative tunneling
    /// via destination IP matching for first packets.
    #[inline(always)]
    fn is_tunnel_connection(
        &self,
        local_ip: Ipv4Addr,
        local_port: u16,
        protocol: Protocol,
    ) -> bool {
        // Direct lookup - O(1) average case
        let key = ConnectionKey::new(local_ip, local_port, protocol);

        if let Some(&pid) = self.connections.get(&key) {
            return self.is_tunnel_pid(pid);
        }

        // Check 0.0.0.0 binding fallback
        if local_ip != Ipv4Addr::UNSPECIFIED {
            let any_key = ConnectionKey::new(Ipv4Addr::UNSPECIFIED, local_port, protocol);
            if let Some(&pid) = self.connections.get(&any_key) {
                return self.is_tunnel_pid(pid);
            }
        }

        // Not in cache - let speculative tunneling (destination IP matching) handle it
        false
    }

    /// Check if PID belongs to tunnel app (internal)
    ///
    /// PERFORMANCE: Names are pre-lowercased at insertion time, so this is
    /// allocation-free. Critical for 100K+ packets/second throughput.
    #[inline(always)]
    fn is_tunnel_pid(&self, pid: u32) -> bool {
        self.is_tunnel_pid_impl(pid)
    }

    /// Check if PID belongs to tunnel app (public, for inline lookups)
    #[inline(always)]
    pub fn is_tunnel_pid_public(&self, pid: u32) -> bool {
        self.is_tunnel_pid_impl(pid)
    }

    /// Implementation of PID tunnel check
    #[inline(always)]
    fn is_tunnel_pid_impl(&self, pid: u32) -> bool {
        self.tunnel_pids.contains(&pid)
    }

    /// Get PID for connection (for debugging)
    #[inline]
    pub fn get_pid(&self, local_ip: Ipv4Addr, local_port: u16, protocol: Protocol) -> Option<u32> {
        let key = ConnectionKey::new(local_ip, local_port, protocol);
        self.connections.get(&key).copied()
    }

    /// Get process name for PID
    #[inline]
    pub fn get_process_name(&self, pid: u32) -> Option<&str> {
        self.pid_names.get(&pid).map(|s| s.as_str())
    }

    /// Check whether the snapshot already has at least one cached endpoint for a PID.
    #[inline]
    pub fn has_connection_for_pid(&self, pid: u32) -> bool {
        // O(n) over tracked connections. Acceptable here because ETW readiness polling
        // runs on a tiny set of launch events, not on the packet hot path.
        self.connections.values().any(|owner_pid| *owner_pid == pid)
    }

    /// Get stats
    pub fn stats(&self) -> TrackerStats {
        TrackerStats {
            tcp_connections: self
                .connections
                .keys()
                .filter(|k| k.protocol == Protocol::Tcp)
                .count(),
            udp_connections: self
                .connections
                .keys()
                .filter(|k| k.protocol == Protocol::Udp)
                .count(),
            stale_connections: 0, // No stale in snapshot
            tracked_pids: self.pid_names.len(),
        }
    }
}

/// Lock-free process cache using RCU pattern with arc-swap
///
/// SAFETY: Uses arc-swap crate which provides correct hazard pointer
/// implementation. Old snapshots are only freed when ALL readers have
/// released their references (via Arc refcount).
///
/// Key insight: We can have ONE writer and MANY readers without any locks
/// by using atomic Arc swap. Readers grab a reference to the current
/// snapshot and use it for their entire operation. Writer creates a new
/// snapshot and atomically swaps the pointer.
pub struct LockFreeProcessCache {
    /// Current snapshot (atomically swapped via arc-swap)
    /// arc-swap handles all the unsafe pointer magic correctly
    current: ArcSwap<ProcessSnapshot>,
    /// Snapshot version counter
    version: AtomicU64,
    /// Apps to tunnel
    tunnel_apps: AHashSet<String>,
    /// Serializes snapshot writers so immediate registrations cannot publish
    /// stale connection data over a fresher cache refresh.
    snapshot_write_lock: Mutex<()>,
    /// UDP ports explicitly registered as tunnel-owned.
    explicit_tunnel_udp_ports: Mutex<AHashSet<u16>>,
    /// TCP ports explicitly registered as tunnel-owned (API tunneling).
    explicit_tunnel_tcp_ports: Mutex<AHashSet<u16>>,
    /// Last time each API-tunnel TCP port was observed in the owner table.
    explicit_tunnel_tcp_port_last_seen: Mutex<AHashMap<u16, Instant>>,
}

impl LockFreeProcessCache {
    fn clone_explicit_ports(&self) -> (AHashSet<u16>, AHashSet<u16>) {
        let explicit_tunnel_udp_ports = self.explicit_tunnel_udp_ports.lock().clone();
        let explicit_tunnel_tcp_ports = self.explicit_tunnel_tcp_ports.lock().clone();
        (explicit_tunnel_udp_ports, explicit_tunnel_tcp_ports)
    }

    fn snapshot_from_parts(
        &self,
        connections: AHashMap<ConnectionKey, u32>,
        pid_names: AHashMap<u32, String>,
        version: u64,
        explicit_tunnel_udp_ports: AHashSet<u16>,
        explicit_tunnel_tcp_ports: AHashSet<u16>,
    ) -> Arc<ProcessSnapshot> {
        let pid_names_lower: AHashMap<u32, String> = pid_names
            .into_iter()
            .map(|(k, v)| (k, v.to_lowercase()))
            .collect();

        let tunnel_pids = ProcessSnapshot::compute_tunnel_pids(&pid_names_lower, &self.tunnel_apps);
        let (tunnel_udp_ports, tunnel_tcp_ports) = ProcessSnapshot::compute_tunnel_ports(
            &connections,
            &tunnel_pids,
            &explicit_tunnel_udp_ports,
            &explicit_tunnel_tcp_ports,
        );

        Arc::new(ProcessSnapshot {
            connections,
            pid_names: pid_names_lower,
            tunnel_apps: self.tunnel_apps.clone(),
            tunnel_pids,
            explicit_tunnel_udp_ports,
            explicit_tunnel_tcp_ports,
            tunnel_udp_ports,
            tunnel_tcp_ports,
            version,
            created_at: std::time::Instant::now(),
        })
    }

    /// Create new lock-free cache
    pub fn new(tunnel_apps: Vec<String>) -> Self {
        let apps: AHashSet<String> = tunnel_apps.into_iter().map(|s| s.to_lowercase()).collect();
        let initial = Arc::new(ProcessSnapshot::empty(apps.clone()));

        Self {
            current: ArcSwap::from(initial),
            version: AtomicU64::new(0),
            tunnel_apps: apps,
            snapshot_write_lock: Mutex::new(()),
            explicit_tunnel_udp_ports: Mutex::new(AHashSet::new()),
            explicit_tunnel_tcp_ports: Mutex::new(AHashSet::new()),
            explicit_tunnel_tcp_port_last_seen: Mutex::new(AHashMap::new()),
        }
    }

    /// Get current snapshot (lock-free!)
    ///
    /// This is the hot path called by packet workers. It must be as fast as possible.
    /// Returns an Arc reference that the caller can use without any synchronization.
    ///
    /// SAFETY: arc-swap's load_full() safely clones the Arc, incrementing the
    /// refcount atomically. The old snapshot won't be freed until all Arcs are
    /// dropped, eliminating the use-after-free bug that caused BSOD.
    #[inline(always)]
    pub fn get_snapshot(&self) -> Arc<ProcessSnapshot> {
        self.current.load_full()
    }

    /// Update snapshot (called by single writer thread)
    ///
    /// Creates a new snapshot and atomically swaps it in. Old snapshot
    /// is deallocated when all readers release their Arc references.
    ///
    /// PERFORMANCE: Pre-lowercases all process names at insertion time,
    /// eliminating string allocation from the hot path (is_tunnel_pid).
    ///
    /// SAFETY: arc-swap's store() handles the atomic swap correctly.
    /// The old Arc is returned and dropped, decrementing its refcount.
    /// Memory is only freed when refcount reaches zero (all readers done).
    pub fn update(
        &self,
        connections: AHashMap<ConnectionKey, u32>,
        pid_names: AHashMap<u32, String>,
    ) {
        let _snapshot_write_guard = self.snapshot_write_lock.lock();
        let version = self.version.fetch_add(1, Ordering::Relaxed) + 1;
        let (explicit_tunnel_udp_ports, explicit_tunnel_tcp_ports) = self.clone_explicit_ports();
        let new_snapshot = self.snapshot_from_parts(
            connections,
            pid_names,
            version,
            explicit_tunnel_udp_ports,
            explicit_tunnel_tcp_ports,
        );

        // Atomically swap in new snapshot - arc-swap handles cleanup safely
        self.current.store(new_snapshot);
    }

    /// Update snapshot and explicit API TCP ports in a single publication.
    ///
    /// The cache refresher uses this when API tunneling is enabled so packet
    /// workers never observe a new connection table without the matching
    /// tunnel-owned TCP source ports.
    pub fn update_with_tcp_ports(
        &self,
        connections: AHashMap<ConnectionKey, u32>,
        pid_names: AHashMap<u32, String>,
        tcp_ports: &[u16],
    ) {
        let _snapshot_write_guard = self.snapshot_write_lock.lock();
        let explicit_tunnel_tcp_ports = self.replace_explicit_tcp_ports_locked(tcp_ports);
        let version = self.version.fetch_add(1, Ordering::Relaxed) + 1;
        let explicit_tunnel_udp_ports = self.explicit_tunnel_udp_ports.lock().clone();
        let new_snapshot = self.snapshot_from_parts(
            connections,
            pid_names,
            version,
            explicit_tunnel_udp_ports,
            explicit_tunnel_tcp_ports,
        );

        self.current.store(new_snapshot);
    }

    /// Update snapshot while retaining recently observed API TCP source ports.
    ///
    /// Roblox teleport/API TCP connections can be short-lived enough to appear
    /// in one owner-table sample and disappear in the next. Keeping a small
    /// grace set prevents one missed sample from breaking the rest of the flow.
    pub fn update_with_recent_tcp_ports(
        &self,
        connections: AHashMap<ConnectionKey, u32>,
        pid_names: AHashMap<u32, String>,
        tcp_ports: &[u16],
        retain_for: Duration,
    ) {
        let _snapshot_write_guard = self.snapshot_write_lock.lock();
        let explicit_tunnel_tcp_ports =
            self.retain_recent_explicit_tcp_ports_locked(tcp_ports, retain_for);
        let version = self.version.fetch_add(1, Ordering::Relaxed) + 1;
        let explicit_tunnel_udp_ports = self.explicit_tunnel_udp_ports.lock().clone();
        let new_snapshot = self.snapshot_from_parts(
            connections,
            pid_names,
            version,
            explicit_tunnel_udp_ports,
            explicit_tunnel_tcp_ports,
        );

        self.current.store(new_snapshot);
    }

    /// Update tunnel apps list and immediately refresh the snapshot
    ///
    /// CRITICAL: This must create a new snapshot immediately, otherwise workers
    /// will continue using the old snapshot with empty tunnel_apps!
    pub fn set_tunnel_apps(&mut self, apps: Vec<String>) {
        let new_apps: AHashSet<String> = apps.into_iter().map(|s| s.to_lowercase()).collect();
        if self.tunnel_apps == new_apps {
            return;
        }
        self.tunnel_apps = new_apps;
        let _snapshot_write_guard = self.snapshot_write_lock.lock();

        // Force immediate snapshot update so workers see the new tunnel_apps
        // Clone the current connections and pid_names from existing snapshot
        let old_snap = self.get_snapshot();

        let version = self.version.fetch_add(1, Ordering::Relaxed) + 1;

        let (explicit_tunnel_udp_ports, explicit_tunnel_tcp_ports) = self.clone_explicit_ports();
        let new_snapshot = self.snapshot_from_parts(
            old_snap.connections.clone(),
            old_snap.pid_names.clone(),
            version,
            explicit_tunnel_udp_ports,
            explicit_tunnel_tcp_ports,
        );

        // Atomically swap in new snapshot - arc-swap handles cleanup safely
        self.current.store(new_snapshot);

        log::info!(
            "set_tunnel_apps: Updated snapshot with {} tunnel apps: {:?}",
            self.tunnel_apps.len(),
            self.tunnel_apps.iter().take(5).collect::<Vec<_>>()
        );
    }

    /// Get tunnel apps
    pub fn tunnel_apps(&self) -> &AHashSet<String> {
        &self.tunnel_apps
    }

    /// Immediately register a process detected via ETW
    ///
    /// Called when ETW detects a watched process starting. This adds the
    /// PID → name mapping immediately, so when the first packet arrives
    /// and we query the TCP/UDP tables, we already know this PID belongs
    /// to a tunnel app.
    ///
    /// This solves the race condition where:
    /// 1. Browser launches RobloxPlayerBeta.exe
    /// 2. Roblox immediately connects to game server
    /// 3. Our 50ms polling hasn't detected the process yet
    /// 4. First packets bypass VPN → Error 279
    ///
    /// With ETW + this method:
    /// 1. ETW notifies us instantly when process starts
    /// 2. We add PID → name mapping here
    /// 3. When first packet arrives, is_tunnel_pid() returns true
    pub fn register_process_immediate(&self, pid: u32, name: String) {
        let _snapshot_write_guard = self.snapshot_write_lock.lock();
        let old_snap = self.get_snapshot();
        let name_lower = name.to_lowercase();
        if old_snap
            .pid_names
            .get(&pid)
            .is_some_and(|existing| existing == &name_lower)
        {
            return;
        }
        let version = self.version.fetch_add(1, Ordering::Relaxed) + 1;

        // Clone existing data and add the new process
        let mut pid_names = old_snap.pid_names.clone();
        pid_names.insert(pid, name_lower);
        let (explicit_tunnel_udp_ports, explicit_tunnel_tcp_ports) = self.clone_explicit_ports();
        let new_snapshot = self.snapshot_from_parts(
            old_snap.connections.clone(),
            pid_names,
            version,
            explicit_tunnel_udp_ports,
            explicit_tunnel_tcp_ports,
        );

        self.current.store(new_snapshot);

        log::info!(
            "ETW: Immediately registered process {} (PID: {}) for tunneling",
            name,
            pid
        );
    }

    /// Immediately register a UDP source port as tunnel-owned.
    ///
    /// This is used by the Windows testbench helper so packet routing does not depend
    /// on connection-table timing races for short-lived probe processes.
    pub fn register_udp_port_immediate(&self, local_port: u16) {
        let _snapshot_write_guard = self.snapshot_write_lock.lock();
        let explicit_tunnel_udp_ports = {
            let mut ports = self.explicit_tunnel_udp_ports.lock();
            if !ports.insert(local_port) {
                return;
            }
            ports.clone()
        };

        let old_snap = self.get_snapshot();
        let version = self.version.fetch_add(1, Ordering::Relaxed) + 1;

        let explicit_tunnel_tcp_ports = self.explicit_tunnel_tcp_ports.lock().clone();

        let new_snapshot = self.snapshot_from_parts(
            old_snap.connections.clone(),
            old_snap.pid_names.clone(),
            version,
            explicit_tunnel_udp_ports,
            explicit_tunnel_tcp_ports,
        );

        self.current.store(new_snapshot);

        log::info!(
            "Registered UDP source port {} for immediate tunneling",
            local_port
        );
    }

    /// Register TCP source ports belonging to tunnel processes for API tunneling.
    ///
    /// Called from the cache refresher when API tunneling is enabled.
    /// Persists TCP ports across snapshot refreshes so they don't rely on
    /// stale connection-table lookups.
    pub fn register_tcp_ports(&self, ports: &[u16]) {
        let _snapshot_write_guard = self.snapshot_write_lock.lock();
        let new_set: AHashSet<u16> = ports.iter().copied().collect();
        let unchanged = {
            let guard = self.explicit_tunnel_tcp_ports.lock();
            *guard == new_set
        };
        if unchanged {
            return;
        }
        let explicit_tunnel_tcp_ports = self.replace_explicit_tcp_ports_locked(ports);

        // Rebuild snapshot immediately so packet workers can use the new port
        // ownership map without waiting for the next cache refresh cycle.
        let old_snap = self.get_snapshot();
        let version = self.version.fetch_add(1, Ordering::Relaxed) + 1;
        let explicit_tunnel_udp_ports = self.explicit_tunnel_udp_ports.lock().clone();
        let new_snapshot = self.snapshot_from_parts(
            old_snap.connections.clone(),
            old_snap.pid_names.clone(),
            version,
            explicit_tunnel_udp_ports,
            explicit_tunnel_tcp_ports,
        );
        self.current.store(new_snapshot);
    }

    fn replace_explicit_tcp_ports_locked(&self, ports: &[u16]) -> AHashSet<u16> {
        let new_set: AHashSet<u16> = ports.iter().copied().collect();
        let now = Instant::now();
        {
            let mut last_seen = self.explicit_tunnel_tcp_port_last_seen.lock();
            last_seen.clear();
            last_seen.extend(new_set.iter().map(|port| (*port, now)));
        }

        self.store_explicit_tcp_ports_locked(new_set)
    }

    fn retain_recent_explicit_tcp_ports_locked(
        &self,
        ports: &[u16],
        retain_for: Duration,
    ) -> AHashSet<u16> {
        let now = Instant::now();
        let new_set = {
            let mut last_seen = self.explicit_tunnel_tcp_port_last_seen.lock();
            for port in ports {
                last_seen.insert(*port, now);
            }
            last_seen.retain(|_, seen_at| now.duration_since(*seen_at) <= retain_for);
            last_seen.keys().copied().collect()
        };

        self.store_explicit_tcp_ports_locked(new_set)
    }

    fn store_explicit_tcp_ports_locked(&self, new_set: AHashSet<u16>) -> AHashSet<u16> {
        let mut guard = self.explicit_tunnel_tcp_ports.lock();
        if *guard != new_set {
            log::info!(
                "Updated TCP ports for API tunneling: {} port(s)",
                new_set.len()
            );
            *guard = new_set;
        }
        guard.clone()
    }
}

// Note: No manual Drop impl needed - ArcSwap handles cleanup automatically
// Note: No unsafe impl Send/Sync needed - ArcSwap is already Send+Sync

#[cfg(test)]
mod tests {
    use super::*;
    // Tests use AHashMap/AHashSet to match the production ProcessSnapshot types
    use ahash::AHashMap as HashMap;
    use ahash::AHashSet as HashSet;

    #[test]
    fn test_lock_free_snapshot() {
        let cache = LockFreeProcessCache::new(vec!["robloxplayerbeta.exe".to_string()]);

        // Get snapshot
        let snap1 = cache.get_snapshot();
        assert_eq!(snap1.version, 0);

        // Update with new data
        let mut connections = HashMap::new();
        connections.insert(
            ConnectionKey::new(Ipv4Addr::new(192, 168, 1, 1), 8080, Protocol::Tcp),
            1234,
        );

        let mut pid_names = HashMap::new();
        pid_names.insert(1234, "RobloxPlayerBeta.exe".to_string());

        cache.update(connections, pid_names);

        // Get new snapshot
        let snap2 = cache.get_snapshot();
        assert_eq!(snap2.version, 1);

        // Old snapshot still valid (that's the RCU magic)
        assert_eq!(snap1.version, 0);

        // New snapshot has the connection
        assert!(snap2.should_tunnel(Ipv4Addr::new(192, 168, 1, 1), 8080, Protocol::Tcp));
    }

    #[test]
    fn test_should_tunnel_0000_fallback() {
        let cache = LockFreeProcessCache::new(vec!["roblox".to_string()]);

        let mut connections = HashMap::new();
        // App binds to 0.0.0.0:50000
        connections.insert(
            ConnectionKey::new(Ipv4Addr::UNSPECIFIED, 50000, Protocol::Udp),
            1234,
        );

        let mut pid_names = HashMap::new();
        pid_names.insert(1234, "RobloxPlayerBeta.exe".to_string());

        cache.update(connections, pid_names);

        let snap = cache.get_snapshot();

        // Packet has actual interface IP, should still match via 0.0.0.0 fallback
        assert!(snap.should_tunnel(Ipv4Addr::new(192, 168, 1, 100), 50000, Protocol::Udp));
    }

    #[test]
    fn test_permissive_routing() {
        let cache = LockFreeProcessCache::new(vec!["roblox".to_string()]);

        let mut connections = HashMap::new();
        connections.insert(
            ConnectionKey::new(Ipv4Addr::new(192, 168, 1, 100), 50000, Protocol::Udp),
            1234,
        );

        let mut pid_names = HashMap::new();
        pid_names.insert(1234, "RobloxPlayerBeta.exe".to_string());

        cache.update(connections, pid_names);

        let snap = cache.get_snapshot();

        // Should tunnel UDP to Roblox game server (128.116.x.x)
        assert!(snap.should_tunnel_v2(
            Ipv4Addr::new(192, 168, 1, 100),
            50000,
            Protocol::Udp,
            Ipv4Addr::new(128, 116, 50, 100),
            55000, // Roblox game server
            false,
        ));

        // Should NOT tunnel TCP (web API calls don't need VPN routing)
        assert!(!snap.should_tunnel_v2(
            Ipv4Addr::new(192, 168, 1, 100),
            50000,
            Protocol::Tcp,
            Ipv4Addr::new(128, 116, 50, 100),
            55000,
            false,
        ));

        // Permissive: SHOULD tunnel UDP to non-game IP from tunnel app
        // We trust the process - ALL its UDP gets tunneled (STUN, voice chat, etc.)
        assert!(snap.should_tunnel_v2(
            Ipv4Addr::new(192, 168, 1, 100),
            50000,
            Protocol::Udp,
            Ipv4Addr::new(1, 1, 1, 1),
            443,
            false,
        ));
    }

    #[test]
    fn test_concurrent_read_write_safety() {
        // This test verifies that arc-swap prevents use-after-free
        use std::thread;
        use std::time::Duration;

        let cache = Arc::new(LockFreeProcessCache::new(vec!["test.exe".to_string()]));

        // Spawn reader threads that continuously get snapshots
        let readers: Vec<_> = (0..4)
            .map(|i| {
                let cache_clone = Arc::clone(&cache);
                thread::spawn(move || {
                    for _ in 0..1000 {
                        let snap = cache_clone.get_snapshot();
                        // Access the snapshot data - this would crash with old implementation
                        let _ = snap.version;
                        let _ = snap.connections.len();
                        thread::sleep(Duration::from_micros(10));
                    }
                    log::debug!("Reader {} finished", i);
                })
            })
            .collect();

        // Writer thread that continuously updates
        let cache_writer = Arc::clone(&cache);
        let writer = thread::spawn(move || {
            for i in 0..100 {
                let mut connections = HashMap::new();
                connections.insert(
                    ConnectionKey::new(Ipv4Addr::new(192, 168, 1, 1), i as u16, Protocol::Tcp),
                    i,
                );
                let mut pid_names = HashMap::new();
                pid_names.insert(i, format!("process_{}.exe", i));
                cache_writer.update(connections, pid_names);
                thread::sleep(Duration::from_micros(100));
            }
            log::debug!("Writer finished");
        });

        // Wait for all threads - if there's a use-after-free, this would crash
        for reader in readers {
            reader.join().expect("Reader thread panicked");
        }
        writer.join().expect("Writer thread panicked");
    }

    #[test]
    fn test_stale_snapshot_direct_lookup() {
        // This test simulates the stale snapshot race condition:
        // 1. Worker has an old snapshot without a new process
        // 2. On-demand lookup finds the PID
        // 3. PID is not in snapshot's pid_names
        // 4. Direct OS lookup should match against tunnel_apps
        //
        // Since we can't actually trigger this in a unit test (requires real
        // Windows process state), we verify the matching logic works correctly.

        let cache =
            LockFreeProcessCache::new(vec!["robloxplayerbeta".to_string(), "roblox".to_string()]);

        let snap = cache.get_snapshot();

        // Verify tunnel_apps matching logic (same as in is_tunnel_connection fallback)
        let test_cases = vec![
            ("RobloxPlayerBeta.exe", true),
            ("robloxplayerbeta.exe", true),
            ("ROBLOXPLAYERBETA.EXE", true),
            ("RobloxApp.exe", true),
            ("chrome.exe", false),
            ("notepad.exe", false),
            ("System", false),
        ];

        for (name, expected) in test_cases {
            let name_lower = name.to_lowercase();
            let matched = process_name_matches_any_tunnel_app(&name_lower, &snap.tunnel_apps);
            assert_eq!(
                matched, expected,
                "Process '{}' match failed: expected {}, got {}",
                name, expected, matched
            );
        }
    }

    #[test]
    fn test_compute_tunnel_pids_exact_and_roblox_alias_match() {
        let mut pid_names = HashMap::new();
        pid_names.insert(1, "robloxplayerbeta.exe".to_string());
        pid_names.insert(2, "robloxapp.exe".to_string());
        pid_names.insert(3, "chrome.exe".to_string());

        let tunnel_apps: HashSet<String> =
            ["roblox".to_string(), "robloxplayerbeta.exe".to_string()]
                .into_iter()
                .collect();

        let tunnel_pids = ProcessSnapshot::compute_tunnel_pids(&pid_names, &tunnel_apps);

        assert!(tunnel_pids.contains(&1), "Exact match should be tunneled");
        assert!(
            tunnel_pids.contains(&2),
            "Known Roblox alias should be tunneled"
        );
        assert!(
            !tunnel_pids.contains(&3),
            "Non-matching process should not be tunneled"
        );
    }

    #[test]
    fn test_set_tunnel_apps_recomputes_tunnel_pids() {
        let mut cache = LockFreeProcessCache::new(vec!["roblox".to_string()]);

        let src_ip = Ipv4Addr::new(192, 168, 1, 100);
        let src_port = 50000;
        let pid = 1111;

        let mut connections = HashMap::new();
        connections.insert(ConnectionKey::new(src_ip, src_port, Protocol::Udp), pid);

        let mut pid_names = HashMap::new();
        pid_names.insert(pid, "RobloxPlayerBeta.exe".to_string());

        cache.update(connections, pid_names);
        let snap = cache.get_snapshot();
        assert!(snap.is_tunnel_pid_public(pid));
        assert!(snap.tunnel_pids.contains(&pid));

        // Remove tunnel apps; tunnel_pids should be recomputed to empty.
        cache.set_tunnel_apps(vec![]);

        let snap2 = cache.get_snapshot();
        assert!(!snap2.is_tunnel_pid_public(pid));
        assert!(!snap2.tunnel_pids.contains(&pid));
    }

    #[test]
    fn test_register_process_immediate_populates_tunnel_pids() {
        let cache = LockFreeProcessCache::new(vec!["roblox".to_string()]);
        let pid = 2222;

        let snap0 = cache.get_snapshot();
        assert!(!snap0.is_tunnel_pid_public(pid));
        assert!(!snap0.tunnel_pids.contains(&pid));

        cache.register_process_immediate(pid, "RobloxPlayerBeta.exe".to_string());

        let snap1 = cache.get_snapshot();
        assert_eq!(
            snap1.pid_names.get(&pid).map(|s| s.as_str()),
            Some("robloxplayerbeta.exe")
        );
        assert!(snap1.is_tunnel_pid_public(pid));
        assert!(snap1.tunnel_pids.contains(&pid));
    }

    #[test]
    fn test_register_process_immediate_populates_tunnel_pids_for_robloxapp_exact_name() {
        let cache = LockFreeProcessCache::new(vec!["robloxapp.exe".to_string()]);
        let pid = 3333;

        cache.register_process_immediate(pid, "RobloxApp.exe".to_string());

        let snap = cache.get_snapshot();
        assert_eq!(
            snap.pid_names.get(&pid).map(|s| s.as_str()),
            Some("robloxapp.exe")
        );
        assert!(snap.is_tunnel_pid_public(pid));
        assert!(snap.tunnel_pids.contains(&pid));
    }

    #[test]
    fn test_register_process_immediate_rejects_store_roblox_host_path() {
        let cache = LockFreeProcessCache::new(vec!["robloxplayerbeta.exe".to_string()]);
        let pid = 4445;
        let identity = r"C:\Program Files\WindowsApps\ROBLOXCORPORATION.ROBLOX_2.617.655.0_x64__55nm5eh3cm0pr\Windows10Universal.exe";

        cache.register_process_immediate(pid, identity.to_string());

        let snap = cache.get_snapshot();
        assert!(!snap.is_tunnel_pid_public(pid));
        assert!(!snap.tunnel_pids.contains(&pid));
    }

    #[test]
    fn test_register_process_immediate_rejects_legacy_store_host_entry() {
        let cache = LockFreeProcessCache::new(vec!["windows10universal.exe".to_string()]);
        let pid = 4446;

        cache.register_process_immediate(pid, "Windows10Universal.exe".to_string());

        let snap = cache.get_snapshot();
        assert!(!snap.is_tunnel_pid_public(pid));
        assert!(!snap.tunnel_pids.contains(&pid));
    }

    #[test]
    fn test_has_connection_for_pid_detects_owned_endpoints() {
        let cache = LockFreeProcessCache::new(vec!["roblox".to_string()]);

        let mut connections = HashMap::new();
        connections.insert(
            ConnectionKey::new(Ipv4Addr::new(10, 0, 0, 10), 55000, Protocol::Udp),
            7001,
        );
        connections.insert(
            ConnectionKey::new(Ipv4Addr::new(10, 0, 0, 10), 55001, Protocol::Tcp),
            7002,
        );

        cache.update(connections, HashMap::new());
        let snap = cache.get_snapshot();

        assert!(snap.has_connection_for_pid(7001));
        assert!(snap.has_connection_for_pid(7002));
        assert!(!snap.has_connection_for_pid(7003));
    }

    #[test]
    fn test_should_tunnel_by_port_fallback_matches_tunnel_pid_port() {
        let cache = LockFreeProcessCache::new(vec!["roblox".to_string()]);

        let mut connections = HashMap::new();
        connections.insert(
            ConnectionKey::new(Ipv4Addr::new(10, 0, 0, 10), 55000, Protocol::Udp),
            7001,
        );
        let mut pid_names = HashMap::new();
        pid_names.insert(7001, "RobloxPlayerBeta.exe".to_string());

        cache.update(connections, pid_names);
        let snap = cache.get_snapshot();

        assert!(snap.should_tunnel_by_port_fallback(55000, Protocol::Udp, false));
        assert!(!snap.should_tunnel_by_port_fallback(55001, Protocol::Udp, false));
    }

    #[test]
    fn test_should_tunnel_by_port_fallback_ignores_non_tunnel_pid() {
        let cache = LockFreeProcessCache::new(vec!["roblox".to_string()]);

        let mut connections = HashMap::new();
        connections.insert(
            ConnectionKey::new(Ipv4Addr::new(10, 0, 0, 20), 56000, Protocol::Udp),
            8001,
        );
        let mut pid_names = HashMap::new();
        pid_names.insert(8001, "chrome.exe".to_string());

        cache.update(connections, pid_names);
        let snap = cache.get_snapshot();

        assert!(!snap.should_tunnel_by_port_fallback(56000, Protocol::Udp, false));
    }

    #[test]
    fn test_api_tunneling_enables_tcp() {
        assert!(is_likely_game_traffic(443, Protocol::Tcp, true));
        assert!(!is_likely_game_traffic(443, Protocol::Tcp, false));
        assert!(is_likely_game_traffic(443, Protocol::Udp, false));
        assert!(is_likely_game_traffic(443, Protocol::Udp, true));
    }

    #[test]
    fn test_roblox_game_server_tcp_with_api_tunneling() {
        let roblox_ip = Ipv4Addr::new(128, 116, 50, 100);
        assert!(is_roblox_game_server(roblox_ip, 443, Protocol::Tcp, true));
        assert!(!is_roblox_game_server(roblox_ip, 443, Protocol::Tcp, false));
        assert!(is_roblox_game_server(
            roblox_ip,
            55000,
            Protocol::Udp,
            false
        ));
    }

    #[test]
    fn test_game_server_tcp_with_api_tunneling() {
        let roblox_ip = Ipv4Addr::new(128, 116, 50, 100);
        assert!(is_game_server(roblox_ip, 443, Protocol::Tcp, true));
        assert!(!is_game_server(roblox_ip, 443, Protocol::Tcp, false));
        assert!(is_game_server(roblox_ip, 55000, Protocol::Udp, false));
        assert!(is_game_server(roblox_ip, 55000, Protocol::Udp, true));
    }

    #[test]
    fn test_should_tunnel_v2_with_api_tunneling() {
        let cache = LockFreeProcessCache::new(vec!["roblox".to_string()]);

        let mut connections = HashMap::new();
        connections.insert(
            ConnectionKey::new(Ipv4Addr::new(192, 168, 1, 100), 50000, Protocol::Tcp),
            1234,
        );

        let mut pid_names = HashMap::new();
        pid_names.insert(1234, "RobloxPlayerBeta.exe".to_string());

        cache.update(connections, pid_names);

        let snap = cache.get_snapshot();

        // TCP from tunnel app should be tunneled when api_tunneling is enabled
        assert!(snap.should_tunnel_v2(
            Ipv4Addr::new(192, 168, 1, 100),
            50000,
            Protocol::Tcp,
            Ipv4Addr::new(128, 116, 50, 100),
            443,
            true,
        ));

        // TCP from tunnel app should NOT be tunneled when api_tunneling is disabled
        assert!(!snap.should_tunnel_v2(
            Ipv4Addr::new(192, 168, 1, 100),
            50000,
            Protocol::Tcp,
            Ipv4Addr::new(128, 116, 50, 100),
            443,
            false,
        ));
    }

    #[test]
    fn test_should_tunnel_by_port_fallback_tcp_with_api_tunneling() {
        let cache = LockFreeProcessCache::new(vec!["roblox".to_string()]);

        let mut connections = HashMap::new();
        connections.insert(
            ConnectionKey::new(Ipv4Addr::new(10, 0, 0, 10), 55000, Protocol::Tcp),
            7001,
        );
        let mut pid_names = HashMap::new();
        pid_names.insert(7001, "RobloxPlayerBeta.exe".to_string());

        cache.update(connections, pid_names);
        let snap = cache.get_snapshot();

        // TCP port fallback should work when api_tunneling is enabled
        assert!(snap.should_tunnel_by_port_fallback(55000, Protocol::Tcp, true));
        // TCP port fallback should NOT work when api_tunneling is disabled
        assert!(!snap.should_tunnel_by_port_fallback(55000, Protocol::Tcp, false));
        // UDP port fallback is unchanged regardless of api_tunneling
        assert!(!snap.should_tunnel_by_port_fallback(55000, Protocol::Udp, false));
    }

    #[test]
    fn test_register_process_immediate_skips_duplicate_snapshot_rebuild() {
        let cache = LockFreeProcessCache::new(vec!["roblox".to_string()]);

        cache.register_process_immediate(7001, "RobloxPlayerBeta.exe".to_string());
        let first_version = cache.get_snapshot().version;

        cache.register_process_immediate(7001, "robloxplayerbeta.exe".to_string());

        assert_eq!(cache.get_snapshot().version, first_version);
    }

    #[test]
    fn test_register_udp_port_immediate_skips_duplicate_snapshot_rebuild() {
        let cache = LockFreeProcessCache::new(vec!["roblox".to_string()]);

        cache.register_udp_port_immediate(55000);
        let first_snapshot = cache.get_snapshot();
        let first_version = first_snapshot.version;
        assert!(first_snapshot.should_tunnel_by_port_fallback(55000, Protocol::Udp, false));
        drop(first_snapshot);

        cache.register_udp_port_immediate(55000);

        assert_eq!(cache.get_snapshot().version, first_version);
    }

    #[test]
    fn test_should_tunnel_v2_does_not_speculate_tcp_without_process_match() {
        let cache = LockFreeProcessCache::new(vec!["roblox".to_string()]);
        let snap = cache.get_snapshot();

        assert!(!snap.should_tunnel_v2(
            Ipv4Addr::new(10, 0, 0, 2),
            40001,
            Protocol::Tcp,
            Ipv4Addr::new(128, 116, 50, 100),
            443,
            true,
        ));
    }

    #[test]
    fn test_register_tcp_ports_applies_immediately_and_persists() {
        let cache = LockFreeProcessCache::new(vec!["roblox".to_string()]);

        // No connection metadata yet, but API tunnel TCP ports are explicitly known.
        cache.register_tcp_ports(&[443, 50000]);
        let first_snapshot = cache.get_snapshot();
        let first_version = first_snapshot.version;

        assert!(first_snapshot.should_tunnel_by_port_fallback(443, Protocol::Tcp, true));
        assert!(first_snapshot.should_tunnel_by_port_fallback(50000, Protocol::Tcp, true));
        assert!(!first_snapshot.should_tunnel_by_port_fallback(443, Protocol::Tcp, false));
        drop(first_snapshot);

        // Calling with the same set should not force another snapshot rebuild.
        cache.register_tcp_ports(&[443, 50000]);
        assert_eq!(cache.get_snapshot().version, first_version);

        // Regular cache updates must preserve explicitly registered TCP ports.
        let mut connections = HashMap::new();
        connections.insert(
            ConnectionKey::new(Ipv4Addr::new(10, 0, 0, 20), 55000, Protocol::Udp),
            9001,
        );
        let mut pid_names = HashMap::new();
        pid_names.insert(9001, "RobloxPlayerBeta.exe".to_string());
        cache.update(connections, pid_names);

        let updated = cache.get_snapshot();
        assert!(updated.should_tunnel_by_port_fallback(443, Protocol::Tcp, true));
        assert!(updated.should_tunnel_by_port_fallback(50000, Protocol::Tcp, true));
    }

    #[test]
    fn test_update_with_tcp_ports_publishes_connections_and_explicit_ports_together() {
        let cache = LockFreeProcessCache::new(vec!["roblox".to_string()]);
        let mut connections = HashMap::new();
        connections.insert(
            ConnectionKey::new(Ipv4Addr::new(10, 0, 0, 20), 53000, Protocol::Tcp),
            9001,
        );
        let mut pid_names = HashMap::new();
        pid_names.insert(9001, "RobloxPlayerBeta.exe".to_string());

        cache.update_with_tcp_ports(connections, pid_names, &[443]);

        let snap = cache.get_snapshot();
        assert!(snap.should_tunnel(Ipv4Addr::new(10, 0, 0, 20), 53000, Protocol::Tcp));
        assert!(snap.should_tunnel_by_port_fallback(443, Protocol::Tcp, true));
        assert!(snap.should_tunnel_by_port_fallback(53000, Protocol::Tcp, true));
    }

    #[test]
    fn test_update_with_recent_tcp_ports_retains_then_expires() {
        let cache = LockFreeProcessCache::new(vec!["roblox".to_string()]);

        cache.update_with_recent_tcp_ports(
            HashMap::new(),
            HashMap::new(),
            &[53000],
            Duration::from_secs(30),
        );
        assert!(
            cache
                .get_snapshot()
                .should_tunnel_by_port_fallback(53000, Protocol::Tcp, true)
        );

        cache.update_with_recent_tcp_ports(
            HashMap::new(),
            HashMap::new(),
            &[],
            Duration::from_secs(30),
        );
        assert!(
            cache
                .get_snapshot()
                .should_tunnel_by_port_fallback(53000, Protocol::Tcp, true)
        );

        std::thread::sleep(Duration::from_millis(2));
        cache.update_with_recent_tcp_ports(
            HashMap::new(),
            HashMap::new(),
            &[],
            Duration::from_millis(1),
        );
        assert!(
            !cache
                .get_snapshot()
                .should_tunnel_by_port_fallback(53000, Protocol::Tcp, true)
        );
    }
}
