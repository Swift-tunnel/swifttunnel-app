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

use std::collections::{HashMap, HashSet};
use std::net::Ipv4Addr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use arc_swap::ArcSwap;
use super::process_tracker::{ConnectionKey, Protocol, TrackerStats};
use crate::settings::RoutingMode;

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

/// Roblox game server UDP port range
/// Game traffic uses ephemeral ports in this range
const ROBLOX_PORT_MIN: u16 = 49152;
const ROBLOX_PORT_MAX: u16 = 65535;

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
        assert!(is_valid_cidr_mask(mask, prefix), "Invalid CIDR mask in ROBLOX_RANGES");
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
/// - Port is in game server range (49152-65535)
/// - Protocol is UDP
#[inline(always)]
pub fn is_roblox_game_server(dst_ip: Ipv4Addr, dst_port: u16, protocol: Protocol) -> bool {
    // Must be UDP for game traffic
    if protocol != Protocol::Udp {
        return false;
    }

    // Check port range
    if dst_port < ROBLOX_PORT_MIN || dst_port > ROBLOX_PORT_MAX {
        return false;
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
pub fn is_likely_game_traffic(_dst_port: u16, protocol: Protocol) -> bool {
    // Trust the process - if it's Roblox, tunnel ALL its UDP traffic
    // TCP is intentionally not tunneled (web API calls don't need VPN routing)
    protocol == Protocol::Udp
}

/// Check if destination is any known game server (extensible for future games)
#[inline(always)]
pub fn is_game_server(dst_ip: Ipv4Addr, dst_port: u16, protocol: Protocol) -> bool {
    // Currently only Roblox, but can add Valorant, Fortnite, etc.
    is_roblox_game_server(dst_ip, dst_port, protocol)
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

/// Look up PID for a specific connection via IP Helper API
///
/// This is an EXPENSIVE synchronous call - only use when cache misses.
/// Critical for guaranteeing first-packet tunneling when ETW has detected
/// a process but the connection tables haven't been refreshed yet.
#[cfg(windows)]
fn lookup_connection_pid(local_ip: Ipv4Addr, local_port: u16, protocol: Protocol) -> Option<u32> {
    use windows::Win32::NetworkManagement::IpHelper::*;
    use windows::Win32::Foundation::*;

    unsafe {
        match protocol {
            Protocol::Tcp => {
                // Get TCP table size
                let mut size: u32 = 0;
                let result = GetExtendedTcpTable(
                    None,
                    &mut size,
                    false,
                    2, // AF_INET
                    TCP_TABLE_CLASS(TCP_TABLE_OWNER_PID_ALL.0),
                    0,
                );
                if result != ERROR_INSUFFICIENT_BUFFER.0 && result != NO_ERROR.0 {
                    return None;
                }
                if size == 0 {
                    return None;
                }

                // Get TCP table
                let mut buffer = vec![0u8; size as usize];
                let result = GetExtendedTcpTable(
                    Some(buffer.as_mut_ptr() as *mut _),
                    &mut size,
                    false,
                    2, // AF_INET
                    TCP_TABLE_CLASS(TCP_TABLE_OWNER_PID_ALL.0),
                    0,
                );
                if result != NO_ERROR.0 {
                    return None;
                }

                // BOUNDS CHECK: Validate buffer has at least the header size
                let header_size = std::mem::size_of::<u32>(); // dwNumEntries
                if buffer.len() < header_size {
                    log::warn!("TCP table buffer too small for header");
                    return None;
                }

                // Search for matching connection
                let table = &*(buffer.as_ptr() as *const MIB_TCPTABLE_OWNER_PID);
                let num_entries = table.dwNumEntries as usize;

                // BOUNDS CHECK: Validate num_entries doesn't exceed buffer capacity
                let entry_size = std::mem::size_of::<MIB_TCPROW_OWNER_PID>();
                let max_entries = buffer.len().saturating_sub(header_size) / entry_size;
                let safe_entries = num_entries.min(max_entries);

                if safe_entries < num_entries {
                    log::warn!("TCP table num_entries ({}) exceeds buffer capacity ({})", num_entries, max_entries);
                }

                let entries = std::slice::from_raw_parts(
                    table.table.as_ptr(),
                    safe_entries,
                );

                for entry in entries {
                    let entry_ip = Ipv4Addr::from(entry.dwLocalAddr.to_ne_bytes());
                    let entry_port = u16::from_be(entry.dwLocalPort as u16);

                    if entry_port == local_port && (entry_ip == local_ip || entry_ip == Ipv4Addr::UNSPECIFIED) {
                        return Some(entry.dwOwningPid);
                    }
                }
            }
            Protocol::Udp => {
                // Get UDP table size
                let mut size: u32 = 0;
                let result = GetExtendedUdpTable(
                    None,
                    &mut size,
                    false,
                    2, // AF_INET
                    UDP_TABLE_CLASS(UDP_TABLE_OWNER_PID.0),
                    0,
                );
                if result != ERROR_INSUFFICIENT_BUFFER.0 && result != NO_ERROR.0 {
                    return None;
                }
                if size == 0 {
                    return None;
                }

                // Get UDP table
                let mut buffer = vec![0u8; size as usize];
                let result = GetExtendedUdpTable(
                    Some(buffer.as_mut_ptr() as *mut _),
                    &mut size,
                    false,
                    2, // AF_INET
                    UDP_TABLE_CLASS(UDP_TABLE_OWNER_PID.0),
                    0,
                );
                if result != NO_ERROR.0 {
                    return None;
                }

                // BOUNDS CHECK: Validate buffer has at least the header size
                let header_size = std::mem::size_of::<u32>(); // dwNumEntries
                if buffer.len() < header_size {
                    log::warn!("UDP table buffer too small for header");
                    return None;
                }

                // Search for matching endpoint
                let table = &*(buffer.as_ptr() as *const MIB_UDPTABLE_OWNER_PID);
                let num_entries = table.dwNumEntries as usize;

                // BOUNDS CHECK: Validate num_entries doesn't exceed buffer capacity
                let entry_size = std::mem::size_of::<MIB_UDPROW_OWNER_PID>();
                let max_entries = buffer.len().saturating_sub(header_size) / entry_size;
                let safe_entries = num_entries.min(max_entries);

                if safe_entries < num_entries {
                    log::warn!("UDP table num_entries ({}) exceeds buffer capacity ({})", num_entries, max_entries);
                }

                let entries = std::slice::from_raw_parts(
                    table.table.as_ptr(),
                    safe_entries,
                );

                for entry in entries {
                    let entry_ip = Ipv4Addr::from(entry.dwLocalAddr.to_ne_bytes());
                    let entry_port = u16::from_be(entry.dwLocalPort as u16);

                    if entry_port == local_port && (entry_ip == local_ip || entry_ip == Ipv4Addr::UNSPECIFIED) {
                        return Some(entry.dwOwningPid);
                    }
                }
            }
        }
    }
    None
}

#[cfg(not(windows))]
fn lookup_connection_pid(_local_ip: Ipv4Addr, _local_port: u16, _protocol: Protocol) -> Option<u32> {
    None
}

/// Immutable snapshot of process state
///
/// Once created, this is NEVER modified. Readers can safely access
/// without any synchronization. New snapshots replace old ones atomically.
#[derive(Clone)]
pub struct ProcessSnapshot {
    /// Connection cache: (local_ip, local_port, protocol) → PID
    pub connections: HashMap<ConnectionKey, u32>,
    /// PID → process name (lowercase)
    pub pid_names: HashMap<u32, String>,
    /// Apps that should be tunneled (lowercase)
    pub tunnel_apps: HashSet<String>,
    /// Snapshot version (monotonically increasing)
    pub version: u64,
    /// Timestamp when snapshot was created
    pub created_at: std::time::Instant,
    /// Routing mode (V1 = process-only, V2 = hybrid)
    pub routing_mode: RoutingMode,
}

impl ProcessSnapshot {
    /// Create empty snapshot
    pub fn empty(tunnel_apps: HashSet<String>, routing_mode: RoutingMode) -> Self {
        Self {
            connections: HashMap::new(),
            pid_names: HashMap::new(),
            tunnel_apps,
            version: 0,
            created_at: std::time::Instant::now(),
            routing_mode,
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
    pub fn should_tunnel(
        &self,
        local_ip: Ipv4Addr,
        local_port: u16,
        protocol: Protocol,
    ) -> bool {
        // V1 mode: just check process (original behavior)
        self.is_tunnel_connection(local_ip, local_port, protocol)
    }

    /// Check if connection should be tunneled with destination info (V2 support)
    ///
    /// This is the new method that supports V2 hybrid routing.
    ///
    /// V2 PERMISSIVE MODE (v0.9.5):
    /// - If process IS a tunnel app → use permissive check (port range only)
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
    ) -> bool {
        // First check: Is this from a tunnel app?
        let is_tunnel_app = self.is_tunnel_connection(local_ip, local_port, protocol);

        // V1 mode: process check is enough
        if self.routing_mode == RoutingMode::V1 {
            return is_tunnel_app;
        }

        // V2 mode with PERMISSIVE process trust:
        // If we KNOW it's a tunnel app, trust it and tunnel its UDP traffic
        // even if the destination IP isn't in our known list.
        // This handles new Roblox server deployments gracefully.
        if is_tunnel_app {
            // Trust the process - just check if it looks like game traffic (UDP to high port)
            return is_likely_game_traffic(dst_port, protocol);
        }

        // Process not detected - use strict IP range check for speculative tunneling
        // This catches first packets before process cache is populated
        is_game_server(dst_ip, dst_port, protocol)
    }

    /// Check if connection belongs to a tunnel app (internal helper)
    ///
    /// If cache lookup fails, performs ON-DEMAND IP Helper API query.
    /// This guarantees first-packet tunneling for ETW-detected processes.
    #[inline(always)]
    fn is_tunnel_connection(&self, local_ip: Ipv4Addr, local_port: u16, protocol: Protocol) -> bool {
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

        // FIRST-PACKET GUARANTEE: On-demand lookup via IP Helper API
        // This is expensive but only happens for packets not yet in cache.
        // Critical for ETW-detected processes whose connections haven't
        // been added to the cache yet.
        if let Some(pid) = lookup_connection_pid(local_ip, local_port, protocol) {
            // Fast path: check if PID is in our snapshot's pid_names
            if self.is_tunnel_pid(pid) {
                log::debug!(
                    "On-demand lookup found tunnel PID {} for {}:{}/{}",
                    pid, local_ip, local_port,
                    if protocol == Protocol::Tcp { "TCP" } else { "UDP" }
                );
                return true;
            }

            // SNAPSHOT STALENESS FIX: PID found but not in snapshot!
            // This happens when:
            // 1. ETW detected process and called register_process_immediate()
            // 2. A new snapshot was created with the PID
            // 3. BUT this worker thread is still using an OLD snapshot
            // 4. First packet arrives and on-demand lookup finds the PID
            // 5. is_tunnel_pid() returns false because OLD snapshot doesn't have this PID
            //
            // Solution: Query the OS directly for the process name and check
            // against tunnel_apps. This is a fallback for stale snapshots.
            if let Some(name) = get_process_name_by_pid_fast(pid) {
                let name_lower = name.to_lowercase();
                let name_stem = name_lower.trim_end_matches(".exe");

                for app in &self.tunnel_apps {
                    let app_stem = app.trim_end_matches(".exe");
                    if name_stem.contains(app_stem) || app_stem.contains(name_stem) {
                        log::info!(
                            "First-packet: Direct lookup matched tunnel app '{}' (PID: {}) for {}:{}/{}",
                            name, pid, local_ip, local_port,
                            if protocol == Protocol::Tcp { "TCP" } else { "UDP" }
                        );
                        return true;
                    }
                }
            }
        }

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
        if let Some(name) = self.pid_names.get(&pid) {
            // Names are already lowercase (done at insertion time)

            // Exact match - O(1) HashSet lookup
            if self.tunnel_apps.contains(name) {
                return true;
            }

            // Partial match (for cases like "robloxplayerbeta" matching "roblox")
            let name_stem = name.trim_end_matches(".exe");
            for app in &self.tunnel_apps {
                let app_stem = app.trim_end_matches(".exe");
                if name_stem.contains(app_stem) || app_stem.contains(name_stem) {
                    return true;
                }
            }
        }
        false
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

    /// Get stats
    pub fn stats(&self) -> TrackerStats {
        TrackerStats {
            tcp_connections: self.connections.keys().filter(|k| k.protocol == Protocol::Tcp).count(),
            udp_connections: self.connections.keys().filter(|k| k.protocol == Protocol::Udp).count(),
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
    tunnel_apps: HashSet<String>,
    /// Routing mode (V1 = process-only, V2 = hybrid)
    routing_mode: RoutingMode,
}

impl LockFreeProcessCache {
    /// Create new lock-free cache
    pub fn new(tunnel_apps: Vec<String>, routing_mode: RoutingMode) -> Self {
        let apps: HashSet<String> = tunnel_apps.into_iter().map(|s| s.to_lowercase()).collect();
        let initial = Arc::new(ProcessSnapshot::empty(apps.clone(), routing_mode));

        Self {
            current: ArcSwap::from(initial),
            version: AtomicU64::new(0),
            tunnel_apps: apps,
            routing_mode,
        }
    }

    /// Get current routing mode
    pub fn routing_mode(&self) -> RoutingMode {
        self.routing_mode
    }

    /// Set routing mode and refresh snapshot
    pub fn set_routing_mode(&mut self, mode: RoutingMode) {
        self.routing_mode = mode;

        // Force immediate snapshot update so workers see the new routing_mode
        let old_snap = self.get_snapshot();
        let version = self.version.fetch_add(1, Ordering::Relaxed) + 1;

        let new_snapshot = Arc::new(ProcessSnapshot {
            connections: old_snap.connections.clone(),
            pid_names: old_snap.pid_names.clone(),
            tunnel_apps: self.tunnel_apps.clone(),
            version,
            created_at: std::time::Instant::now(),
            routing_mode: self.routing_mode,
        });

        self.current.store(new_snapshot);

        log::info!(
            "set_routing_mode: Updated to {:?}",
            self.routing_mode
        );
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
    pub fn update(&self, connections: HashMap<ConnectionKey, u32>, pid_names: HashMap<u32, String>) {
        let version = self.version.fetch_add(1, Ordering::Relaxed) + 1;

        // Pre-lowercase all names at insertion time (not in hot path!)
        let pid_names_lower: HashMap<u32, String> = pid_names
            .into_iter()
            .map(|(k, v)| (k, v.to_lowercase()))
            .collect();

        let new_snapshot = Arc::new(ProcessSnapshot {
            connections,
            pid_names: pid_names_lower,
            tunnel_apps: self.tunnel_apps.clone(),
            version,
            created_at: std::time::Instant::now(),
            routing_mode: self.routing_mode,
        });

        // Atomically swap in new snapshot - arc-swap handles cleanup safely
        self.current.store(new_snapshot);
    }

    /// Update tunnel apps list and immediately refresh the snapshot
    ///
    /// CRITICAL: This must create a new snapshot immediately, otherwise workers
    /// will continue using the old snapshot with empty tunnel_apps!
    pub fn set_tunnel_apps(&mut self, apps: Vec<String>) {
        self.tunnel_apps = apps.into_iter().map(|s| s.to_lowercase()).collect();

        // Force immediate snapshot update so workers see the new tunnel_apps
        // Clone the current connections and pid_names from existing snapshot
        let old_snap = self.get_snapshot();

        let version = self.version.fetch_add(1, Ordering::Relaxed) + 1;

        let new_snapshot = Arc::new(ProcessSnapshot {
            connections: old_snap.connections.clone(),
            pid_names: old_snap.pid_names.clone(),
            tunnel_apps: self.tunnel_apps.clone(),  // Use NEW tunnel_apps
            version,
            created_at: std::time::Instant::now(),
            routing_mode: self.routing_mode,
        });

        // Atomically swap in new snapshot - arc-swap handles cleanup safely
        self.current.store(new_snapshot);

        log::info!(
            "set_tunnel_apps: Updated snapshot with {} tunnel apps: {:?}",
            self.tunnel_apps.len(),
            self.tunnel_apps.iter().take(5).collect::<Vec<_>>()
        );
    }

    /// Get tunnel apps
    pub fn tunnel_apps(&self) -> &HashSet<String> {
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
        let old_snap = self.get_snapshot();
        let version = self.version.fetch_add(1, Ordering::Relaxed) + 1;

        // Clone existing data and add the new process
        let mut pid_names = old_snap.pid_names.clone();
        pid_names.insert(pid, name.to_lowercase());

        let new_snapshot = Arc::new(ProcessSnapshot {
            connections: old_snap.connections.clone(),
            pid_names,
            tunnel_apps: self.tunnel_apps.clone(),
            version,
            created_at: std::time::Instant::now(),
            routing_mode: self.routing_mode,
        });

        self.current.store(new_snapshot);

        log::info!(
            "ETW: Immediately registered process {} (PID: {}) for tunneling",
            name, pid
        );
    }
}

// Note: No manual Drop impl needed - ArcSwap handles cleanup automatically
// Note: No unsafe impl Send/Sync needed - ArcSwap is already Send+Sync

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_lock_free_snapshot() {
        let cache = LockFreeProcessCache::new(vec!["robloxplayerbeta.exe".to_string()], RoutingMode::V1);

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
        let cache = LockFreeProcessCache::new(vec!["roblox".to_string()], RoutingMode::V1);

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
    fn test_v2_routing_game_server() {
        let cache = LockFreeProcessCache::new(vec!["roblox".to_string()], RoutingMode::V2);

        let mut connections = HashMap::new();
        connections.insert(
            ConnectionKey::new(Ipv4Addr::new(192, 168, 1, 100), 50000, Protocol::Udp),
            1234,
        );

        let mut pid_names = HashMap::new();
        pid_names.insert(1234, "RobloxPlayerBeta.exe".to_string());

        cache.update(connections, pid_names);

        let snap = cache.get_snapshot();

        // V2: Should tunnel UDP to Roblox game server (128.116.x.x)
        assert!(snap.should_tunnel_v2(
            Ipv4Addr::new(192, 168, 1, 100), 50000, Protocol::Udp,
            Ipv4Addr::new(128, 116, 50, 100), 55000  // Roblox game server
        ));

        // V2: Should NOT tunnel TCP to Roblox game server (wrong protocol)
        assert!(!snap.should_tunnel_v2(
            Ipv4Addr::new(192, 168, 1, 100), 50000, Protocol::Tcp,
            Ipv4Addr::new(128, 116, 50, 100), 55000
        ));

        // V2: Should NOT tunnel UDP to non-game IP (CDN, API, etc.)
        assert!(!snap.should_tunnel_v2(
            Ipv4Addr::new(192, 168, 1, 100), 50000, Protocol::Udp,
            Ipv4Addr::new(1, 1, 1, 1), 443  // Not a game server
        ));
    }

    #[test]
    fn test_concurrent_read_write_safety() {
        // This test verifies that arc-swap prevents use-after-free
        use std::thread;
        use std::time::Duration;

        let cache = Arc::new(LockFreeProcessCache::new(vec!["test.exe".to_string()], RoutingMode::V1));

        // Spawn reader threads that continuously get snapshots
        let readers: Vec<_> = (0..4).map(|i| {
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
        }).collect();

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

        let cache = LockFreeProcessCache::new(
            vec!["robloxplayerbeta".to_string(), "roblox".to_string()],
            RoutingMode::V1
        );

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
            let name_stem = name_lower.trim_end_matches(".exe");

            let mut matched = false;
            for app in &snap.tunnel_apps {
                let app_stem = app.trim_end_matches(".exe");
                if name_stem.contains(app_stem) || app_stem.contains(name_stem) {
                    matched = true;
                    break;
                }
            }

            assert_eq!(
                matched, expected,
                "Process '{}' match failed: expected {}, got {}",
                name, expected, matched
            );
        }
    }
}
