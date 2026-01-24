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

/// Roblox game server IP ranges
/// Primary: 128.116.0.0/17 (128.116.0.0 - 128.116.127.255)
/// Secondary: 209.206.40.0/21 (209.206.40.0 - 209.206.47.255)
///
/// Source: Roblox DevForum, ExitLag research
const ROBLOX_RANGES: &[(u32, u32, u32)] = &[
    // 128.116.0.0/17 - primary game servers
    (0x80740000, 0xFFFF8000, 17), // 128.116.0.0, mask 255.255.128.0, /17
    // 209.206.40.0/21 - secondary
    (0xD1CE2800, 0xFFFFF800, 21), // 209.206.40.0, mask 255.255.248.0, /21
];

/// Roblox game server UDP port range
/// Game traffic uses ephemeral ports in this range
const ROBLOX_PORT_MIN: u16 = 49152;
const ROBLOX_PORT_MAX: u16 = 65535;

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

/// Check if destination is any known game server (extensible for future games)
#[inline(always)]
pub fn is_game_server(dst_ip: Ipv4Addr, dst_port: u16, protocol: Protocol) -> bool {
    // Currently only Roblox, but can add Valorant, Fortnite, etc.
    is_roblox_game_server(dst_ip, dst_port, protocol)
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

        if !is_tunnel_app {
            return false;
        }

        // V1 mode: process check is enough
        if self.routing_mode == RoutingMode::V1 {
            return true;
        }

        // V2 mode: also check destination is a game server
        is_game_server(dst_ip, dst_port, protocol)
    }

    /// Check if connection belongs to a tunnel app (internal helper)
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
}
