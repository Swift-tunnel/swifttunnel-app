//! Parallel Packet Interceptor - Per-CPU packet processing for <0.5ms latency
//!
//! Architecture modeled after WireGuard kernel module:
//! - Per-CPU packet workers with affinity
//! - Lock-free process cache (RCU pattern)
//! - Batch packet reading to amortize syscall overhead
//! - Separate reader/dispatcher thread feeds workers via MPSC channels
//! - Zero-allocation hot path using pre-allocated buffers
//!
//! Target: <0.5ms added latency for split tunnel routing decisions
//!
//! Optimizations:
//! - Thread-local packet buffers (eliminates per-packet heap allocs)
//! - ArrayVec for stack-allocated packet work items
//! - Adaptive channel timeout (5ms active, 150ms idle)
//!
//! ```text
//!                    ┌─────────────────────────────────────┐
//!                    │          ndisapi driver             │
//!                    └───────────────┬─────────────────────┘
//!                                    │
//!                                    ▼
//!                    ┌─────────────────────────────────────┐
//!                    │      Packet Reader Thread           │
//!                    │  (reads batches, dispatches by hash)│
//!                    └───────────────┬─────────────────────┘
//!                                    │
//!          ┌─────────────────────────┼─────────────────────────┐
//!          ▼                         ▼                         ▼
//!    ┌───────────┐             ┌───────────┐             ┌───────────┐
//!    │ Worker 0  │             │ Worker 1  │             │ Worker N  │
//!    │ (core 0)  │             │ (core 1)  │             │ (core N)  │
//!    └─────┬─────┘             └─────┬─────┘             └─────┬─────┘
//!          │                         │                         │
//!          └─────────────────────────┼─────────────────────────┘
//!                                    │
//!               ┌────────────────────┴────────────────────┐
//!               ▼                                         ▼
//!       ┌──────────────┐                         ┌──────────────┐
//!       │  V3 UDP Relay│                         │  Passthrough │
//!       │  (Server)    │                         │  (Adapter)   │
//!       └──────────────┘                         └──────────────┘
//! ```

use std::cell::RefCell;
use std::collections::HashMap;
use std::net::Ipv4Addr;
#[cfg(target_os = "windows")]
use std::os::windows::process::CommandExt;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

use arrayvec::ArrayVec;

use super::process_cache::{LockFreeProcessCache, ProcessSnapshot};
use super::process_tracker::{ConnectionKey, Protocol};
use super::tso_recovery::{delete_tso_marker, write_tso_marker};
use super::{VpnError, VpnResult};
use crate::geolocation::is_roblox_game_server_ip;

// ============================================================================
// ZERO-ALLOCATION BUFFER MANAGEMENT
// ============================================================================

/// Maximum Ethernet frame size (MTU 1500 + headers)
const MAX_PACKET_SIZE: usize = 1600;

/// Thread-local pre-allocated buffer to eliminate per-packet heap allocations
/// Used for checksum fixup on tunneled packets
thread_local! {
    /// Buffer for packet processing (checksum offload fix)
    static PACKET_BUFFER: RefCell<[u8; MAX_PACKET_SIZE]> = RefCell::new([0u8; MAX_PACKET_SIZE]);
}

use windows::Win32::Foundation::{CloseHandle, HANDLE};
use windows::Win32::NetworkManagement::IpHelper::{GetAdaptersInfo, IP_ADAPTER_INFO};
use windows::Win32::System::Threading::{
    CreateEventW, ResetEvent, SetThreadAffinityMask, WaitForSingleObject,
};

/// Packet work item sent to workers
/// Uses ArrayVec for stack allocation - avoids heap allocation per packet
struct PacketWork {
    /// Raw packet data (Ethernet frame) - stack allocated, max 1600 bytes
    data: ArrayVec<u8, MAX_PACKET_SIZE>,
    /// Whether packet is outbound
    is_outbound: bool,
    /// Physical adapter internal name (GUID) - shared across all work items
    /// Using Arc to avoid copying the string for every packet
    physical_adapter_name: Arc<String>,
    /// Routing decision computed in the reader thread.
    /// When true, the worker should tunnel/relay this packet (unless auto-routing bypass is active).
    should_tunnel: bool,
}

/// Per-worker statistics
#[derive(Default)]
pub struct WorkerStats {
    pub packets_processed: AtomicU64,
    pub packets_tunneled: AtomicU64,
    pub packets_bypassed: AtomicU64,
    pub bytes_tunneled: AtomicU64,
    pub bytes_bypassed: AtomicU64,
}

/// Shared network throughput stats (readable from GUI)
#[derive(Clone)]
pub struct ThroughputStats {
    /// Bytes sent through VPN tunnel
    pub bytes_tx: Arc<AtomicU64>,
    /// Bytes received through VPN tunnel
    pub bytes_rx: Arc<AtomicU64>,
    /// Timestamp when stats were started
    pub started_at: std::time::Instant,
}

impl Default for ThroughputStats {
    fn default() -> Self {
        Self {
            bytes_tx: Arc::new(AtomicU64::new(0)),
            bytes_rx: Arc::new(AtomicU64::new(0)),
            started_at: std::time::Instant::now(),
        }
    }
}

impl ThroughputStats {
    /// Reset stats
    pub fn reset(&self) {
        self.bytes_tx.store(0, Ordering::Relaxed);
        self.bytes_rx.store(0, Ordering::Relaxed);
    }

    /// Get current bytes TX
    pub fn get_bytes_tx(&self) -> u64 {
        self.bytes_tx.load(Ordering::Relaxed)
    }

    /// Get current bytes RX
    pub fn get_bytes_rx(&self) -> u64 {
        self.bytes_rx.load(Ordering::Relaxed)
    }

    /// Add to TX counter (called when packet sent through tunnel)
    pub fn add_tx(&self, bytes: u64) {
        self.bytes_tx.fetch_add(bytes, Ordering::Relaxed);
    }

    /// Add to RX counter (called when packet received through tunnel)
    pub fn add_rx(&self, bytes: u64) {
        self.bytes_rx.fetch_add(bytes, Ordering::Relaxed);
    }
}

// ============================================================================
// THREAD JOIN WITH TIMEOUT
// ============================================================================

/// Timeout for thread join operations during stop()
const THREAD_JOIN_TIMEOUT: Duration = Duration::from_secs(3);

/// Join a thread with a timeout using a polling approach
///
/// Since Rust's JoinHandle doesn't have a native timeout, we use a polling strategy:
/// - Check if the thread is finished every 100ms
/// - If timeout is reached, log a warning and return false (thread still running)
/// - This prevents stop() from hanging indefinitely if a thread is stuck
///
/// STABILITY FIX: On timeout, we explicitly forget the JoinHandle to detach the thread.
/// This is safer than letting the handle drop (which would call join and block forever).
/// The detached thread will be cleaned up when the process exits.
fn join_with_timeout(handle: JoinHandle<()>, name: &str) -> bool {
    let start = Instant::now();
    let poll_interval = Duration::from_millis(100);

    // First, try to join immediately in case thread already finished
    if handle.is_finished() {
        let _ = handle.join();
        return true;
    }

    // Poll until timeout
    while start.elapsed() < THREAD_JOIN_TIMEOUT {
        if handle.is_finished() {
            let _ = handle.join();
            log::debug!("{} thread joined successfully", name);
            return true;
        }
        thread::sleep(poll_interval);
    }

    // Timeout reached - thread is stuck
    log::error!(
        "STABILITY: {} thread did not stop within {:?} - detaching thread to prevent hang",
        name,
        THREAD_JOIN_TIMEOUT
    );

    // CRITICAL: Forget the handle to detach the thread instead of blocking on drop
    // This prevents the app from hanging during shutdown, at the cost of leaking the thread.
    // The thread will be forcibly terminated when the process exits.
    std::mem::forget(handle);

    false
}

/// Parallel packet interceptor
pub struct ParallelInterceptor {
    /// Number of worker threads (typically = CPU cores)
    num_workers: usize,
    /// Lock-free process cache shared by all workers
    process_cache: Arc<LockFreeProcessCache>,
    /// Stop flag
    stop_flag: Arc<AtomicBool>,
    /// Worker thread handles
    worker_handles: Vec<JoinHandle<()>>,
    /// Reader thread handle
    reader_handle: Option<JoinHandle<()>>,
    /// Cache refresher thread handle
    refresher_handle: Option<JoinHandle<()>>,
    /// Physical adapter index
    physical_adapter_idx: Option<usize>,
    /// Physical adapter internal name (GUID) for cross-thread lookup
    physical_adapter_name: Option<String>,
    /// Physical adapter friendly name (e.g., "Ethernet") for offload control
    physical_adapter_friendly_name: Option<String>,
    /// Whether we disabled TSO on the physical adapter (to restore on cleanup)
    tso_was_disabled: bool,
    /// Whether we disabled IPv6 on the physical adapter (to restore on cleanup)
    ipv6_was_disabled: bool,
    /// Interface index of the adapter with the default route (for validation)
    default_route_if_index: Option<u32>,
    /// VPN adapter index
    vpn_adapter_idx: Option<usize>,
    /// Whether interceptor is active
    active: bool,
    /// Per-worker stats
    worker_stats: Vec<Arc<WorkerStats>>,
    /// Global stats
    total_packets: AtomicU64,
    total_tunneled: AtomicU64,
    total_injected: AtomicU64,
    /// Shared throughput stats for GUI
    throughput_stats: ThroughputStats,
    /// Context for V3 UDP relay (unencrypted, lowest latency)
    relay_ctx: Option<Arc<super::udp_relay::UdpRelay>>,
    /// Inbound receiver thread handle (reads from UdpRelay)
    inbound_receiver_handle: Option<JoinHandle<()>>,
    /// Detected game server IPs (for notification purposes)
    detected_game_servers: Arc<parking_lot::RwLock<std::collections::HashSet<std::net::Ipv4Addr>>>,
    /// Flag to trigger immediate cache refresh (set by ETW when game process detected)
    /// This enables instant detection without polling - ExitLag-style efficiency
    refresh_now_flag: Arc<AtomicBool>,
    /// Condvar to wake the cache refresher thread instead of 50ms polling
    refresh_condvar: Arc<(std::sync::Mutex<bool>, std::sync::Condvar)>,
    /// Auto-router for automatic relay switching based on game server region
    auto_router: Option<Arc<super::auto_routing::AutoRouter>>,
}

impl ParallelInterceptor {
    /// Create new parallel interceptor
    pub fn new(tunnel_apps: Vec<String>) -> Self {
        // Use physical cores only (hyperthreading doesn't help packet processing)
        // Cap at 4 workers - more threads = more overhead with diminishing returns
        // ExitLag-style efficiency: fewer threads, smarter scheduling
        let physical_cores = num_cpus::get_physical();
        let num_workers = physical_cores.min(4).max(1);

        log::info!(
            "Creating parallel interceptor with {} workers (CPUs: {})",
            num_workers,
            num_cpus::get(),
        );

        let worker_stats: Vec<Arc<WorkerStats>> = (0..num_workers)
            .map(|_| Arc::new(WorkerStats::default()))
            .collect();

        Self {
            num_workers,
            process_cache: Arc::new(LockFreeProcessCache::new(tunnel_apps)),
            stop_flag: Arc::new(AtomicBool::new(false)),
            worker_handles: Vec::new(),
            reader_handle: None,
            refresher_handle: None,
            physical_adapter_idx: None,
            physical_adapter_name: None,
            physical_adapter_friendly_name: None,
            tso_was_disabled: false,
            ipv6_was_disabled: false,
            default_route_if_index: None,
            vpn_adapter_idx: None,
            active: false,
            worker_stats,
            total_packets: AtomicU64::new(0),
            total_tunneled: AtomicU64::new(0),
            total_injected: AtomicU64::new(0),
            throughput_stats: ThroughputStats::default(),
            relay_ctx: None,
            inbound_receiver_handle: None,
            detected_game_servers: Arc::new(parking_lot::RwLock::new(
                std::collections::HashSet::new(),
            )),
            refresh_now_flag: Arc::new(AtomicBool::new(false)),
            refresh_condvar: Arc::new((std::sync::Mutex::new(false), std::sync::Condvar::new())),
            auto_router: None,
        }
    }

    /// Trigger immediate cache refresh (call when ETW detects game process)
    /// This is the key to instant detection without polling
    pub fn trigger_refresh(&self) {
        self.refresh_now_flag.store(true, Ordering::Release);
        // Wake the cache refresher thread via Condvar
        let (lock, cvar) = &*self.refresh_condvar;
        if let Ok(mut signaled) = lock.lock() {
            *signaled = true;
            cvar.notify_one();
        }
    }

    /// Get list of detected game server IPs (for notifications)
    pub fn get_detected_game_servers(&self) -> Vec<std::net::Ipv4Addr> {
        self.detected_game_servers.read().iter().copied().collect()
    }

    /// Clear detected game servers (call on disconnect)
    pub fn clear_detected_game_servers(&self) {
        self.detected_game_servers.write().clear();
    }

    /// Add a detected game server IP (called from worker threads)
    fn record_game_server(&self, ip: std::net::Ipv4Addr) {
        let mut servers = self.detected_game_servers.write();
        if servers.insert(ip) {
            log::info!("New game server detected: {}", ip);
        }
    }

    /// Get throughput stats (cloneable, for GUI access)
    pub fn get_throughput_stats(&self) -> ThroughputStats {
        self.throughput_stats.clone()
    }

    /// Get physical adapter name (for UI diagnostics)
    pub fn get_physical_adapter_name(&self) -> Option<String> {
        self.physical_adapter_friendly_name.clone()
    }

    /// Get diagnostic info for UI display
    ///
    /// Returns: (adapter_name, has_default_route, packets_tunneled, packets_bypassed)
    pub fn get_diagnostics(&self) -> (Option<String>, bool, u64, u64) {
        let adapter_name = self.physical_adapter_friendly_name.clone();
        let has_default_route = self.default_route_if_index.is_some();

        // Sum up stats from all workers
        let mut tunneled = 0u64;
        let mut bypassed = 0u64;
        for stats in &self.worker_stats {
            tunneled += stats.packets_tunneled.load(Ordering::Relaxed);
            bypassed += stats.packets_bypassed.load(Ordering::Relaxed);
        }

        (adapter_name, has_default_route, tunneled, bypassed)
    }

    /// Set UDP relay context for V3 mode (unencrypted relay)
    ///
    /// This allows workers to forward packets directly via UDP relay
    /// without encryption. Used for V3 routing mode (lowest latency).
    pub fn set_relay_context(&mut self, relay: Arc<super::udp_relay::UdpRelay>) {
        log::info!(
            "Set relay context: server={}, session={:016x}",
            relay.relay_addr(),
            relay.session_id_u64()
        );
        self.relay_ctx = Some(relay);
    }

    /// Get the relay context for external use (e.g., inbound receiver)
    pub fn get_relay_context(&self) -> Option<Arc<super::udp_relay::UdpRelay>> {
        self.relay_ctx.clone()
    }

    /// Switch the relay server address for auto-routing.
    /// This atomically updates the relay address that all workers use.
    /// Workers will send their next packet to the new address.
    pub fn switch_relay_addr(&self, new_addr: std::net::SocketAddr) -> bool {
        if let Some(ref relay) = self.relay_ctx {
            relay.switch_relay(new_addr);
            true
        } else {
            log::warn!("Cannot switch relay: no relay context set");
            false
        }
    }

    /// Get the current relay address (for auto-routing comparison)
    pub fn current_relay_addr(&self) -> Option<std::net::SocketAddr> {
        self.relay_ctx.as_ref().map(|r| r.relay_addr())
    }

    /// Set the auto-router for automatic relay switching based on game server region
    pub fn set_auto_router(&mut self, router: Arc<super::auto_routing::AutoRouter>) {
        self.auto_router = Some(router);
    }

    /// Check if driver is available
    pub fn check_driver_available() -> bool {
        match ndisapi::Ndisapi::new("NDISRD") {
            Ok(_) => {
                log::info!("Windows Packet Filter driver available");
                true
            }
            Err(e) => {
                log::warn!("Windows Packet Filter driver not available: {}", e);
                false
            }
        }
    }

    /// Initialize interceptor
    pub fn initialize(&mut self) -> VpnResult<()> {
        if !Self::check_driver_available() {
            return Err(VpnError::SplitTunnelNotAvailable);
        }
        log::info!("Parallel interceptor initialized");
        Ok(())
    }

    /// Configure with VPN adapter
    pub fn configure(
        &mut self,
        vpn_adapter_name: &str,
        tunnel_apps: Vec<String>,
        vpn_adapter_luid: u64,
    ) -> VpnResult<()> {
        log::info!(
            "Configuring parallel interceptor for VPN adapter: {} (LUID: {})",
            vpn_adapter_name,
            vpn_adapter_luid
        );

        // Update tunnel apps in cache
        Arc::get_mut(&mut self.process_cache)
            .ok_or_else(|| VpnError::SplitTunnel("Cache in use".to_string()))?
            .set_tunnel_apps(tunnel_apps);

        // Retry adapter detection with progressive backoff
        // The Wintun adapter may not be immediately visible to NDIS after creation,
        // especially when the app is launched via UAC elevation (v0.9.11+)
        // On some systems, Windows networking APIs need time to recognize new adapters
        const MAX_RETRIES: u32 = 5;
        const RETRY_DELAYS_MS: [u64; 5] = [500, 750, 1000, 1500, 2000]; // Progressive backoff

        let mut last_error = String::new();

        for attempt in 1..=MAX_RETRIES {
            match self.find_adapters(vpn_adapter_name, vpn_adapter_luid) {
                Ok(()) => {
                    if attempt > 1 {
                        log::info!(
                            "Adapter detection succeeded on attempt {} (after {}ms total delay)",
                            attempt,
                            RETRY_DELAYS_MS[..attempt as usize - 1].iter().sum::<u64>()
                        );
                    } else {
                        log::info!("Adapter detection succeeded on first attempt");
                    }
                    return Ok(());
                }
                Err(e) => {
                    last_error = e.to_string();
                    if attempt < MAX_RETRIES {
                        let delay = RETRY_DELAYS_MS[attempt as usize - 1];
                        log::warn!(
                            "Adapter detection failed (attempt {}/{}): {}. Retrying in {}ms...",
                            attempt,
                            MAX_RETRIES,
                            e,
                            delay
                        );
                        std::thread::sleep(std::time::Duration::from_millis(delay));
                    }
                }
            }
        }

        // Final error with diagnostic info
        log::error!(
            "Adapter detection failed after {} attempts (total wait: {}ms). Last error: {}",
            MAX_RETRIES,
            RETRY_DELAYS_MS.iter().sum::<u64>(),
            last_error
        );
        log::error!(
            "This may indicate the Wintun adapter was not created successfully, or Windows networking APIs are slow to update."
        );

        Err(VpnError::SplitTunnel(format!(
            "Failed to find VPN adapter after {} attempts: {}",
            MAX_RETRIES, last_error
        )))
    }

    /// Get the interface index that has the default route (0.0.0.0/0)
    /// This ensures we intercept the correct adapter even on multi-NIC systems
    fn get_default_route_interface_index() -> Option<u32> {
        use windows::Win32::Foundation::*;
        use windows::Win32::NetworkManagement::IpHelper::*;

        unsafe {
            // Get routing table size
            let mut size: u32 = 0;
            let _ = GetIpForwardTable(None, &mut size, false);

            if size == 0 {
                return None;
            }

            // Allocate buffer
            let mut buffer = vec![0u8; size as usize];
            let table = buffer.as_mut_ptr() as *mut MIB_IPFORWARDTABLE;

            if GetIpForwardTable(Some(table), &mut size, false) != NO_ERROR.0 {
                return None;
            }

            let num_entries = (*table).dwNumEntries as usize;
            let entries = std::slice::from_raw_parts((*table).table.as_ptr(), num_entries);

            // Find the default route (destination 0.0.0.0 with lowest metric)
            let mut best_metric = u32::MAX;
            let mut best_if_index = None;

            for row in entries {
                // Default route: destination 0.0.0.0, mask 0.0.0.0, non-zero next hop
                if row.dwForwardDest == 0 && row.dwForwardMask == 0 && row.dwForwardNextHop != 0 {
                    if row.dwForwardMetric1 < best_metric {
                        best_metric = row.dwForwardMetric1;
                        best_if_index = Some(row.dwForwardIfIndex);
                    }
                }
            }

            if let Some(idx) = best_if_index {
                log::info!(
                    "Default route is on interface index {} (metric: {})",
                    idx,
                    best_metric
                );
            }

            best_if_index
        }
    }

    /// Get interface index from adapter GUID/name using GetAdaptersAddresses
    fn get_adapter_interface_index(adapter_guid: &str) -> Option<u32> {
        use windows::Win32::NetworkManagement::IpHelper::*;
        use windows::Win32::Networking::WinSock::AF_INET;

        unsafe {
            let mut size: u32 = 0;
            let _ = GetAdaptersAddresses(
                AF_INET.0 as u32,
                GAA_FLAG_INCLUDE_PREFIX,
                None,
                None,
                &mut size,
            );

            if size == 0 {
                return None;
            }

            let mut buffer = vec![0u8; size as usize];
            let adapter_addresses = buffer.as_mut_ptr() as *mut IP_ADAPTER_ADDRESSES_LH;

            if GetAdaptersAddresses(
                AF_INET.0 as u32,
                GAA_FLAG_INCLUDE_PREFIX,
                None,
                Some(adapter_addresses),
                &mut size,
            ) != 0
            {
                return None;
            }

            let mut current = adapter_addresses;
            while !current.is_null() {
                let adapter = &*current;

                // Get adapter name (GUID format like {GUID})
                let name = adapter.AdapterName.to_string().unwrap_or_default();

                // Match by exact GUID comparison (strip \DEVICE\ prefix and compare)
                let guid_from_adapter = adapter_guid.trim_start_matches("\\DEVICE\\");
                if guid_from_adapter == name
                    || guid_from_adapter.trim_matches('{').trim_matches('}')
                        == name.trim_matches('{').trim_matches('}')
                {
                    return Some(adapter.Anonymous1.Anonymous.IfIndex);
                }

                current = adapter.Next;
            }
        }

        None
    }

    /// Internal adapter detection logic
    ///
    /// Identifies adapters by:
    /// 1. LUID matching (most reliable - directly identifies our Wintun adapter)
    /// 2. Name matching (friendly name or internal name contains "swifttunnel" or "wintun")
    /// 3. Default route matching (prioritize adapter with default route)
    fn find_adapters(&mut self, vpn_adapter_name: &str, vpn_adapter_luid: u64) -> VpnResult<()> {
        // Get default route interface first - this is the adapter we MUST intercept
        let default_route_if_index = Self::get_default_route_interface_index();
        self.default_route_if_index = default_route_if_index;

        if let Some(idx) = default_route_if_index {
            log::info!(
                "Will prioritize adapter with interface index {} (has default route)",
                idx
            );
        } else {
            log::warn!("Could not determine default route interface - will use name-based scoring");
        }
        // Find adapters
        let driver = ndisapi::Ndisapi::new("NDISRD")
            .map_err(|e| VpnError::SplitTunnel(format!("Failed to open driver: {}", e)))?;

        let adapters = driver
            .get_tcpip_bound_adapters_info()
            .map_err(|e| VpnError::SplitTunnel(format!("Failed to enumerate adapters: {}", e)))?;

        log::info!("Found {} adapters", adapters.len());

        let mut vpn_adapter: Option<(usize, String)> = None;
        // (idx, friendly_name, internal_name, score)
        let mut physical_candidates: Vec<(usize, String, String, i32)> = Vec::new();

        for (idx, adapter) in adapters.iter().enumerate() {
            let internal_name = adapter.get_name();
            // Try both GetAdaptersInfo and GetAdaptersAddresses for friendly name
            let friendly_name = get_adapter_friendly_name(&internal_name)
                .or_else(|| get_adapter_friendly_name_v2(&internal_name))
                .unwrap_or_default();

            log::info!(
                "  Adapter {}: '{}' (internal: {})",
                idx,
                friendly_name,
                internal_name
            );

            let name_lower = internal_name.to_lowercase();
            let friendly_lower = friendly_name.to_lowercase();

            // Check if this is our VPN adapter (SwiftTunnel/Wintun)
            // Priority order:
            // 1. LUID matching (most reliable - directly identifies our Wintun adapter)
            // 2. Name matching (friendly name or internal name contains keywords)
            //
            // CRITICAL FIX (v0.9.15): LUID matching resolves adapter detection failures
            // that occurred after v0.9.11 for some users. The issue was that:
            // - GetAdaptersInfo sometimes fails to find newly created Wintun adapters
            // - This caused friendly_name to be empty
            // - Name-based matching failed because internal_name is just a GUID
            // - The LUID is always available and uniquely identifies our adapter
            let is_vpn_by_luid = vpn_adapter_luid != 0
                && check_adapter_matches_luid(&internal_name, vpn_adapter_luid);
            let is_vpn_by_name = name_lower.contains(&vpn_adapter_name.to_lowercase())
                || name_lower.contains("swifttunnel")
                || name_lower.contains("wintun")
                || friendly_lower.contains(&vpn_adapter_name.to_lowercase())
                || friendly_lower.contains("swifttunnel")
                || friendly_lower.contains("wintun");
            let is_vpn = is_vpn_by_luid || is_vpn_by_name;

            if is_vpn_by_luid && !is_vpn_by_name {
                log::info!("    -> VPN adapter identified by LUID (friendly name unavailable)");
            }

            // Filter out virtual adapters (VPNs, tunnels, etc.)
            // These should NOT be selected as the physical adapter
            // IMPORTANT: Do NOT filter based on empty friendly_name - that would skip
            // adapters where the name lookup failed (including potentially our VPN adapter)
            let is_virtual = name_lower.contains("loopback")
                || friendly_lower.contains("loopback")
                || friendly_lower.contains("isatap")
                || friendly_lower.contains("teredo")
                // Third-party VPN adapters
                || friendly_lower.contains("radmin")      // Radmin VPN
                || friendly_lower.contains("hamachi")     // LogMeIn Hamachi
                || friendly_lower.contains("zerotier")    // ZeroTier
                || friendly_lower.contains("tailscale")   // Tailscale
                || friendly_lower.contains("wireguard")   // WireGuard (not ours)
                || friendly_lower.contains("openvpn")     // OpenVPN
                || friendly_lower.contains("tap-windows") // OpenVPN TAP
                || friendly_lower.contains("nordvpn")     // NordVPN
                || friendly_lower.contains("expressvpn")  // ExpressVPN
                || friendly_lower.contains("surfshark")   // Surfshark
                || friendly_lower.contains("proton")      // ProtonVPN
                || friendly_lower.contains("mullvad")     // Mullvad
                || friendly_lower.contains("private internet") // PIA
                || friendly_lower.contains("cyberghost")  // CyberGhost
                || friendly_lower.contains("famatech")    // Famatech (Radmin parent company)
                // Generic virtual adapter detection (but NOT if friendly name is empty -
                // that could be our VPN adapter where name lookup failed)
                || (!friendly_lower.is_empty() && (
                    friendly_lower.contains("virtual")
                    || friendly_lower.contains("vpn")
                    || friendly_lower.contains("tunnel")
                ));

            if is_vpn {
                log::info!("    -> VPN adapter (SwiftTunnel/Wintun)");
                vpn_adapter = Some((idx, friendly_name.clone()));
            } else if is_virtual {
                log::info!("    -> Skipped (virtual/VPN adapter)");
            } else if friendly_name.is_empty() {
                // Unknown adapter with no friendly name - could be anything
                // Don't use as physical adapter but also don't skip entirely
                log::info!("    -> Skipped (unknown adapter, no friendly name)");
            } else {
                let mut score = 0;

                // CRITICAL FIX (v0.9.25): Prioritize adapter with default route
                // This fixes the bug where users with multiple NICs (e.g., disconnected Ethernet + WiFi)
                // had traffic going through the wrong adapter
                let adapter_if_index = Self::get_adapter_interface_index(&internal_name);
                let has_default_route = adapter_if_index.is_some()
                    && default_route_if_index.is_some()
                    && adapter_if_index == default_route_if_index;

                if has_default_route {
                    score += 1000; // Massive bonus - this is THE adapter internet traffic uses
                    log::info!("    -> Has DEFAULT ROUTE (priority +1000)");
                }

                if friendly_lower.contains("ethernet")
                    || friendly_lower.contains("intel")
                    || friendly_lower.contains("realtek")
                    || friendly_lower.contains("broadcom")
                {
                    score += 100;
                }
                if friendly_lower.contains("wi-fi")
                    || friendly_lower.contains("wifi")
                    || friendly_lower.contains("wireless")
                {
                    score += 80; // WiFi is common for laptops
                }
                if !friendly_name.is_empty() {
                    score += 50;
                }
                score += (10 - idx.min(10)) as i32;
                log::info!(
                    "    -> Physical adapter candidate (score: {}, has_default_route: {})",
                    score,
                    has_default_route
                );
                physical_candidates.push((
                    idx,
                    friendly_name.clone(),
                    internal_name.to_string(),
                    score,
                ));
            }
        }

        // Select physical adapter - MUST have default route if available
        let selected = physical_candidates.iter().max_by_key(|x| x.3);

        if let Some((idx, friendly_name, internal_name, score)) = selected {
            // Warn if selected adapter doesn't have default route but others exist
            let has_default = *score >= 1000;
            if !has_default && default_route_if_index.is_some() {
                log::warn!(
                    "Selected adapter '{}' does NOT have the default route - traffic may not be intercepted!",
                    friendly_name
                );
                log::warn!(
                    "This could cause split tunnel to fail. Check if the correct network adapter is being used."
                );
            }

            self.physical_adapter_idx = Some(*idx);
            self.physical_adapter_name = Some(internal_name.clone());
            self.physical_adapter_friendly_name = Some(friendly_name.clone());
            log::info!(
                "Selected physical adapter: {} (index {}, internal: '{}', score: {})",
                friendly_name,
                idx,
                internal_name,
                score
            );
        } else {
            return Err(VpnError::SplitTunnel(
                "No physical adapter found".to_string(),
            ));
        }

        // Set VPN adapter (not required for V3 mode where LUID=0)
        if let Some((idx, name)) = vpn_adapter {
            self.vpn_adapter_idx = Some(idx);
            log::info!("Found VPN adapter: {} (index {})", name, idx);
        } else if vpn_adapter_luid == 0 {
            // V3 mode: No Wintun adapter needed - we use UDP relay instead
            log::info!("V3 mode: No VPN adapter required (LUID=0)");
            self.vpn_adapter_idx = None;
        } else {
            return Err(VpnError::SplitTunnel(format!(
                "VPN adapter '{}' not found. Ensure the Wintun adapter was created successfully.",
                vpn_adapter_name
            )));
        }

        Ok(())
    }

    /// Run a PowerShell command with a timeout
    ///
    /// Returns true if command succeeded, false otherwise.
    /// Uses spawn + try_wait loop to implement timeout without extra dependencies.
    fn run_powershell_with_timeout(script: &str, timeout_secs: u64) -> bool {
        use std::time::{Duration, Instant};

        let mut child = match std::process::Command::new("powershell")
            .args(["-NoProfile", "-NonInteractive", "-Command", script])
            .creation_flags(0x08000000) // CREATE_NO_WINDOW
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped())
            .spawn()
        {
            Ok(child) => child,
            Err(e) => {
                log::warn!("Failed to spawn PowerShell: {}", e);
                return false;
            }
        };

        let start = Instant::now();
        let timeout = Duration::from_secs(timeout_secs);

        // Poll for completion with timeout
        loop {
            match child.try_wait() {
                Ok(Some(status)) => {
                    // Process finished
                    if status.success() {
                        return true;
                    } else {
                        // Try to get stderr for logging
                        if let Some(mut stderr) = child.stderr.take() {
                            use std::io::Read;
                            let mut err_msg = String::new();
                            let _ = stderr.read_to_string(&mut err_msg);
                            if !err_msg.is_empty() {
                                log::warn!("PowerShell error: {}", err_msg.trim());
                            }
                        }
                        return false;
                    }
                }
                Ok(None) => {
                    // Still running - check timeout
                    if start.elapsed() >= timeout {
                        log::warn!(
                            "PowerShell timed out after {}s, killing process",
                            timeout_secs
                        );
                        let _ = child.kill();
                        let _ = child.wait(); // Reap the process
                        return false;
                    }
                    // Sleep briefly before next poll (50ms)
                    std::thread::sleep(Duration::from_millis(50));
                }
                Err(e) => {
                    log::warn!("Error waiting for PowerShell: {}", e);
                    let _ = child.kill();
                    return false;
                }
            }
        }
    }

    /// Disable TCP Segmentation Offload (TSO/LSO) on the physical adapter
    ///
    /// Modern NICs use TSO to create large "super-packets" (up to 64KB) that get
    /// segmented by hardware. When we intercept at the NDIS layer, we see these
    /// un-segmented packets BEFORE the NIC processes them. Our buffers are sized
    /// for normal MTU packets (1600 bytes), so TSO packets get truncated and corrupt
    /// the TCP stream.
    ///
    /// Disabling TSO forces the OS to segment packets in software before they reach
    /// the NIC, ensuring all packets are MTU-sized when we intercept them.
    pub fn disable_adapter_offload(&mut self) -> VpnResult<()> {
        let friendly_name = match &self.physical_adapter_friendly_name {
            Some(name) => name.clone(),
            None => {
                log::warn!("No physical adapter friendly name available, skipping TSO disable");
                return Ok(());
            }
        };

        log::info!("Disabling TSO/LSO on adapter: {}", friendly_name);

        // Disable Large Send Offload v2 for IPv4 and IPv6
        // These are the standard registry keywords for TSO/LSO
        let script = format!(
            r#"
            $ErrorActionPreference = 'SilentlyContinue'
            $adapter = '{}'

            # Disable LSO v2 IPv4
            Set-NetAdapterAdvancedProperty -Name $adapter -RegistryKeyword '*LsoV2IPv4' -RegistryValue 0 2>$null

            # Disable LSO v2 IPv6
            Set-NetAdapterAdvancedProperty -Name $adapter -RegistryKeyword '*LsoV2IPv6' -RegistryValue 0 2>$null

            # Also disable TCP/UDP checksum offload to ensure we handle all checksums
            # (Some NICs have separate settings for Tx and Rx)
            Set-NetAdapterAdvancedProperty -Name $adapter -RegistryKeyword '*TCPChecksumOffloadIPv4' -RegistryValue 0 2>$null
            Set-NetAdapterAdvancedProperty -Name $adapter -RegistryKeyword '*UDPChecksumOffloadIPv4' -RegistryValue 0 2>$null
            Set-NetAdapterAdvancedProperty -Name $adapter -RegistryKeyword '*TCPChecksumOffloadIPv6' -RegistryValue 0 2>$null
            Set-NetAdapterAdvancedProperty -Name $adapter -RegistryKeyword '*UDPChecksumOffloadIPv6' -RegistryValue 0 2>$null

            Write-Host 'Offload disabled'
            "#,
            friendly_name.replace("'", "''") // Escape single quotes
        );

        // 5 second timeout to prevent indefinite hangs
        if Self::run_powershell_with_timeout(&script, 5) {
            log::info!("TSO/LSO disabled successfully on {}", friendly_name);
            // Write marker file BEFORE setting flag - ensures recovery works if we crash
            // between these two operations (marker exists = TSO was disabled)
            write_tso_marker(&friendly_name);
            self.tso_was_disabled = true;
        } else {
            log::warn!(
                "Failed to disable TSO (non-fatal) - adapter may not support these settings"
            );
            // Don't fail - some adapters don't support these settings
        }

        Ok(())
    }

    /// Re-enable TCP Segmentation Offload on the physical adapter
    ///
    /// Called when the VPN disconnects to restore normal NIC performance.
    pub fn enable_adapter_offload(&mut self) {
        if !self.tso_was_disabled {
            return;
        }

        let friendly_name = match &self.physical_adapter_friendly_name {
            Some(name) => name.clone(),
            None => return,
        };

        log::info!("Re-enabling TSO/LSO on adapter: {}", friendly_name);

        let script = format!(
            r#"
            $ErrorActionPreference = 'SilentlyContinue'
            $adapter = '{}'

            # Re-enable LSO v2
            Set-NetAdapterAdvancedProperty -Name $adapter -RegistryKeyword '*LsoV2IPv4' -RegistryValue 1 2>$null
            Set-NetAdapterAdvancedProperty -Name $adapter -RegistryKeyword '*LsoV2IPv6' -RegistryValue 1 2>$null

            # Re-enable checksum offload
            Set-NetAdapterAdvancedProperty -Name $adapter -RegistryKeyword '*TCPChecksumOffloadIPv4' -RegistryValue 3 2>$null
            Set-NetAdapterAdvancedProperty -Name $adapter -RegistryKeyword '*UDPChecksumOffloadIPv4' -RegistryValue 3 2>$null
            Set-NetAdapterAdvancedProperty -Name $adapter -RegistryKeyword '*TCPChecksumOffloadIPv6' -RegistryValue 3 2>$null
            Set-NetAdapterAdvancedProperty -Name $adapter -RegistryKeyword '*UDPChecksumOffloadIPv6' -RegistryValue 3 2>$null

            Write-Host 'Offload enabled'
            "#,
            friendly_name.replace("'", "''")
        );

        // 5 second timeout
        if Self::run_powershell_with_timeout(&script, 5) {
            log::info!("TSO/LSO re-enabled on {}", friendly_name);
            // Delete marker file - TSO successfully restored
            delete_tso_marker();
        } else {
            log::warn!("Failed to re-enable TSO - manual re-enable may be needed");
            // Still delete marker to avoid repeated restore attempts on next startup
            delete_tso_marker();
        }

        self.tso_was_disabled = false;
    }

    /// Disable IPv6 on the physical adapter
    ///
    /// SwiftTunnel is IPv4-only. If IPv6 is enabled, Roblox or Windows may prefer IPv6,
    /// causing traffic to bypass our IPv4 tunnel entirely. Disabling IPv6 on the physical
    /// adapter ensures all traffic goes through our interceptor.
    ///
    /// This is a common cause of "detection works but tunneling fails" - the process is
    /// detected, but its IPv6 traffic bypasses the VPN.
    pub fn disable_ipv6(&mut self) -> VpnResult<()> {
        let friendly_name = match &self.physical_adapter_friendly_name {
            Some(name) => name.clone(),
            None => {
                log::warn!("No physical adapter friendly name available, skipping IPv6 disable");
                return Ok(());
            }
        };

        log::info!(
            "Disabling IPv6 on adapter: {} (SwiftTunnel is IPv4-only)",
            friendly_name
        );

        // Disable IPv6 binding on the adapter using netsh
        // This is safer than registry changes and takes effect immediately
        let script = format!(
            r#"
            $ErrorActionPreference = 'SilentlyContinue'
            $adapter = '{}'

            # Disable IPv6 binding on the adapter
            # This uses the Disable-NetAdapterBinding cmdlet which is the cleanest approach
            Disable-NetAdapterBinding -Name $adapter -ComponentId ms_tcpip6 2>$null

            # Verify it was disabled
            $binding = Get-NetAdapterBinding -Name $adapter -ComponentId ms_tcpip6 2>$null
            if ($binding -and -not $binding.Enabled) {{
                Write-Host 'IPv6 disabled'
            }} else {{
                Write-Host 'IPv6 disable may have failed'
            }}
            "#,
            friendly_name.replace("'", "''")
        );

        if Self::run_powershell_with_timeout(&script, 5) {
            log::info!(
                "IPv6 disabled successfully on {} - all traffic will use IPv4",
                friendly_name
            );
            self.ipv6_was_disabled = true;
        } else {
            log::warn!("Failed to disable IPv6 (non-fatal) - IPv6 traffic may bypass VPN");
            // Don't fail - the VPN can still work, just with potential IPv6 leakage
        }

        Ok(())
    }

    /// Re-enable IPv6 on the physical adapter
    ///
    /// Called when the VPN disconnects to restore normal IPv6 connectivity.
    pub fn enable_ipv6(&mut self) {
        if !self.ipv6_was_disabled {
            return;
        }

        let friendly_name = match &self.physical_adapter_friendly_name {
            Some(name) => name.clone(),
            None => return,
        };

        log::info!("Re-enabling IPv6 on adapter: {}", friendly_name);

        let script = format!(
            r#"
            $ErrorActionPreference = 'SilentlyContinue'
            $adapter = '{}'

            # Re-enable IPv6 binding on the adapter
            Enable-NetAdapterBinding -Name $adapter -ComponentId ms_tcpip6 2>$null

            Write-Host 'IPv6 enabled'
            "#,
            friendly_name.replace("'", "''")
        );

        if Self::run_powershell_with_timeout(&script, 5) {
            log::info!("IPv6 re-enabled on {}", friendly_name);
        } else {
            log::warn!(
                "Failed to re-enable IPv6 - manual re-enable may be needed via Network Settings"
            );
        }

        self.ipv6_was_disabled = false;
    }

    /// Start parallel interception
    pub fn start(&mut self) -> VpnResult<()> {
        if self.active {
            return Ok(());
        }

        let physical_idx = self
            .physical_adapter_idx
            .ok_or_else(|| VpnError::SplitTunnel("Physical adapter not configured".to_string()))?;

        log::info!(
            "Starting parallel interceptor with {} workers",
            self.num_workers
        );

        // Disable TSO/LSO on physical adapter BEFORE starting packet capture
        // This prevents the NIC from creating super-packets that exceed our buffer size
        self.disable_adapter_offload()?;

        // Disable IPv6 on physical adapter - SwiftTunnel is IPv4-only
        // This prevents Roblox/Windows from preferring IPv6 and bypassing our tunnel
        self.disable_ipv6()?;

        self.stop_flag.store(false, Ordering::SeqCst);
        self.active = true;

        // Create channels for workers
        let (senders, receivers): (Vec<_>, Vec<_>) = (0..self.num_workers)
            .map(|_| crossbeam_channel::bounded::<PacketWork>(1024))
            .unzip();

        // Start cache refresher thread (single writer)
        let refresher_stop = Arc::clone(&self.stop_flag);
        let refresher_cache = Arc::clone(&self.process_cache);
        let refresh_now = Arc::clone(&self.refresh_now_flag);
        let refresh_condvar = Arc::clone(&self.refresh_condvar);
        self.refresher_handle = Some(thread::spawn(move || {
            run_cache_refresher(
                refresher_cache,
                refresher_stop,
                refresh_now,
                refresh_condvar,
            );
        }));

        // Reset throughput stats on start
        self.throughput_stats.reset();

        // Start worker threads
        for (worker_id, receiver) in receivers.into_iter().enumerate() {
            let stop_flag = Arc::clone(&self.stop_flag);
            let stats = Arc::clone(&self.worker_stats[worker_id]);
            let throughput = self.throughput_stats.clone();
            let relay_ctx = self.relay_ctx.clone();
            let detected_game_servers = Arc::clone(&self.detected_game_servers);
            let auto_router = self.auto_router.clone();

            let handle = thread::spawn(move || {
                // Set CPU affinity for this worker
                set_thread_affinity(worker_id);

                run_packet_worker(
                    worker_id,
                    receiver,
                    stats,
                    throughput,
                    stop_flag,
                    relay_ctx,
                    detected_game_servers,
                    auto_router,
                );
            });

            self.worker_handles.push(handle);
        }

        // Start packet reader/dispatcher thread
        let reader_stop = Arc::clone(&self.stop_flag);
        let num_workers = self.num_workers;
        let reader_cache = Arc::clone(&self.process_cache);
        let reader_worker_stats = self.worker_stats.clone();
        let reader_auto_router = self.auto_router.clone();
        let physical_name =
            Arc::new(self.physical_adapter_name.clone().ok_or_else(|| {
                VpnError::SplitTunnel("Physical adapter name not set".to_string())
            })?);

        self.reader_handle = Some(thread::spawn(move || {
            if let Err(e) = run_packet_reader(
                physical_idx,
                physical_name,
                senders,
                reader_cache,
                reader_worker_stats,
                reader_auto_router,
                reader_stop,
                num_workers,
            ) {
                log::error!("Packet reader error: {}", e);
            }
        }));

        // Start V3 inbound receiver thread (reads from UdpRelay, injects to MSTCP)
        if let Some(ref relay_ctx) = self.relay_ctx {
            let inbound_config = self.create_inbound_config();

            if let Some(config) = inbound_config {
                let relay = Arc::clone(relay_ctx);
                let inbound_stop = Arc::clone(&self.stop_flag);
                let throughput = self.throughput_stats.clone();

                self.inbound_receiver_handle = Some(thread::spawn(move || {
                    run_v3_inbound_receiver(relay, config, inbound_stop, throughput);
                }));
                log::info!("V3 inbound receiver thread started (UDP relay)");
            } else {
                log::warn!("V3 inbound receiver NOT started (failed to create config)");
            }
        } else {
            log::info!("Inbound receiver NOT started (no relay_ctx)");
        }

        log::info!("Parallel interceptor started");
        Ok(())
    }

    /// Stop interception
    pub fn stop(&mut self) {
        if !self.active {
            return;
        }

        log::info!("Stopping parallel interceptor...");
        self.stop_flag.store(true, Ordering::SeqCst);

        // Wait for threads with timeout to prevent hanging on stuck threads
        if let Some(handle) = self.reader_handle.take() {
            join_with_timeout(handle, "Reader");
        }

        for (i, handle) in self.worker_handles.drain(..).enumerate() {
            join_with_timeout(handle, &format!("Worker-{}", i));
        }

        if let Some(handle) = self.refresher_handle.take() {
            join_with_timeout(handle, "Refresher");
        }

        if let Some(handle) = self.inbound_receiver_handle.take() {
            join_with_timeout(handle, "Inbound");
        }

        self.active = false;

        // Log final stats
        let total = self.total_packets.load(Ordering::Relaxed);
        let tunneled = self.total_tunneled.load(Ordering::Relaxed);
        let injected = self.total_injected.load(Ordering::Relaxed);
        log::info!(
            "Parallel interceptor stopped - {} total, {} tunneled ({:.1}%), {} injected",
            total,
            tunneled,
            if total > 0 {
                (tunneled as f64 / total as f64) * 100.0
            } else {
                0.0
            },
            injected
        );

        // Re-enable TSO/LSO on physical adapter
        self.enable_adapter_offload();

        // Re-enable IPv6 on physical adapter
        self.enable_ipv6();
    }

    /// Check if active
    pub fn is_active(&self) -> bool {
        self.active
    }

    /// Get snapshot for external use
    pub fn get_snapshot(&self) -> Arc<ProcessSnapshot> {
        self.process_cache.get_snapshot()
    }

    /// Immediately register a process detected via ETW
    ///
    /// Called when ETW detects a watched process starting. This adds the
    /// PID → name mapping immediately, so when the first packet arrives,
    /// the process is already in our tunnel list.
    ///
    /// This fixes Error 279 when launching Roblox from the website:
    /// - Browser launches RobloxPlayerBeta.exe
    /// - ETW notifies us INSTANTLY (microseconds)
    /// - We register the process here
    /// - First packet arrives → process is already known → tunneled!
    pub fn register_process_immediate(&self, pid: u32, name: String) {
        self.process_cache.register_process_immediate(pid, name);
    }

    /// Create InboundConfig for the optimized inbound receiver
    ///
    /// Returns None if physical adapter cannot be found
    fn create_inbound_config(&self) -> Option<InboundConfig> {
        let physical_name = self.physical_adapter_name.clone()?;

        // Open driver to get adapter MAC
        let driver = match ndisapi::Ndisapi::new("NDISRD") {
            Ok(d) => d,
            Err(e) => {
                log::error!("create_inbound_config: failed to open driver: {}", e);
                return None;
            }
        };

        let adapters = match driver.get_tcpip_bound_adapters_info() {
            Ok(a) => a,
            Err(e) => {
                log::error!("create_inbound_config: failed to get adapters: {}", e);
                return None;
            }
        };

        let adapter_mac: [u8; 6] = match adapters.iter().find(|a| a.get_name() == &physical_name) {
            Some(a) => a.get_hw_address()[0..6].try_into().unwrap_or([0; 6]),
            None => {
                log::error!(
                    "create_inbound_config: physical adapter '{}' not found",
                    physical_name
                );
                return None;
            }
        };

        log::info!(
            "create_inbound_config: adapter={}, MAC={:02X}:{:02X}:{:02X}:{:02X}:{:02X}:{:02X}",
            physical_name,
            adapter_mac[0],
            adapter_mac[1],
            adapter_mac[2],
            adapter_mac[3],
            adapter_mac[4],
            adapter_mac[5],
        );

        Some(InboundConfig {
            physical_adapter_name: physical_name,
            adapter_mac,
        })
    }
}

impl Drop for ParallelInterceptor {
    fn drop(&mut self) {
        self.stop();
    }
}

/// Set thread affinity to specific CPU core
fn set_thread_affinity(core_id: usize) {
    #[cfg(target_os = "windows")]
    unsafe {
        let mask = 1usize << core_id;
        let _ = SetThreadAffinityMask(windows::Win32::System::Threading::GetCurrentThread(), mask);
    }
}

/// Configuration for inbound packet injection
#[derive(Clone)]
struct InboundConfig {
    physical_adapter_name: String,
    adapter_mac: [u8; 6],
}

/// Inject an inbound packet to MSTCP
/// Returns Some(true) on success, Some(false) on error, None if packet should be skipped
fn inject_inbound_packet(
    ip_packet: &[u8],
    config: &InboundConfig,
    adapter_handle: windows::Win32::Foundation::HANDLE,
    driver: &ndisapi::Ndisapi,
    packet_count: u64,
) -> Option<bool> {
    use ndisapi::{DirectionFlags, EthMRequest, IntermediateBuffer};

    if ip_packet.len() < 20 {
        log::warn!(
            "inject_inbound_packet: packet too small ({} bytes)",
            ip_packet.len()
        );
        return None;
    }

    // Log first 10 packets for debugging
    if packet_count < 10 {
        let src_ip =
            std::net::Ipv4Addr::new(ip_packet[12], ip_packet[13], ip_packet[14], ip_packet[15]);
        let dst_ip =
            std::net::Ipv4Addr::new(ip_packet[16], ip_packet[17], ip_packet[18], ip_packet[19]);
        log::debug!(
            "inject_inbound_packet #{}: {} -> {}, proto={}, {} bytes",
            packet_count,
            src_ip,
            dst_ip,
            ip_packet[9],
            ip_packet.len(),
        );
    }

    // Create Ethernet frame (stack-allocated buffer)
    const MAX_ETHER_FRAME: usize = 1622; // 14 header + 1600 payload + 8 padding
    let frame_len = 14 + ip_packet.len();

    if frame_len > MAX_ETHER_FRAME {
        log::warn!("Inbound: packet too large ({} bytes), dropping", frame_len);
        return None;
    }

    let mut ethernet_frame_buf = [0u8; MAX_ETHER_FRAME];
    let ethernet_frame = &mut ethernet_frame_buf[..frame_len];
    ethernet_frame[0..6].copy_from_slice(&config.adapter_mac); // Destination = physical adapter
    ethernet_frame[6..12].copy_from_slice(&[0x02, 0x00, 0x00, 0x00, 0x00, 0x01]); // Locally administered src MAC
    ethernet_frame[12] = 0x08; // EtherType: IPv4
    ethernet_frame[13] = 0x00;
    ethernet_frame[14..].copy_from_slice(ip_packet);

    // Create IntermediateBuffer and inject
    let mut buffer = IntermediateBuffer::default();
    buffer.device_flags = DirectionFlags::PACKET_FLAG_ON_RECEIVE;
    buffer.length = ethernet_frame.len() as u32;
    buffer.buffer.0[..ethernet_frame.len()].copy_from_slice(ethernet_frame);

    let mut to_mstcp: EthMRequest<1> = EthMRequest::new(adapter_handle);
    if to_mstcp.push(&buffer).is_err() {
        log::warn!("Inbound: failed to push buffer");
        return Some(false);
    }

    if let Err(e) = driver.send_packets_to_mstcp::<1>(&to_mstcp) {
        if packet_count < 10 {
            log::warn!("Inbound: send_packets_to_mstcp failed: {:?}", e);
        }
        return Some(false);
    }

    Some(true)
}

/// Packet reader thread - reads from ndisapi and dispatches to workers
fn run_packet_reader(
    physical_idx: usize,
    physical_name: Arc<String>,
    senders: Vec<crossbeam_channel::Sender<PacketWork>>,
    process_cache: Arc<LockFreeProcessCache>,
    worker_stats: Vec<Arc<WorkerStats>>,
    auto_router: Option<Arc<super::auto_routing::AutoRouter>>,
    stop_flag: Arc<AtomicBool>,
    num_workers: usize,
) -> VpnResult<()> {
    use ndisapi::{DirectionFlags, EthMRequest, EthMRequestMut, FilterFlags, IntermediateBuffer};

    const BATCH_SIZE: usize = 64; // Read up to 64 packets per syscall

    log::info!(
        "Packet reader started (physical idx: {}, name: '{}', {} workers)",
        physical_idx,
        physical_name,
        num_workers
    );

    // Routing decisions are made here (reader thread) so bypass traffic never hits workers.
    let mut snapshot = process_cache.get_snapshot();
    let mut snapshot_version = snapshot.version;
    let mut inline_cache: InlineCache = std::collections::HashMap::with_capacity(1024);

    let driver = ndisapi::Ndisapi::new("NDISRD")
        .map_err(|e| VpnError::SplitTunnel(format!("Failed to open driver: {}", e)))?;

    let adapters = driver
        .get_tcpip_bound_adapters_info()
        .map_err(|e| VpnError::SplitTunnel(format!("Failed to get adapters: {}", e)))?;

    if physical_idx >= adapters.len() {
        return Err(VpnError::SplitTunnel(
            "Physical adapter index out of range".to_string(),
        ));
    }

    let physical_handle = adapters[physical_idx].get_handle();

    // RAII guard for Windows HANDLE to prevent leaks on error
    struct HandleGuard(HANDLE);
    impl Drop for HandleGuard {
        fn drop(&mut self) {
            // Check for null (0) and INVALID_HANDLE_VALUE (-1 as isize cast to pointer)
            if self.0.0 as isize != 0 && self.0.0 as isize != -1 {
                unsafe {
                    let _ = CloseHandle(self.0);
                }
            }
        }
    }

    // Create event for packet notification
    let event: HANDLE = unsafe {
        CreateEventW(None, true, false, None)
            .map_err(|e| VpnError::SplitTunnel(format!("Failed to create event: {}", e)))?
    };

    // Wrap in RAII guard - will close handle if we return early due to error
    let event_guard = HandleGuard(event);

    driver
        .set_packet_event(physical_handle, event)
        .map_err(|e| VpnError::SplitTunnel(format!("Failed to set packet event: {}", e)))?;

    // Set adapter to tunnel mode
    driver
        .set_adapter_mode(physical_handle, FilterFlags::MSTCP_FLAG_SENT_RECEIVE_TUNNEL)
        .map_err(|e| VpnError::SplitTunnel(format!("Failed to set adapter mode: {}", e)))?;

    // Transfer ownership from guard - we'll close manually in cleanup
    std::mem::forget(event_guard);

    let mut packets: Vec<IntermediateBuffer> = vec![Default::default(); BATCH_SIZE];
    let mut passthrough_to_adapter: EthMRequest<BATCH_SIZE>;
    let mut passthrough_to_mstcp: EthMRequest<BATCH_SIZE>;

    loop {
        if stop_flag.load(Ordering::Relaxed) {
            break;
        }

        // Wait for packet event with reasonable timeout
        // The event is signaled by ndisapi driver when packets are available
        // Using 100ms timeout allows responsive stop_flag checking while
        // avoiding 1000Hz polling that wastes CPU when idle
        // (When packets arrive, event signals immediately - no added latency)
        unsafe {
            WaitForSingleObject(event, 100);
        }

        // Read batch of packets
        let mut to_read = EthMRequestMut::from_iter(physical_handle, packets.iter_mut());

        let packets_read = driver.read_packets::<BATCH_SIZE>(&mut to_read).unwrap_or(0);

        if packets_read == 0 {
            unsafe {
                let _ = ResetEvent(event);
            }
            continue;
        }

        // Refresh process snapshot once per batch (cheap atomic load) so routing decisions
        // track new processes/connection tables without per-packet ArcSwap loads.
        let new_snapshot = process_cache.get_snapshot();
        if new_snapshot.version != snapshot_version {
            snapshot_version = new_snapshot.version;
            inline_cache.clear();
        }
        snapshot = new_snapshot;

        // Prepare passthrough queues
        passthrough_to_adapter = EthMRequest::new(physical_handle);
        passthrough_to_mstcp = EthMRequest::new(physical_handle);

        // Dispatch packets to workers based on hash of source port
        for i in 0..packets_read {
            let direction_flags = packets[i].get_device_flags();
            let is_outbound = direction_flags == DirectionFlags::PACKET_FLAG_ON_SEND;
            let data = packets[i].get_data();

            if is_outbound {
                // Parse to get source port for hashing (and ensure TCP/UDP IPv4)
                if let Some((src_port, _dst_port)) = parse_ports(data) {
                    // Hash by source port to select worker
                    // DEFENSIVE: Prevent division by zero (should never happen with num_workers >= 1)
                    let worker_id = if num_workers > 0 {
                        (src_port as usize) % num_workers
                    } else {
                        log::error!("CRITICAL: num_workers is 0 - this should never happen");
                        0
                    };

                    let packet_len = data.len() as u64;

                    // Decide routing here to keep bypass traffic out of the workers.
                    let should_tunnel =
                        should_route_to_vpn_with_inline_cache(data, &snapshot, &mut inline_cache);

                    // Auto-routing whitelist bypass: if bypass is active, tunnel-eligible packets
                    // should be passed through to the physical adapter instead.
                    let auto_routing_bypass =
                        should_tunnel && auto_router.as_ref().map_or(false, |r| r.is_bypassed());

                    if !should_tunnel || auto_routing_bypass {
                        // When bypassing due to auto-routing whitelist, still run game server
                        // detection + evaluation so teleports to non-whitelisted regions resume tunneling.
                        if auto_routing_bypass && data.len() >= 14 + 20 {
                            let ip_start = 14;
                            let dst_ip = Ipv4Addr::new(
                                data[ip_start + 16],
                                data[ip_start + 17],
                                data[ip_start + 18],
                                data[ip_start + 19],
                            );
                            if is_roblox_game_server_ip(dst_ip) {
                                if let Some(ref ar) = auto_router {
                                    ar.evaluate_game_server(dst_ip);
                                }
                            }
                        }

                        // Batch passthrough (much cheaper than per-packet bypass reinjection).
                        let _ = passthrough_to_adapter.push(&packets[i]);

                        // Keep diagnostics accurate (bypass packets won't reach workers anymore).
                        if let Some(stats) = worker_stats.get(worker_id) {
                            stats.packets_bypassed.fetch_add(1, Ordering::Relaxed);
                            stats
                                .bytes_bypassed
                                .fetch_add(packet_len, Ordering::Relaxed);
                        }
                        continue;
                    }

                    // Tunnel packet: dispatch to worker. (Copy only when tunneling.)
                    // Use ArrayVec for stack allocation - avoids heap alloc per packet
                    let mut packet_data: ArrayVec<u8, MAX_PACKET_SIZE> = ArrayVec::new();
                    let copy_len = data.len().min(MAX_PACKET_SIZE);
                    packet_data.try_extend_from_slice(&data[..copy_len]).ok();

                    let work = PacketWork {
                        data: packet_data,
                        is_outbound: true,
                        physical_adapter_name: Arc::clone(&physical_name),
                        should_tunnel: true,
                    };

                    // If worker queue is full, fall back to passthrough and count as bypass.
                    if senders[worker_id].try_send(work).is_err() {
                        let _ = passthrough_to_adapter.push(&packets[i]);
                        if let Some(stats) = worker_stats.get(worker_id) {
                            stats.packets_bypassed.fetch_add(1, Ordering::Relaxed);
                            stats
                                .bytes_bypassed
                                .fetch_add(packet_len, Ordering::Relaxed);
                        }
                    }
                } else {
                    // Non-TCP/UDP packet - passthrough
                    let _ = passthrough_to_adapter.push(&packets[i]);
                }
            } else {
                // Inbound - passthrough to MSTCP
                let _ = passthrough_to_mstcp.push(&packets[i]);
            }
        }

        // Send passthrough packets
        if passthrough_to_adapter.get_packet_number() > 0 {
            let _ = driver.send_packets_to_adapter::<BATCH_SIZE>(&passthrough_to_adapter);
        }

        if passthrough_to_mstcp.get_packet_number() > 0 {
            let _ = driver.send_packets_to_mstcp::<BATCH_SIZE>(&passthrough_to_mstcp);
        }

        unsafe {
            let _ = ResetEvent(event);
        }
    }

    // Cleanup
    let _ = driver.set_adapter_mode(physical_handle, FilterFlags::default());
    unsafe {
        let _ = CloseHandle(event);
    }

    log::info!("Packet reader stopped");
    Ok(())
}

/// Worker thread - processes packets and routes to VPN or passthrough
fn run_packet_worker(
    worker_id: usize,
    receiver: crossbeam_channel::Receiver<PacketWork>,
    stats: Arc<WorkerStats>,
    throughput: ThroughputStats,
    stop_flag: Arc<AtomicBool>,
    relay_ctx: Option<Arc<super::udp_relay::UdpRelay>>,
    detected_game_servers: Arc<parking_lot::RwLock<std::collections::HashSet<std::net::Ipv4Addr>>>,
    auto_router: Option<Arc<super::auto_routing::AutoRouter>>,
) {
    log::info!("Worker {} started", worker_id);

    // Diagnostic logging
    let mut diagnostic_counter = 0u64;

    // Open driver for this worker (each worker needs own handle for sending bypass packets)
    let driver = match ndisapi::Ndisapi::new("NDISRD") {
        Ok(d) => d,
        Err(e) => {
            log::error!("Worker {} failed to open driver: {}", worker_id, e);
            return;
        }
    };

    // Get adapters to find physical adapter handle
    let adapters = match driver.get_tcpip_bound_adapters_info() {
        Ok(a) => a,
        Err(e) => {
            log::error!("Worker {} failed to get adapters: {}", worker_id, e);
            return;
        }
    };

    if relay_ctx.is_some() {
        log::info!("Worker {}: V3 relay context AVAILABLE", worker_id);
    } else {
        log::warn!(
            "Worker {}: NO relay context - tunnel packets will be bypassed!",
            worker_id
        );
    }

    // Track relay stats
    let mut relay_success = 0u64;
    let mut relay_fail = 0u64;

    // Adaptive timeout: short when active, longer when idle to save CPU
    // This is the key optimization - avoid 1000Hz polling when no packets
    let mut consecutive_timeouts = 0u32;

    loop {
        if stop_flag.load(Ordering::Relaxed) {
            break;
        }

        // Adaptive timeout based on recent activity:
        // - 5ms when recently active (gaming latency acceptable)
        // - 150ms after 10 consecutive timeouts (idle, save CPU)
        // The reader thread has the event-driven wakeup, workers just need
        // to process what the reader dispatches to them
        let timeout_ms = if consecutive_timeouts > 10 { 150 } else { 5 };

        let work = match receiver.recv_timeout(std::time::Duration::from_millis(timeout_ms)) {
            Ok(w) => {
                consecutive_timeouts = 0; // Reset on successful receive
                w
            }
            Err(crossbeam_channel::RecvTimeoutError::Timeout) => {
                consecutive_timeouts = consecutive_timeouts.saturating_add(1);
                continue;
            }
            Err(crossbeam_channel::RecvTimeoutError::Disconnected) => break,
        };

        // Process packet
        stats.packets_processed.fetch_add(1, Ordering::Relaxed);
        let packet_len = work.data.len() as u64;
        diagnostic_counter += 1;

        if work.is_outbound {
            // Routing decision is computed in the reader thread so bypass traffic
            // can be batch-passed-through without ever hitting the workers.
            let should_tunnel = work.should_tunnel;

            // Periodic diagnostic logging (every 500 packets on worker 0)
            if worker_id == 0 && diagnostic_counter % 500 == 0 {
                let tunneled = stats.packets_tunneled.load(Ordering::Relaxed);
                let bypassed = stats.packets_bypassed.load(Ordering::Relaxed);
                let total = tunneled + bypassed;
                let tunnel_pct = if total > 0 {
                    (tunneled as f64 / total as f64) * 100.0
                } else {
                    0.0
                };

                log::info!(
                    "Worker 0 PERF: {} tunneled, {} bypassed ({:.1}%), relay: {}/{}",
                    tunneled,
                    bypassed,
                    tunnel_pct,
                    relay_success,
                    relay_fail,
                );
            }

            // Auto-routing whitelist bypass: if the current game region is whitelisted,
            // game packets that would normally be tunneled are passed through to the
            // real adapter instead. Lock-free AtomicBool check (<1ns overhead).
            let auto_routing_bypass =
                should_tunnel && auto_router.as_ref().map_or(false, |r| r.is_bypassed());

            // When bypassing, still run game server detection + auto-routing evaluation
            // so we can detect teleports to non-whitelisted regions and resume tunneling.
            if auto_routing_bypass && work.data.len() > 14 + 20 {
                let ip_start = 14;
                let dst_ip = Ipv4Addr::new(
                    work.data[ip_start + 16],
                    work.data[ip_start + 17],
                    work.data[ip_start + 18],
                    work.data[ip_start + 19],
                );
                if is_roblox_game_server_ip(dst_ip) {
                    if let Some(ref ar) = auto_router {
                        ar.evaluate_game_server(dst_ip);
                    }
                }
            }

            if should_tunnel && !auto_routing_bypass {
                stats.packets_tunneled.fetch_add(1, Ordering::Relaxed);
                stats
                    .bytes_tunneled
                    .fetch_add(packet_len, Ordering::Relaxed);
                throughput.add_tx(packet_len);

                // Extract IP packet from Ethernet frame
                if work.data.len() <= 14 {
                    continue;
                }
                let ip_packet = &work.data[14..];

                // === GAME SERVER DETECTION (Bloxstrap-style) ===
                // Track Roblox game server IPs for notifications
                // STABILITY FIX (v1.0.8): Use try_write() to avoid blocking in hot path
                // If lock is contended, skip recording this packet (not critical)
                if ip_packet.len() >= 20 {
                    let dst_ip =
                        Ipv4Addr::new(ip_packet[16], ip_packet[17], ip_packet[18], ip_packet[19]);
                    if is_roblox_game_server_ip(dst_ip) {
                        // Non-blocking write - skip if lock contended (prevents freeze)
                        if let Some(mut servers) = detected_game_servers.try_write() {
                            if servers.insert(dst_ip) {
                                log::info!(
                                    "Game server detected: {} (tunneled by SwiftTunnel)",
                                    dst_ip
                                );
                            }
                        }

                        // === AUTO ROUTING ===
                        // Notify auto-router of new game server IPs (triggers async region lookup).
                        // The actual relay switch happens asynchronously via handle_region_lookup().
                        if let Some(ref auto_router) = auto_router {
                            auto_router.evaluate_game_server(dst_ip);
                        }
                    }
                }

                // === CHECKSUM OFFLOAD FIX ===
                // Modern NICs use hardware checksum offload — we intercept packets BEFORE
                // the NIC computes checksums, so they have placeholder values (0x0000).
                // Use thread-local buffer to avoid per-packet heap allocation.
                let (packet_to_send_ptr, packet_to_send_len): (*const u8, usize) =
                    if ip_packet.len() >= 20 {
                        PACKET_BUFFER.with(|buf| {
                            let mut fix_buf = buf.borrow_mut();
                            let pkt_len = ip_packet.len().min(MAX_PACKET_SIZE);
                            fix_buf[..pkt_len].copy_from_slice(&ip_packet[..pkt_len]);

                            fix_packet_checksums(&mut fix_buf[..pkt_len]);

                            (fix_buf.as_ptr(), pkt_len)
                        })
                    } else {
                        (ip_packet.as_ptr(), ip_packet.len())
                    };

                // SAFETY: The pointer is either from ip_packet (still in scope) or
                // from PACKET_BUFFER (thread-local, valid for duration of this function)
                let packet_to_send =
                    unsafe { std::slice::from_raw_parts(packet_to_send_ptr, packet_to_send_len) };

                // === PACKET HOLD: Drop packets while auto-routing lookup is pending ===
                // When a new game server IP is detected, we hold (drop) packets to it
                // until the ipinfo.io lookup completes and the relay switches. This
                // prevents the game server from seeing traffic from the old relay IP,
                // which causes Roblox Error 2/277. RakNet will retransmit the held packets.
                if ip_packet.len() >= 20 {
                    let dst_ip =
                        Ipv4Addr::new(ip_packet[16], ip_packet[17], ip_packet[18], ip_packet[19]);
                    // Only Roblox game server IPs participate in auto-routing lookups.
                    // Avoid taking the pending-lookups lock for non-Roblox traffic.
                    if is_roblox_game_server_ip(dst_ip) {
                        if let Some(ref auto_router) = auto_router {
                            if auto_router.is_lookup_pending(dst_ip) {
                                // Skip this packet — RakNet will retransmit after relay switch
                                continue;
                            }
                        }
                    }
                }

                // === V3: UDP RELAY (NO ENCRYPTION) ===
                // Forward packets directly to relay server without encryption
                // This provides lowest latency and CPU usage
                if let Some(ref relay) = relay_ctx {
                    // Log relay destination for first few packets (auto-routing debug)
                    if relay_success + relay_fail < 10 {
                        log::info!(
                            "Worker {}: Forwarding to relay {} (pkt #{}, dst={})",
                            worker_id,
                            relay.relay_addr(),
                            relay_success + relay_fail + 1,
                            if ip_packet.len() >= 20 {
                                format!(
                                    "{}.{}.{}.{}",
                                    ip_packet[16], ip_packet[17], ip_packet[18], ip_packet[19]
                                )
                            } else {
                                "?".to_string()
                            }
                        );
                    }
                    match relay.forward_outbound(packet_to_send) {
                        Ok(sent) => {
                            relay_success += 1;
                            if relay_success <= 5 && sent > 0 {
                                log::info!(
                                    "Worker {}: V3 relay forward OK - {} bytes",
                                    worker_id,
                                    sent
                                );
                            }
                        }
                        Err(e) => {
                            relay_fail += 1;
                            // Log first 10 failures, then every 100th to avoid log spam
                            // but keep visibility into persistent relay issues (Error 277)
                            if relay_fail <= 10 || relay_fail % 100 == 0 {
                                log::warn!(
                                    "Worker {}: V3 relay forward failed ({} total): {}",
                                    worker_id,
                                    relay_fail,
                                    e
                                );
                            }
                        }
                    }
                } else {
                    // No relay context — forward to adapter (bypass)
                    send_bypass_packet(&driver, &adapters, &work);
                }
            } else {
                stats.packets_bypassed.fetch_add(1, Ordering::Relaxed);
                stats
                    .bytes_bypassed
                    .fetch_add(packet_len, Ordering::Relaxed);

                // CRITICAL FIX: Forward bypass packets to adapter
                // Previously this was missing, causing all non-tunnel traffic to be dropped!
                send_bypass_packet(&driver, &adapters, &work);
            }
        }
    }

    log::info!(
        "Worker {} stopped - processed: {}, tunneled: {} ({} bytes), bypassed: {} ({} bytes)",
        worker_id,
        stats.packets_processed.load(Ordering::Relaxed),
        stats.packets_tunneled.load(Ordering::Relaxed),
        stats.bytes_tunneled.load(Ordering::Relaxed),
        stats.packets_bypassed.load(Ordering::Relaxed),
        stats.bytes_bypassed.load(Ordering::Relaxed)
    );
}

/// Send a bypass packet to the physical adapter
fn send_bypass_packet(
    driver: &ndisapi::Ndisapi,
    adapters: &[ndisapi::NetworkAdapterInfo],
    work: &PacketWork,
) {
    use ndisapi::{DirectionFlags, EthMRequest, IntermediateBuffer};

    // Find adapter by internal name (GUID) - this is consistent across driver instances
    let adapter = match adapters
        .iter()
        .find(|a| a.get_name() == work.physical_adapter_name.as_str())
    {
        Some(a) => a,
        None => {
            log::warn!(
                "send_bypass_packet: adapter '{}' not found in worker's adapter list ({} adapters)",
                work.physical_adapter_name,
                adapters.len()
            );
            return;
        }
    };

    let adapter_handle = adapter.get_handle();

    // Safety check: Don't process oversized packets that would overflow IntermediateBuffer
    const MAX_ETHER_FRAME: usize = 1522;
    if work.data.len() > MAX_ETHER_FRAME {
        log::warn!(
            "send_bypass_packet: packet too large ({} bytes), dropping",
            work.data.len()
        );
        return;
    }

    // Create IntermediateBuffer with packet data
    let mut buffer = IntermediateBuffer::default();
    // CRITICAL: Set direction flag to outbound - required for send_packets_to_adapter
    buffer.device_flags = DirectionFlags::PACKET_FLAG_ON_SEND;
    buffer.length = work.data.len() as u32;
    buffer.buffer.0[..work.data.len()].copy_from_slice(&work.data);

    // Send to adapter (bypasses VPN, goes directly to physical network)
    let mut to_adapter: EthMRequest<1> = EthMRequest::new(adapter_handle);
    if to_adapter.push(&buffer).is_ok() {
        if let Err(e) = driver.send_packets_to_adapter::<1>(&to_adapter) {
            log::warn!("send_bypass_packet: send failed: {:?}", e);
        }
    }
}

/// Cache refresher thread - single writer
///
/// OPTIMIZATION: Event-driven refresh instead of polling
/// - Sleeps for 2 seconds normally (was 20ms = 50x reduction)
/// - Wakes immediately when ETW detects game process (via refresh_now flag)
/// - Full process scan only every 10th iteration (was every iteration)
fn run_cache_refresher(
    cache: Arc<LockFreeProcessCache>,
    stop_flag: Arc<AtomicBool>,
    refresh_now: Arc<AtomicBool>,
    refresh_condvar: Arc<(std::sync::Mutex<bool>, std::sync::Condvar)>,
) {
    use sysinfo::{ProcessRefreshKind, ProcessesToUpdate, System, UpdateKind};
    use windows::Win32::NetworkManagement::IpHelper::*;

    log::info!("Cache refresher started (event-driven + 2s fallback, ExitLag-style efficiency)");

    // Log tunnel apps at startup
    let tunnel_apps = cache.tunnel_apps();
    log::info!(
        "Cache refresher: tunnel_apps = {:?} ({} apps)",
        tunnel_apps.iter().take(5).collect::<Vec<_>>(),
        tunnel_apps.len()
    );

    if tunnel_apps.is_empty() {
        log::warn!("Cache refresher: WARNING - tunnel_apps is EMPTY! No traffic will be tunneled!");
    }

    let mut system = System::new();
    let mut refresh_count = 0u64;
    let mut first_run = true;

    // OPTIMIZATION: Reuse HashMaps instead of recreating every iteration
    let mut connections: HashMap<ConnectionKey, u32> = HashMap::with_capacity(2048);
    let mut pid_names: HashMap<u32, String> = HashMap::with_capacity(512);

    loop {
        if stop_flag.load(Ordering::Relaxed) {
            break;
        }

        // On first run, don't sleep - immediately refresh to populate cache
        if first_run {
            first_run = false;
            log::info!("Cache refresher: Performing initial refresh immediately");
        } else {
            // EVENT-DRIVEN REFRESH: Block on Condvar until ETW signals or 2s timeout
            // Zero CPU when idle, instant wakeup when game launches
            let tunnel_apps = cache.tunnel_apps();
            let wait_timeout = if tunnel_apps.is_empty() {
                // No apps to tunnel - sleep longer (5s) since nothing to track
                Duration::from_secs(5)
            } else {
                // Normal: 2 second fallback
                Duration::from_secs(2)
            };

            let (lock, cvar) = &*refresh_condvar;
            if let Ok(mut signaled) = lock.lock() {
                // Wait until signaled or timeout
                let result = cvar.wait_timeout_while(signaled, wait_timeout, |s| {
                    !*s && !stop_flag.load(Ordering::Relaxed)
                });
                if let Ok((mut guard, _)) = result {
                    *guard = false; // Reset signal
                }
            }

            // Check if ETW triggered (also reset the atomic flag)
            if refresh_now.swap(false, Ordering::AcqRel) {
                log::info!("Cache refresher: ETW triggered immediate refresh");
            }

            if stop_flag.load(Ordering::Relaxed) {
                return;
            }
        }

        // OPTIMIZATION: Clear and reuse instead of reallocating
        connections.clear();
        pid_names.clear();

        // Get TCP table
        unsafe {
            let mut size: u32 = 0;
            let _ = GetExtendedTcpTable(
                None,
                &mut size,
                false,
                2,
                TCP_TABLE_CLASS(TCP_TABLE_OWNER_PID_ALL.0),
                0,
            );

            if size > 0 {
                let mut buffer = vec![0u8; size as usize];
                if GetExtendedTcpTable(
                    Some(buffer.as_mut_ptr() as *mut _),
                    &mut size,
                    false,
                    2,
                    TCP_TABLE_CLASS(TCP_TABLE_OWNER_PID_ALL.0),
                    0,
                ) == 0
                {
                    // BOUNDS CHECK: Validate buffer has at least the header size
                    let header_size = std::mem::size_of::<u32>(); // dwNumEntries
                    if buffer.len() >= header_size {
                        let table = &*(buffer.as_ptr() as *const MIB_TCPTABLE_OWNER_PID);
                        let num_entries = table.dwNumEntries as usize;

                        // BOUNDS CHECK: Validate num_entries doesn't exceed buffer capacity
                        let entry_size = std::mem::size_of::<MIB_TCPROW_OWNER_PID>();
                        let max_entries = buffer.len().saturating_sub(header_size) / entry_size;
                        let safe_entries = num_entries.min(max_entries);

                        let entries =
                            std::slice::from_raw_parts(table.table.as_ptr(), safe_entries);

                        for entry in entries {
                            let local_ip = Ipv4Addr::from(entry.dwLocalAddr.to_ne_bytes());
                            let local_port = u16::from_be(entry.dwLocalPort as u16);
                            let key = ConnectionKey::new(local_ip, local_port, Protocol::Tcp);
                            connections.insert(key, entry.dwOwningPid);
                        }
                    }
                }
            }
        }

        // Get UDP table
        unsafe {
            let mut size: u32 = 0;
            let _ = GetExtendedUdpTable(
                None,
                &mut size,
                false,
                2,
                UDP_TABLE_CLASS(UDP_TABLE_OWNER_PID.0),
                0,
            );

            if size > 0 {
                let mut buffer = vec![0u8; size as usize];
                if GetExtendedUdpTable(
                    Some(buffer.as_mut_ptr() as *mut _),
                    &mut size,
                    false,
                    2,
                    UDP_TABLE_CLASS(UDP_TABLE_OWNER_PID.0),
                    0,
                ) == 0
                {
                    // BOUNDS CHECK: Validate buffer has at least the header size
                    let header_size = std::mem::size_of::<u32>(); // dwNumEntries
                    if buffer.len() >= header_size {
                        let table = &*(buffer.as_ptr() as *const MIB_UDPTABLE_OWNER_PID);
                        let num_entries = table.dwNumEntries as usize;

                        // BOUNDS CHECK: Validate num_entries doesn't exceed buffer capacity
                        let entry_size = std::mem::size_of::<MIB_UDPROW_OWNER_PID>();
                        let max_entries = buffer.len().saturating_sub(header_size) / entry_size;
                        let safe_entries = num_entries.min(max_entries);

                        let entries =
                            std::slice::from_raw_parts(table.table.as_ptr(), safe_entries);

                        for entry in entries {
                            let local_ip = Ipv4Addr::from(entry.dwLocalAddr.to_ne_bytes());
                            let local_port = u16::from_be(entry.dwLocalPort as u16);
                            let key = ConnectionKey::new(local_ip, local_port, Protocol::Udp);
                            connections.insert(key, entry.dwOwningPid);
                        }
                    }
                }
            }
        }

        // OPTIMIZATION: Only do expensive full process scan every 10th iteration (~20 seconds)
        // - refresh_count starts at 0, so first iteration gets a full scan (0 % 10 == 0)
        // - ETW handles instant detection of new game launches
        // - Full scan is just a fallback for edge cases (process started before VPN connected)
        let do_full_process_scan = refresh_count % 10 == 0;

        let tunnel_apps = cache.tunnel_apps();
        let mut tunnel_pids_found: Vec<(u32, String)> = Vec::new();

        if do_full_process_scan {
            // Full process scan - expensive but only ~every 20 seconds
            system.refresh_processes_specifics(
                ProcessesToUpdate::All,
                true,
                ProcessRefreshKind::new().with_exe(UpdateKind::OnlyIfNotSet),
            );

            for pid in connections.values() {
                if !pid_names.contains_key(pid) {
                    if let Some(process) = system.process(sysinfo::Pid::from_u32(*pid)) {
                        pid_names.insert(*pid, process.name().to_string_lossy().to_string());
                    }
                }
            }

            // Scan for tunnel apps
            for (_pid, process) in system.processes() {
                let name = process.name().to_string_lossy().to_lowercase();
                for app in tunnel_apps {
                    if name.contains(app.trim_end_matches(".exe")) {
                        let pid_u32 = _pid.as_u32();
                        pid_names.insert(pid_u32, process.name().to_string_lossy().to_string());
                        tunnel_pids_found
                            .push((pid_u32, process.name().to_string_lossy().to_string()));

                        if refresh_count < 10 {
                            log::info!(
                                "Cache refresher: Found tunnel app '{}' with PID {} (sysinfo)",
                                process.name().to_string_lossy(),
                                pid_u32
                            );
                        }
                        break;
                    }
                }
            }
        } else {
            // Fast path: Only look up PIDs from connection table (no full scan)
            // Uses cached process info from last full scan
            for pid in connections.values() {
                if !pid_names.contains_key(pid) {
                    // Try to get from existing system cache (no syscall if already cached)
                    if let Some(process) = system.process(sysinfo::Pid::from_u32(*pid)) {
                        pid_names.insert(*pid, process.name().to_string_lossy().to_string());
                    }
                }
            }
        }

        // Also log connections owned by tunnel apps
        if refresh_count < 10 && !tunnel_pids_found.is_empty() {
            for ((key, &pid), (tunnel_pid, _name)) in connections.iter().flat_map(|c| {
                tunnel_pids_found
                    .iter()
                    .filter_map(move |tp| if *c.1 == tp.0 { Some((c, tp)) } else { None })
            }) {
                log::info!(
                    "Cache refresher: Tunnel app connection {}:{} ({:?}) owned by PID {}",
                    key.local_ip,
                    key.local_port,
                    key.protocol,
                    pid
                );
            }
        }

        // Update cache atomically
        cache.update(connections.clone(), pid_names.clone());

        // Log tunnel app detection periodically
        refresh_count += 1;
        if refresh_count % 100 == 0 {
            let snap = cache.get_snapshot();

            // Count connections for tunnel PIDs
            let tunnel_connections: Vec<_> = connections
                .iter()
                .filter(|(_, pid)| tunnel_pids_found.iter().any(|(tp, _)| tp == *pid))
                .collect();

            if !tunnel_pids_found.is_empty() || tunnel_connections.len() > 0 {
                log::debug!(
                    "Cache #{}: {} tunnel PIDs found: {:?}, {} tunnel connections",
                    refresh_count,
                    tunnel_pids_found.len(),
                    tunnel_pids_found
                        .iter()
                        .map(|(_, n)| n.as_str())
                        .collect::<Vec<_>>(),
                    tunnel_connections.len()
                );
            }

            log::debug!(
                "Cache refresh #{}: {} connections, {} PIDs, tunnel_apps: {:?}",
                refresh_count,
                snap.connections.len(),
                snap.pid_names.len(),
                tunnel_apps.iter().collect::<Vec<_>>()
            );
        }
    }

    log::info!("Cache refresher stopped");
}

/// Parse ports from packet (returns src_port, dst_port)
#[inline(always)]
fn parse_ports(data: &[u8]) -> Option<(u16, u16)> {
    // Skip Ethernet header
    if data.len() < 14 + 20 + 4 {
        return None;
    }

    // Check EtherType
    let ethertype = u16::from_be_bytes([data[12], data[13]]);
    if ethertype != 0x0800 {
        return None;
    }

    // Check IP version and get IHL
    let version = (data[14] >> 4) & 0xF;
    if version != 4 {
        return None;
    }

    let ihl = ((data[14] & 0xF) as usize) * 4;
    let ip_start = 14;

    // Check protocol (TCP=6, UDP=17)
    let protocol = data[ip_start + 9];
    if protocol != 6 && protocol != 17 {
        return None;
    }

    // Parse transport header
    let transport_start = ip_start + ihl;
    if data.len() < transport_start + 4 {
        return None;
    }

    let src_port = u16::from_be_bytes([data[transport_start], data[transport_start + 1]]);
    let dst_port = u16::from_be_bytes([data[transport_start + 2], data[transport_start + 3]]);

    Some((src_port, dst_port))
}

/// Per-worker inline cache for connection lookups
/// This amortizes the expensive GetExtendedTcpTable syscall across multiple packets
/// from the same connection. First packet: ~500μs, subsequent packets: <1μs
type InlineCache = std::collections::HashMap<(Ipv4Addr, u16, Protocol), bool>;

/// Debug counters for inline cache diagnostics
struct InlineCacheStats {
    snapshot_hits: u64,
    inline_cache_hits: u64,
    syscall_lookups: u64,
    syscall_tunneled: u64,
    syscall_bypassed: u64,
    connection_not_found: u64,
}

/// Inline lookup with per-worker caching
///
/// For cache misses from the snapshot, this does a GetExtendedTcpTable lookup
/// and caches the result. This way, only the FIRST packet of a new connection
/// incurs the syscall overhead - subsequent packets use the inline cache.
fn should_route_to_vpn_with_inline_cache(
    data: &[u8],
    snapshot: &ProcessSnapshot,
    inline_cache: &mut InlineCache,
) -> bool {
    // Thread-local counters for debugging
    thread_local! {
        static TOTAL: std::cell::Cell<u64> = const { std::cell::Cell::new(0) };
        static SNAPSHOT_HITS: std::cell::Cell<u64> = const { std::cell::Cell::new(0) };
        static INLINE_HITS: std::cell::Cell<u64> = const { std::cell::Cell::new(0) };
        static SYSCALL_LOOKUPS: std::cell::Cell<u64> = const { std::cell::Cell::new(0) };
        static LAST_LOG: std::cell::Cell<u64> = const { std::cell::Cell::new(0) };
    }

    let total = TOTAL.with(|c| {
        let n = c.get();
        c.set(n + 1);
        n
    });

    // Skip Ethernet header (14 bytes)
    if data.len() < 14 + 20 + 4 {
        return false;
    }

    // Check EtherType
    let ethertype = u16::from_be_bytes([data[12], data[13]]);
    if ethertype != 0x0800 {
        return false;
    }

    // Parse IP header
    let ip_start = 14;
    let version = (data[ip_start] >> 4) & 0xF;
    if version != 4 {
        return false;
    }

    let ihl = ((data[ip_start] & 0xF) as usize) * 4;
    let protocol_num = data[ip_start + 9];

    let protocol = match protocol_num {
        6 => Protocol::Tcp,
        17 => Protocol::Udp,
        _ => return false,
    };

    let src_ip = Ipv4Addr::new(
        data[ip_start + 12],
        data[ip_start + 13],
        data[ip_start + 14],
        data[ip_start + 15],
    );

    // Parse destination IP (for V2 routing)
    let dst_ip = Ipv4Addr::new(
        data[ip_start + 16],
        data[ip_start + 17],
        data[ip_start + 18],
        data[ip_start + 19],
    );

    // Parse transport header
    let transport_start = ip_start + ihl;
    if data.len() < transport_start + 4 {
        return false;
    }

    let src_port = u16::from_be_bytes([data[transport_start], data[transport_start + 1]]);
    let dst_port = u16::from_be_bytes([data[transport_start + 2], data[transport_start + 3]]);

    // Phase 1: Check snapshot cache (fast path, O(1))
    //
    // IMPORTANT: This is process-based only. Destination-based speculative tunneling
    // is handled below so we can seed the inline cache for game-server hits.
    if snapshot.should_tunnel(src_ip, src_port, protocol) {
        SNAPSHOT_HITS.with(|c| c.set(c.get() + 1));
        // Tunnel all UDP from tunnel apps; TCP is intentionally never tunneled.
        return super::process_cache::is_likely_game_traffic(dst_port, protocol);
    }

    // Phase 2: Check per-worker inline cache (fast path, O(1))
    // Cache ONLY stores TRUE results (v0.9.25) - finding key means it's a tunnel app
    let cache_key = (src_ip, src_port, protocol);
    if inline_cache.contains_key(&cache_key) {
        INLINE_HITS.with(|c| c.set(c.get() + 1));
        // Process IS a tunnel app - trust it, tunnel all its UDP
        return super::process_cache::is_likely_game_traffic(dst_port, protocol);
    }

    // Phase 3: Skip inline lookup (expensive GetExtendedTcpTable/UdpTable syscalls
    // can block and cause system freezes with ndisapi packet interception).
    // Rely on speculative tunneling (destination IP matching) for first packets.
    let is_tunnel_app = false;

    // Cache the process check result for subsequent packets from this connection
    // Limit cache size to prevent unbounded growth
    //
    // CRITICAL FIX (v0.9.25): Only cache TRUE results, not FALSE results
    // This fixes the "inline cache poisoning" bug where:
    //   1. First UDP packet arrives before PID is in Windows UDP table
    //   2. lookup returns false (can't find PID)
    //   3. false gets cached
    //   4. All subsequent packets bypass VPN (cache hit returns false)
    //   5. User sees "Roblox detected" but traffic graph shows 0
    //
    // By only caching true results, we ensure that if a process wasn't found,
    // we keep trying on subsequent packets until it IS found.
    if is_tunnel_app && inline_cache.len() < 10000 {
        inline_cache.insert(cache_key, true);
    }

    // Apply V2 destination filter if needed
    let result = if !is_tunnel_app {
        // Phase 4: SPECULATIVE TUNNELING for first-packet guarantee
        // If destination is a known game server IP, tunnel it anyway even if we
        // couldn't identify the source process. This catches first packets sent
        // before the UDP table is populated (0.5-2ms race window).
        //
        // This is safe because:
        // 1. Only game traffic goes to these IP ranges
        // 2. If somehow non-game traffic hits these IPs, tunneling is harmless
        // 3. Subsequent packets will be correctly identified once cache is populated
        let is_game_dst = super::process_cache::is_game_server(dst_ip, dst_port, protocol);
        if is_game_dst {
            // Log speculative tunneling for debugging (first 20 times only)
            thread_local! {
                static SPECULATIVE_COUNT: std::cell::Cell<u64> = const { std::cell::Cell::new(0) };
            }
            let spec_count = SPECULATIVE_COUNT.with(|c| {
                let n = c.get();
                c.set(n + 1);
                n
            });
            if spec_count < 20 {
                log::info!(
                    "SPECULATIVE TUNNEL: {}:{} -> {}:{} (PID unknown, but destination is game server)",
                    src_ip,
                    src_port,
                    dst_ip,
                    dst_port
                );
            }

            // Cache speculative hit so subsequent packets from this source port
            // use the fast inline cache path. Critical for V3 mode where
            // inline_connection_lookup is disabled (stability fix v1.0.8).
            // Without this, every V3 packet re-does the speculative IP range check.
            if inline_cache.len() < 10000 {
                inline_cache.insert(cache_key, true);
            }

            true // Speculatively tunnel to game server
        } else {
            false
        }
    } else {
        // Process IS a tunnel app - trust it, tunnel all its UDP
        super::process_cache::is_likely_game_traffic(dst_port, protocol)
    };

    // Log stats periodically
    if total > 0 && total % 200 == 0 {
        let last = LAST_LOG.with(|c| c.get());
        if total > last {
            LAST_LOG.with(|c| c.set(total));
            let snapshot_h = SNAPSHOT_HITS.with(|c| c.get());
            let inline_h = INLINE_HITS.with(|c| c.get());
            let syscall_l = SYSCALL_LOOKUPS.with(|c| c.get());
            log::info!(
                "Cache stats: total={} snapshot_hits={} inline_hits={} syscall={} | snapshot_apps={} connections={}",
                total,
                snapshot_h,
                inline_h,
                syscall_l,
                snapshot.tunnel_apps.len(),
                snapshot.connections.len()
            );
        }
    }

    // Log first 10 packets for debugging - DEBUG level
    if total < 10 {
        log::debug!(
            "Packet #{}: {}:{} {:?} -> result={} (tunnel_apps={:?})",
            total,
            src_ip,
            src_port,
            protocol,
            result,
            snapshot.tunnel_apps.iter().take(5).collect::<Vec<_>>()
        );
    }

    // V2 DIAGNOSTIC: Log first few UDP packets to high ports that are BYPASSED
    // This helps diagnose if V2 mode is incorrectly rejecting game traffic
    if !result && protocol == Protocol::Udp && dst_port >= 49152 {
        thread_local! {
            static V2_BYPASS_LOG_COUNT: std::cell::Cell<u64> = const { std::cell::Cell::new(0) };
        }
        let log_count = V2_BYPASS_LOG_COUNT.with(|c| {
            let n = c.get();
            c.set(n + 1);
            n
        });
        // Log first 20 high-port UDP packets that were bypassed
        if log_count < 20 {
            log::info!(
                "V2 BYPASS: {}:{}/{:?} -> {}:{} | tunnel_app={}, port_ok=true, ip_in_ranges={}",
                src_ip,
                src_port,
                protocol,
                dst_ip,
                dst_port,
                is_tunnel_app,
                super::process_cache::is_roblox_game_server(dst_ip, dst_port, protocol)
            );
        }
    }

    result
}

/// Perform inline GetExtendedTcpTable/UdpTable lookup
/// This is expensive (~500μs) but only called once per new connection
///
/// CRITICAL: This function does NOT rely on snapshot.pid_names (which may be stale).
/// Instead, it gets the process name directly from the OS and matches against tunnel_apps.
fn inline_connection_lookup(
    src_ip: Ipv4Addr,
    src_port: u16,
    protocol: Protocol,
    snapshot: &ProcessSnapshot,
) -> bool {
    use windows::Win32::NetworkManagement::IpHelper::*;

    // Track lookups for debugging (thread-local counter)
    thread_local! {
        static LOOKUP_COUNT: std::cell::Cell<u64> = const { std::cell::Cell::new(0) };
        static FOUND_COUNT: std::cell::Cell<u64> = const { std::cell::Cell::new(0) };
        static TUNNEL_COUNT: std::cell::Cell<u64> = const { std::cell::Cell::new(0) };
    }

    let lookup_num = LOOKUP_COUNT.with(|c| {
        let n = c.get();
        c.set(n + 1);
        n
    });

    // Log first few lookups for debugging
    let debug_log = lookup_num < 20;

    match protocol {
        Protocol::Tcp => {
            // Get TCP table size
            let mut size: u32 = 0;
            unsafe {
                let _ = GetExtendedTcpTable(
                    None,
                    &mut size,
                    false,
                    2, // AF_INET
                    TCP_TABLE_CLASS(TCP_TABLE_OWNER_PID_ALL.0),
                    0,
                );

                if size == 0 {
                    if debug_log {
                        log::debug!("inline_lookup: TCP table size=0");
                    }
                    return false;
                }

                let mut buffer = vec![0u8; size as usize];
                if GetExtendedTcpTable(
                    Some(buffer.as_mut_ptr() as *mut _),
                    &mut size,
                    false,
                    2,
                    TCP_TABLE_CLASS(TCP_TABLE_OWNER_PID_ALL.0),
                    0,
                ) != 0
                {
                    if debug_log {
                        log::debug!("inline_lookup: GetExtendedTcpTable failed");
                    }
                    return false;
                }

                // BOUNDS CHECK: Validate buffer has at least the header size
                let header_size = std::mem::size_of::<u32>(); // dwNumEntries
                if buffer.len() < header_size {
                    if debug_log {
                        log::debug!("inline_lookup: TCP table buffer too small");
                    }
                    return false;
                }

                let table = &*(buffer.as_ptr() as *const MIB_TCPTABLE_OWNER_PID);
                let num_entries = table.dwNumEntries as usize;

                // BOUNDS CHECK: Validate num_entries doesn't exceed buffer capacity
                let entry_size = std::mem::size_of::<MIB_TCPROW_OWNER_PID>();
                let max_entries = buffer.len().saturating_sub(header_size) / entry_size;
                let safe_entries = num_entries.min(max_entries);

                let rows = std::slice::from_raw_parts(table.table.as_ptr(), safe_entries);

                if debug_log {
                    log::debug!(
                        "inline_lookup #{}: searching TCP table ({} entries) for {}:{}",
                        lookup_num,
                        rows.len(),
                        src_ip,
                        src_port
                    );
                }

                for row in rows {
                    // Match byte order handling with cache refresher
                    let local_ip = Ipv4Addr::from(row.dwLocalAddr.to_ne_bytes());
                    let local_port = u16::from_be(row.dwLocalPort as u16);

                    if local_ip == src_ip && local_port == src_port {
                        FOUND_COUNT.with(|c| c.set(c.get() + 1));

                        // CRITICAL FIX: Get process name directly from OS, not from stale snapshot
                        let is_tunnel = is_pid_tunnel_app(row.dwOwningPid, snapshot);
                        if is_tunnel {
                            TUNNEL_COUNT.with(|c| c.set(c.get() + 1));
                        }

                        if debug_log || is_tunnel {
                            log::debug!(
                                "inline_lookup #{}: MATCH {}:{} -> PID {} tunnel={}",
                                lookup_num,
                                local_ip,
                                local_port,
                                row.dwOwningPid,
                                is_tunnel
                            );
                        }
                        return is_tunnel;
                    }

                    // Also check 0.0.0.0 binding
                    if local_ip == Ipv4Addr::UNSPECIFIED && local_port == src_port {
                        FOUND_COUNT.with(|c| c.set(c.get() + 1));

                        let is_tunnel = is_pid_tunnel_app(row.dwOwningPid, snapshot);
                        if is_tunnel {
                            TUNNEL_COUNT.with(|c| c.set(c.get() + 1));
                        }

                        if debug_log || is_tunnel {
                            log::debug!(
                                "inline_lookup #{}: MATCH 0.0.0.0:{} (for {}:{}) -> PID {} tunnel={}",
                                lookup_num,
                                local_port,
                                src_ip,
                                src_port,
                                row.dwOwningPid,
                                is_tunnel
                            );
                        }
                        return is_tunnel;
                    }
                }

                if debug_log {
                    log::debug!(
                        "inline_lookup #{}: NOT FOUND in TCP table for {}:{}",
                        lookup_num,
                        src_ip,
                        src_port
                    );
                }
            }
        }
        Protocol::Udp => {
            // Get UDP table size
            let mut size: u32 = 0;
            unsafe {
                let _ = GetExtendedUdpTable(
                    None,
                    &mut size,
                    false,
                    2, // AF_INET
                    UDP_TABLE_CLASS(UDP_TABLE_OWNER_PID.0),
                    0,
                );

                if size == 0 {
                    return false;
                }

                let mut buffer = vec![0u8; size as usize];
                if GetExtendedUdpTable(
                    Some(buffer.as_mut_ptr() as *mut _),
                    &mut size,
                    false,
                    2,
                    UDP_TABLE_CLASS(UDP_TABLE_OWNER_PID.0),
                    0,
                ) != 0
                {
                    return false;
                }

                // BOUNDS CHECK: Validate buffer has at least the header size
                let header_size = std::mem::size_of::<u32>(); // dwNumEntries
                if buffer.len() < header_size {
                    return false;
                }

                let table = &*(buffer.as_ptr() as *const MIB_UDPTABLE_OWNER_PID);
                let num_entries = table.dwNumEntries as usize;

                // BOUNDS CHECK: Validate num_entries doesn't exceed buffer capacity
                let entry_size = std::mem::size_of::<MIB_UDPROW_OWNER_PID>();
                let max_entries = buffer.len().saturating_sub(header_size) / entry_size;
                let safe_entries = num_entries.min(max_entries);

                let rows = std::slice::from_raw_parts(table.table.as_ptr(), safe_entries);

                for row in rows {
                    // Match byte order handling with cache refresher
                    let local_ip = Ipv4Addr::from(row.dwLocalAddr.to_ne_bytes());
                    let local_port = u16::from_be(row.dwLocalPort as u16);

                    if local_ip == src_ip && local_port == src_port {
                        return is_pid_tunnel_app(row.dwOwningPid, snapshot);
                    }

                    // Also check 0.0.0.0 binding
                    if local_ip == Ipv4Addr::UNSPECIFIED && local_port == src_port {
                        return is_pid_tunnel_app(row.dwOwningPid, snapshot);
                    }
                }
            }
        }
    }

    // Log periodic stats - DEBUG level
    if lookup_num > 0 && lookup_num % 100 == 0 {
        let found = FOUND_COUNT.with(|c| c.get());
        let tunneled = TUNNEL_COUNT.with(|c| c.get());
        log::debug!(
            "inline_lookup stats: {} lookups, {} found, {} tunneled ({:.1}% hit rate)",
            lookup_num,
            found,
            tunneled,
            if lookup_num > 0 {
                (found as f64 / lookup_num as f64) * 100.0
            } else {
                0.0
            }
        );
    }

    false
}

/// Check if a PID belongs to a tunnel app by getting process name directly from OS
///
/// This avoids relying on potentially stale snapshot.pid_names data.
/// Uses Windows API QueryFullProcessImageNameW for fast process name lookup.
fn is_pid_tunnel_app(pid: u32, snapshot: &ProcessSnapshot) -> bool {
    use windows::Win32::Foundation::{CloseHandle, HANDLE};
    use windows::Win32::System::Threading::{
        OpenProcess, PROCESS_NAME_FORMAT, PROCESS_QUERY_LIMITED_INFORMATION,
        QueryFullProcessImageNameW,
    };

    // First try snapshot (fast path if PID is already known)
    if snapshot.is_tunnel_pid_public(pid) {
        return true;
    }

    // Slow path: get process name directly from OS
    unsafe {
        let handle = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, false, pid);
        if let Ok(h) = handle {
            if h.is_invalid() || h.0.is_null() {
                return false;
            }

            let mut buffer = [0u16; 260];
            let mut size = buffer.len() as u32;

            if QueryFullProcessImageNameW(
                h,
                PROCESS_NAME_FORMAT(0),
                windows::core::PWSTR(buffer.as_mut_ptr()),
                &mut size,
            )
            .is_ok()
            {
                let _ = CloseHandle(h);

                // Extract filename from full path
                let path = String::from_utf16_lossy(&buffer[..size as usize]);
                let name = path.rsplit('\\').next().unwrap_or(&path).to_lowercase();

                // Check against tunnel_apps
                let name_stem = name.trim_end_matches(".exe");
                for app in &snapshot.tunnel_apps {
                    let app_stem = app.trim_end_matches(".exe");
                    if name_stem.contains(app_stem) || app_stem.contains(name_stem) {
                        log::debug!("is_pid_tunnel_app: PID {} is '{}' -> TUNNEL", pid, name);
                        return true;
                    }
                }

                log::trace!("is_pid_tunnel_app: PID {} is '{}' -> bypass", pid, name);
            } else {
                let _ = CloseHandle(h);
            }
        }
    }

    false
}

/// Get adapter friendly name
fn get_adapter_friendly_name(internal_name: &str) -> Option<String> {
    let guid = internal_name
        .rsplit('\\')
        .next()
        .unwrap_or("")
        .trim_matches(|c| c == '{' || c == '}');

    if guid.is_empty() {
        return None;
    }

    unsafe {
        let mut buf_len: u32 = 0;
        let _ = GetAdaptersInfo(None, &mut buf_len);

        if buf_len == 0 {
            return None;
        }

        let mut buffer: Vec<u8> = vec![0; buf_len as usize];
        let adapter_info_ptr = buffer.as_mut_ptr() as *mut IP_ADAPTER_INFO;

        if GetAdaptersInfo(Some(adapter_info_ptr), &mut buf_len) != 0 {
            return None;
        }

        let mut current = adapter_info_ptr;
        while !current.is_null() {
            let adapter = &*current;

            let adapter_name_bytes: Vec<u8> = adapter
                .AdapterName
                .iter()
                .take_while(|&&b| b != 0)
                .map(|&b| b as u8)
                .collect();
            let adapter_guid = String::from_utf8_lossy(&adapter_name_bytes);

            if adapter_guid.to_lowercase().contains(&guid.to_lowercase()) {
                let desc_bytes: Vec<u8> = adapter
                    .Description
                    .iter()
                    .take_while(|&&b| b != 0)
                    .map(|&b| b as u8)
                    .collect();
                return Some(String::from_utf8_lossy(&desc_bytes).to_string());
            }

            current = adapter.Next;
        }
    }

    None
}

/// Get adapter friendly name using GetAdaptersAddresses (newer, more comprehensive API)
///
/// This fallback function uses the modern GetAdaptersAddresses API which can find
/// all adapters including Wintun TUN adapters that GetAdaptersInfo might miss.
fn get_adapter_friendly_name_v2(internal_name: &str) -> Option<String> {
    use windows::Win32::NetworkManagement::IpHelper::{
        GAA_FLAG_INCLUDE_PREFIX, GetAdaptersAddresses, IP_ADAPTER_ADDRESSES_LH,
    };
    use windows::Win32::Networking::WinSock::AF_UNSPEC;

    let guid = internal_name
        .rsplit('\\')
        .next()
        .unwrap_or("")
        .trim_matches(|c| c == '{' || c == '}')
        .to_lowercase();

    if guid.is_empty() {
        return None;
    }

    unsafe {
        let mut buf_len: u32 = 0;
        // First call to get required buffer size
        let _ = GetAdaptersAddresses(
            AF_UNSPEC.0 as u32,
            GAA_FLAG_INCLUDE_PREFIX,
            None,
            None,
            &mut buf_len,
        );

        if buf_len == 0 {
            return None;
        }

        let mut buffer: Vec<u8> = vec![0; buf_len as usize];
        let adapter_addr_ptr = buffer.as_mut_ptr() as *mut IP_ADAPTER_ADDRESSES_LH;

        // Second call to get actual data
        let result = GetAdaptersAddresses(
            AF_UNSPEC.0 as u32,
            GAA_FLAG_INCLUDE_PREFIX,
            None,
            Some(adapter_addr_ptr),
            &mut buf_len,
        );

        if result != 0 {
            log::debug!("GetAdaptersAddresses failed with error: {}", result);
            return None;
        }

        // Iterate through adapters
        let mut current = adapter_addr_ptr;
        while !current.is_null() {
            let adapter = &*current;

            // Get adapter name (GUID) from AdapterName field
            if !adapter.AdapterName.0.is_null() {
                let adapter_name = std::ffi::CStr::from_ptr(adapter.AdapterName.0 as *const i8);
                if let Ok(name_str) = adapter_name.to_str() {
                    let adapter_guid = name_str
                        .trim_matches(|c| c == '{' || c == '}')
                        .to_lowercase();

                    if adapter_guid == guid {
                        // Found matching adapter - get friendly name
                        if !adapter.FriendlyName.0.is_null() {
                            let len = (0..)
                                .take_while(|&i| *adapter.FriendlyName.0.add(i) != 0)
                                .count();
                            let friendly_slice =
                                std::slice::from_raw_parts(adapter.FriendlyName.0, len);
                            let friendly_name = String::from_utf16_lossy(friendly_slice);
                            log::debug!(
                                "get_adapter_friendly_name_v2: Found '{}' for GUID {}",
                                friendly_name,
                                guid
                            );
                            return Some(friendly_name);
                        }
                    }
                }
            }

            current = adapter.Next;
        }
    }

    None
}

/// Check if an adapter's internal name matches a given LUID
///
/// Uses GetAdaptersAddresses to map the LUID to an adapter GUID, then checks
/// if the internal_name contains that GUID. This provides reliable adapter
/// identification even when friendly name lookup fails.
fn check_adapter_matches_luid(internal_name: &str, target_luid: u64) -> bool {
    use windows::Win32::NetworkManagement::IpHelper::{
        GAA_FLAG_INCLUDE_PREFIX, GetAdaptersAddresses, IP_ADAPTER_ADDRESSES_LH,
    };
    use windows::Win32::Networking::WinSock::AF_UNSPEC;

    if target_luid == 0 {
        return false;
    }

    // Extract GUID from internal_name (format: \DEVICE\{GUID})
    let internal_guid = internal_name
        .rsplit('\\')
        .next()
        .unwrap_or("")
        .trim_matches(|c| c == '{' || c == '}')
        .to_lowercase();

    if internal_guid.is_empty() {
        return false;
    }

    unsafe {
        let mut buf_len: u32 = 0;
        let _ = GetAdaptersAddresses(
            AF_UNSPEC.0 as u32,
            GAA_FLAG_INCLUDE_PREFIX,
            None,
            None,
            &mut buf_len,
        );

        if buf_len == 0 {
            return false;
        }

        let mut buffer: Vec<u8> = vec![0; buf_len as usize];
        let adapter_addr_ptr = buffer.as_mut_ptr() as *mut IP_ADAPTER_ADDRESSES_LH;

        let result = GetAdaptersAddresses(
            AF_UNSPEC.0 as u32,
            GAA_FLAG_INCLUDE_PREFIX,
            None,
            Some(adapter_addr_ptr),
            &mut buf_len,
        );

        if result != 0 {
            return false;
        }

        let mut current = adapter_addr_ptr;
        while !current.is_null() {
            let adapter = &*current;

            // Check if LUID matches
            // The Luid field is a NET_LUID_LH which contains Value as u64
            let adapter_luid = adapter.Luid.Value;

            if adapter_luid == target_luid {
                // Found adapter with matching LUID - check if GUID matches
                if !adapter.AdapterName.0.is_null() {
                    let adapter_name = std::ffi::CStr::from_ptr(adapter.AdapterName.0 as *const i8);
                    if let Ok(name_str) = adapter_name.to_str() {
                        let adapter_guid = name_str
                            .trim_matches(|c| c == '{' || c == '}')
                            .to_lowercase();

                        if adapter_guid == internal_guid {
                            log::debug!(
                                "check_adapter_matches_luid: LUID {} matches adapter GUID {}",
                                target_luid,
                                adapter_guid
                            );
                            return true;
                        }
                    }
                }
            }

            current = adapter.Next;
        }
    }

    false
}

/// Calculate IP header checksum (RFC 1071)
fn calculate_ip_checksum(header: &[u8]) -> u16 {
    let mut sum: u32 = 0;
    let mut i = 0;

    // Sum 16-bit words
    while i + 1 < header.len() {
        sum += u16::from_be_bytes([header[i], header[i + 1]]) as u32;
        i += 2;
    }

    // Handle odd byte
    if i < header.len() {
        sum += (header[i] as u32) << 8;
    }

    // Fold 32-bit sum to 16 bits
    while (sum >> 16) != 0 {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }

    // One's complement
    !(sum as u16)
}

/// Calculate TCP checksum with pseudo-header (RFC 793)
/// packet: Full IP packet (starting at IP header)
/// ihl: IP header length in bytes
fn calculate_tcp_checksum(packet: &[u8], ihl: usize) -> u16 {
    if packet.len() < ihl + 20 {
        return 0;
    }

    let src_ip = &packet[12..16];
    let dst_ip = &packet[16..20];
    let tcp_len = packet.len() - ihl;
    let tcp_segment = &packet[ihl..];

    let mut sum: u32 = 0;

    // Pseudo-header: src IP (4) + dst IP (4) + zero + protocol (6) + TCP length
    sum += u16::from_be_bytes([src_ip[0], src_ip[1]]) as u32;
    sum += u16::from_be_bytes([src_ip[2], src_ip[3]]) as u32;
    sum += u16::from_be_bytes([dst_ip[0], dst_ip[1]]) as u32;
    sum += u16::from_be_bytes([dst_ip[2], dst_ip[3]]) as u32;
    sum += 6u32; // TCP protocol number
    sum += tcp_len as u32;

    // Sum TCP segment (treating checksum field as 0)
    let mut i = 0;
    while i + 1 < tcp_segment.len() {
        if i == 16 {
            // Skip checksum field (bytes 16-17)
            i += 2;
            continue;
        }
        sum += u16::from_be_bytes([tcp_segment[i], tcp_segment[i + 1]]) as u32;
        i += 2;
    }

    // Handle odd byte
    if i < tcp_segment.len() {
        sum += (tcp_segment[i] as u32) << 8;
    }

    // Fold 32-bit sum to 16 bits
    while (sum >> 16) != 0 {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }

    !(sum as u16)
}

/// Calculate UDP checksum with pseudo-header (RFC 768)
/// packet: Full IP packet (starting at IP header)
/// ihl: IP header length in bytes
fn calculate_udp_checksum(packet: &[u8], ihl: usize) -> u16 {
    if packet.len() < ihl + 8 {
        return 0;
    }

    let src_ip = &packet[12..16];
    let dst_ip = &packet[16..20];
    let udp_len = packet.len() - ihl;
    let udp_datagram = &packet[ihl..];

    let mut sum: u32 = 0;

    // Pseudo-header: src IP (4) + dst IP (4) + zero + protocol (17) + UDP length
    sum += u16::from_be_bytes([src_ip[0], src_ip[1]]) as u32;
    sum += u16::from_be_bytes([src_ip[2], src_ip[3]]) as u32;
    sum += u16::from_be_bytes([dst_ip[0], dst_ip[1]]) as u32;
    sum += u16::from_be_bytes([dst_ip[2], dst_ip[3]]) as u32;
    sum += 17u32; // UDP protocol number
    sum += udp_len as u32;

    // Sum UDP datagram (treating checksum field as 0)
    let mut i = 0;
    while i + 1 < udp_datagram.len() {
        if i == 6 {
            // Skip checksum field (bytes 6-7)
            i += 2;
            continue;
        }
        sum += u16::from_be_bytes([udp_datagram[i], udp_datagram[i + 1]]) as u32;
        i += 2;
    }

    // Handle odd byte
    if i < udp_datagram.len() {
        sum += (udp_datagram[i] as u32) << 8;
    }

    // Fold 32-bit sum to 16 bits
    while (sum >> 16) != 0 {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }

    let checksum = !(sum as u16);
    // UDP checksum of 0 means "no checksum" - use 0xFFFF instead
    if checksum == 0 { 0xFFFF } else { checksum }
}

/// Fix checksums in an IP packet (modifies packet in place)
/// Returns true if checksums were fixed
fn fix_packet_checksums(packet: &mut [u8]) -> bool {
    if packet.len() < 20 {
        return false;
    }

    let ihl = ((packet[0] & 0x0F) as usize) * 4;
    if packet.len() < ihl {
        return false;
    }

    // Fix IP header checksum
    packet[10] = 0;
    packet[11] = 0;
    let ip_checksum = calculate_ip_checksum(&packet[..ihl]);
    packet[10] = (ip_checksum >> 8) as u8;
    packet[11] = (ip_checksum & 0xFF) as u8;

    let protocol = packet[9];
    let transport_offset = ihl;

    // Fix TCP checksum
    if protocol == 6 && packet.len() >= transport_offset + 20 {
        packet[transport_offset + 16] = 0;
        packet[transport_offset + 17] = 0;
        let tcp_checksum = calculate_tcp_checksum(packet, ihl);
        packet[transport_offset + 16] = (tcp_checksum >> 8) as u8;
        packet[transport_offset + 17] = (tcp_checksum & 0xFF) as u8;
        return true;
    }

    // Fix UDP checksum
    if protocol == 17 && packet.len() >= transport_offset + 8 {
        packet[transport_offset + 6] = 0;
        packet[transport_offset + 7] = 0;
        let udp_checksum = calculate_udp_checksum(packet, ihl);
        packet[transport_offset + 6] = (udp_checksum >> 8) as u8;
        packet[transport_offset + 7] = (udp_checksum & 0xFF) as u8;
        return true;
    }

    true
}

/// V3 Inbound receiver thread - reads unencrypted packets from UDP relay
/// and injects to MSTCP
///
/// - Receives packets from UdpRelay (already stripped of session ID)
/// - Injects to MSTCP
fn run_v3_inbound_receiver(
    relay: Arc<super::udp_relay::UdpRelay>,
    config: InboundConfig,
    stop_flag: Arc<AtomicBool>,
    throughput: ThroughputStats,
) {
    log::info!("========================================");
    log::info!("V3 INBOUND RECEIVER STARTING");
    log::info!("========================================");
    log::info!("  Relay: {}", relay.relay_addr());
    log::info!("  Session ID: {:016x}", relay.session_id_u64());
    log::info!("  Adapter: {}", config.physical_adapter_name);
    // Open driver ONCE at thread start (not per-packet!)
    let driver = match ndisapi::Ndisapi::new("NDISRD") {
        Ok(d) => {
            log::info!("V3 inbound receiver: ndisapi driver opened successfully");
            d
        }
        Err(e) => {
            log::error!("========================================");
            log::error!("V3 INBOUND RECEIVER FATAL ERROR");
            log::error!("Failed to open ndisapi driver: {}", e);
            log::error!("Inbound traffic will NOT work!");
            log::error!("========================================");
            return;
        }
    };

    let adapters = match driver.get_tcpip_bound_adapters_info() {
        Ok(a) => a,
        Err(e) => {
            log::error!("========================================");
            log::error!("V3 INBOUND RECEIVER FATAL ERROR");
            log::error!("Failed to get adapters: {}", e);
            log::error!("Inbound traffic will NOT work!");
            log::error!("========================================");
            return;
        }
    };

    let adapter = match adapters
        .iter()
        .find(|a| a.get_name() == &config.physical_adapter_name)
    {
        Some(a) => a,
        None => {
            log::error!("========================================");
            log::error!("V3 INBOUND RECEIVER FATAL ERROR");
            log::error!(
                "Physical adapter '{}' not found!",
                config.physical_adapter_name
            );
            log::error!("Available adapters:");
            for a in adapters.iter() {
                log::error!("  - {}", a.get_name());
            }
            log::error!("Inbound traffic will NOT work!");
            log::error!("========================================");
            return;
        }
    };

    let adapter_handle = adapter.get_handle();
    log::info!("V3 inbound receiver: adapter handle acquired, ready to inject packets");

    let mut recv_buf = vec![0u8; 2048];
    let mut packets_received = 0u64;
    let mut packets_injected = 0u64;
    let mut inject_errors = 0u64;

    // Health monitoring timestamps
    let start_time = std::time::Instant::now();
    let mut last_packet_time: Option<std::time::Instant> = None;
    let mut last_health_check = std::time::Instant::now();
    let mut no_traffic_warning_logged = false;

    // Health check constants
    const HEALTH_CHECK_INTERVAL_SECS: u64 = 5;
    const NO_TRAFFIC_WARNING_SECS: u64 = 10;

    // Keepalive interval for relay - must match udp_relay::KEEPALIVE_INTERVAL (15s)
    // 20s was too long and could cause NAT timeout on strict networks (Error 277)
    let mut last_keepalive = std::time::Instant::now();
    const KEEPALIVE_INTERVAL_SECS: u64 = 15;

    log::info!("V3 inbound receiver: entering main loop, waiting for relay traffic...");

    loop {
        if stop_flag.load(Ordering::Relaxed) {
            log::info!("V3 inbound receiver: stop flag set, exiting loop");
            break;
        }

        let now = std::time::Instant::now();

        // === HEALTH CHECK (every 5 seconds) ===
        if now.duration_since(last_health_check).as_secs() >= HEALTH_CHECK_INTERVAL_SECS {
            last_health_check = now;
            let uptime_secs = now.duration_since(start_time).as_secs();

            // Check for "no traffic ever received" condition
            if packets_received == 0
                && uptime_secs >= NO_TRAFFIC_WARNING_SECS
                && !no_traffic_warning_logged
            {
                no_traffic_warning_logged = true;
                log::error!("========================================");
                log::error!("V3 WARNING: NO INBOUND TRAFFIC DETECTED!");
                log::error!("========================================");
                log::error!("  Uptime: {}s", uptime_secs);
                log::error!("  Packets received: 0");
                log::error!("");
                log::error!("This may indicate:");
                log::error!("  1. Relay server not running on port 51821");
                log::error!("  2. Firewall blocking UDP traffic");
                log::error!("  3. Session ID mismatch");
                log::error!("========================================");
            }

            // Periodic health log
            let rx_bytes = throughput.bytes_rx.load(Ordering::Relaxed);
            let rx_rate = if uptime_secs > 0 {
                rx_bytes / uptime_secs
            } else {
                0
            };
            log::info!(
                "V3 inbound health: {}s uptime, {} recv, {} injected, {} B/s avg, {} errors",
                uptime_secs,
                packets_received,
                packets_injected,
                rx_rate,
                inject_errors
            );
        }

        // === KEEPALIVE (every 20 seconds) ===
        if now.duration_since(last_keepalive).as_secs() >= KEEPALIVE_INTERVAL_SECS {
            last_keepalive = now;
            if let Err(e) = relay.send_keepalive() {
                log::warn!("V3 inbound receiver: keepalive failed: {}", e);
            }
        }

        // === RECEIVE PACKET FROM RELAY ===
        match relay.receive_inbound(&mut recv_buf) {
            Ok(Some(len)) => {
                packets_received += 1;
                last_packet_time = Some(now);

                // Track throughput
                throughput.bytes_rx.fetch_add(len as u64, Ordering::Relaxed);

                // Log first 10 received packets at INFO level
                if packets_received <= 10 {
                    log::info!(
                        "V3 inbound: received packet #{} ({} bytes)",
                        packets_received,
                        len
                    );
                }

                // The payload is already plain IP packet (relay strips session ID)
                let ip_packet = &recv_buf[..len];

                // Inject to MSTCP
                match inject_inbound_packet(
                    ip_packet,
                    &config,
                    adapter_handle,
                    &driver,
                    packets_received,
                ) {
                    Some(true) => {
                        packets_injected += 1;
                        if packets_injected <= 10 || packets_injected % 1000 == 0 {
                            log::info!(
                                "V3 inbound: injected packet #{} ({} bytes)",
                                packets_injected,
                                len
                            );
                        }
                    }
                    Some(false) => {
                        inject_errors += 1;
                        if inject_errors <= 10 {
                            log::error!(
                                "V3 inbound: FAILED to inject packet #{}",
                                packets_received
                            );
                        }
                    }
                    None => {
                        // Packet skipped (e.g., too small)
                    }
                }
            }
            Ok(None) => {
                // No packet available (socket timeout already acts as sleep)
                continue;
            }
            Err(e) => {
                log::warn!("V3 inbound receiver: receive error: {}", e);
                std::thread::sleep(std::time::Duration::from_millis(2));
            }
        }
    }

    // === FINAL STATS ===
    let total_uptime = start_time.elapsed().as_secs();
    let (sent, recv) = relay.stats();
    log::info!("========================================");
    log::info!("V3 INBOUND RECEIVER STOPPED");
    log::info!("========================================");
    log::info!("  Uptime: {}s", total_uptime);
    log::info!("  Packets received: {}", packets_received);
    log::info!("  Packets injected: {}", packets_injected);
    log::info!("  Inject errors: {}", inject_errors);
    log::info!("  Relay stats: sent={}, recv={}", sent, recv);
    log::info!(
        "  Total RX bytes: {}",
        throughput.bytes_rx.load(Ordering::Relaxed)
    );

    if packets_received == 0 && total_uptime > NO_TRAFFIC_WARNING_SECS {
        log::error!("========================================");
        log::error!("CRITICAL: V3 session ended with ZERO inbound traffic!");
        log::error!("Relay server may not be running.");
        log::error!("========================================");
    }
    log::info!("========================================");
}

#[cfg(test)]
mod tests {
    use super::*;

    fn build_ipv4_frame(
        protocol: u8,
        src_ip: Ipv4Addr,
        dst_ip: Ipv4Addr,
        src_port: u16,
        dst_port: u16,
    ) -> Vec<u8> {
        // Minimal Ethernet + IPv4 + (UDP/TCP) frame. Routing decisions only need:
        // - EtherType
        // - IPv4 header with src/dst/protocol
        // - First 4 bytes of transport header (ports)
        let mut frame = vec![0u8; 14 + 20 + 8];
        frame[12..14].copy_from_slice(&0x0800u16.to_be_bytes()); // IPv4 EtherType

        let ip_start = 14;
        frame[ip_start] = 0x45; // IPv4, IHL=5
        frame[ip_start + 9] = protocol; // TCP=6, UDP=17
        frame[ip_start + 12..ip_start + 16].copy_from_slice(&src_ip.octets());
        frame[ip_start + 16..ip_start + 20].copy_from_slice(&dst_ip.octets());

        let transport_start = ip_start + 20;
        frame[transport_start..transport_start + 2].copy_from_slice(&src_port.to_be_bytes());
        frame[transport_start + 2..transport_start + 4].copy_from_slice(&dst_port.to_be_bytes());

        frame
    }

    #[test]
    fn test_parse_ports() {
        // Create minimal Ethernet + IP + TCP frame
        let mut frame = vec![0u8; 54];
        // Ethernet header
        frame[12..14].copy_from_slice(&0x0800u16.to_be_bytes()); // IPv4
        // IP header
        frame[14] = 0x45; // IPv4, IHL=5
        frame[23] = 6; // TCP
        // TCP header
        frame[34..36].copy_from_slice(&1234u16.to_be_bytes()); // src port
        frame[36..38].copy_from_slice(&80u16.to_be_bytes()); // dst port

        let (src, dst) = parse_ports(&frame).unwrap();
        assert_eq!(src, 1234);
        assert_eq!(dst, 80);
    }

    #[test]
    fn test_should_route_snapshot_tunnels_udp() {
        let src_ip = Ipv4Addr::new(192, 168, 1, 100);
        let dst_ip = Ipv4Addr::new(1, 1, 1, 1);
        let src_port = 50000;
        let dst_port = 443;
        let pid = 1234;

        let mut connections = HashMap::new();
        connections.insert(ConnectionKey::new(src_ip, src_port, Protocol::Udp), pid);

        let tunnel_pids: std::collections::HashSet<u32> = [pid].into_iter().collect();

        let snapshot = ProcessSnapshot {
            connections,
            pid_names: HashMap::new(),
            tunnel_apps: std::collections::HashSet::new(),
            tunnel_pids,
            version: 0,
            created_at: std::time::Instant::now(),
        };

        let frame = build_ipv4_frame(17, src_ip, dst_ip, src_port, dst_port);
        let mut inline_cache: InlineCache = HashMap::new();

        assert!(should_route_to_vpn_with_inline_cache(
            &frame,
            &snapshot,
            &mut inline_cache
        ));
        assert!(
            inline_cache.is_empty(),
            "Snapshot hit should not mutate cache"
        );
    }

    #[test]
    fn test_should_route_snapshot_does_not_tunnel_tcp() {
        let src_ip = Ipv4Addr::new(192, 168, 1, 100);
        let dst_ip = Ipv4Addr::new(128, 116, 50, 100);
        let src_port = 50001;
        let dst_port = 55000;
        let pid = 1234;

        let mut connections = HashMap::new();
        connections.insert(ConnectionKey::new(src_ip, src_port, Protocol::Tcp), pid);

        let tunnel_pids: std::collections::HashSet<u32> = [pid].into_iter().collect();

        let snapshot = ProcessSnapshot {
            connections,
            pid_names: HashMap::new(),
            tunnel_apps: std::collections::HashSet::new(),
            tunnel_pids,
            version: 0,
            created_at: std::time::Instant::now(),
        };

        let frame = build_ipv4_frame(6, src_ip, dst_ip, src_port, dst_port);
        let mut inline_cache: InlineCache = HashMap::new();

        assert!(!should_route_to_vpn_with_inline_cache(
            &frame,
            &snapshot,
            &mut inline_cache
        ));
        assert!(inline_cache.is_empty());
    }

    #[test]
    fn test_should_route_inline_cache_hit_tunnels_udp() {
        let src_ip = Ipv4Addr::new(10, 0, 0, 2);
        let dst_ip = Ipv4Addr::new(1, 1, 1, 1);
        let src_port = 40000;
        let dst_port = 53;

        let snapshot = ProcessSnapshot {
            connections: HashMap::new(),
            pid_names: HashMap::new(),
            tunnel_apps: std::collections::HashSet::new(),
            tunnel_pids: std::collections::HashSet::new(),
            version: 0,
            created_at: std::time::Instant::now(),
        };

        let frame = build_ipv4_frame(17, src_ip, dst_ip, src_port, dst_port);
        let mut inline_cache: InlineCache = HashMap::new();
        inline_cache.insert((src_ip, src_port, Protocol::Udp), true);

        assert!(should_route_to_vpn_with_inline_cache(
            &frame,
            &snapshot,
            &mut inline_cache
        ));
    }

    #[test]
    fn test_should_route_speculative_game_server_caches_and_tunnels() {
        let src_ip = Ipv4Addr::new(10, 0, 0, 2);
        let dst_ip = Ipv4Addr::new(128, 116, 50, 100);
        let src_port = 40001;
        let dst_port = 55000;

        let snapshot = ProcessSnapshot {
            connections: HashMap::new(),
            pid_names: HashMap::new(),
            tunnel_apps: std::collections::HashSet::new(),
            tunnel_pids: std::collections::HashSet::new(),
            version: 0,
            created_at: std::time::Instant::now(),
        };

        let frame = build_ipv4_frame(17, src_ip, dst_ip, src_port, dst_port);
        let mut inline_cache: InlineCache = HashMap::new();

        assert!(should_route_to_vpn_with_inline_cache(
            &frame,
            &snapshot,
            &mut inline_cache
        ));
        assert!(
            inline_cache.contains_key(&(src_ip, src_port, Protocol::Udp)),
            "Speculative tunnel should seed the inline cache"
        );
    }

    #[test]
    fn test_should_route_non_game_does_not_cache() {
        let src_ip = Ipv4Addr::new(10, 0, 0, 2);
        let dst_ip = Ipv4Addr::new(1, 1, 1, 1);
        let src_port = 40002;
        let dst_port = 55000;

        let snapshot = ProcessSnapshot {
            connections: HashMap::new(),
            pid_names: HashMap::new(),
            tunnel_apps: std::collections::HashSet::new(),
            tunnel_pids: std::collections::HashSet::new(),
            version: 0,
            created_at: std::time::Instant::now(),
        };

        let frame = build_ipv4_frame(17, src_ip, dst_ip, src_port, dst_port);
        let mut inline_cache: InlineCache = HashMap::new();

        assert!(!should_route_to_vpn_with_inline_cache(
            &frame,
            &snapshot,
            &mut inline_cache
        ));
        assert!(inline_cache.is_empty());
    }
}
