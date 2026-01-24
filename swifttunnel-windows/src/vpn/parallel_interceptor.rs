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
//! Optimizations (v0.5.55):
//! - Thread-local NAT and encryption buffers (eliminates per-packet heap allocs)
//! - ArrayVec for stack-allocated packet work items
//! - Reduced channel timeout from 10ms to 1ms
//!
//! ```
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
//!       │  VPN Tunnel  │                         │  Passthrough │
//!       │  (Wintun)    │                         │  (Adapter)   │
//!       └──────────────┘                         └──────────────┘
//! ```

use std::cell::RefCell;
use std::collections::HashMap;
use std::net::{Ipv4Addr, SocketAddr, UdpSocket};
#[cfg(target_os = "windows")]
use std::os::windows::process::CommandExt;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use std::thread::{self, JoinHandle};

use arrayvec::ArrayVec;

use boringtun::noise::{Tunn, TunnResult};

use super::process_cache::{LockFreeProcessCache, ProcessSnapshot};
use super::process_tracker::{ConnectionKey, Protocol};
use super::tunnel::FastMutex;
use super::{VpnError, VpnResult};
use crate::geolocation::is_roblox_game_server_ip;

/// Context for direct WireGuard encryption (bypasses OS routing)
///
/// Uses parking_lot::Mutex (FastMutex) for the Tunn instance to minimize
/// contention when multiple worker threads encrypt packets simultaneously.
/// This provides ~10x less lock overhead compared to std::sync::Mutex.
#[derive(Clone)]
pub struct VpnEncryptContext {
    /// WireGuard tunnel for encryption (FastMutex for low-contention locking)
    pub tunn: Arc<FastMutex<Tunn>>,
    /// UDP socket for sending encrypted packets
    pub socket: Arc<UdpSocket>,
    /// VPN server address
    pub server_addr: SocketAddr,
}

// ============================================================================
// ZERO-ALLOCATION BUFFER MANAGEMENT
// ============================================================================

/// Maximum Ethernet frame size (MTU 1500 + headers)
const MAX_PACKET_SIZE: usize = 1600;

/// Maximum WireGuard overhead (header + auth tag)
const WIREGUARD_OVERHEAD: usize = 80;

/// Pre-allocated buffer size for encryption output
const ENCRYPT_BUFFER_SIZE: usize = MAX_PACKET_SIZE + WIREGUARD_OVERHEAD;

/// Thread-local pre-allocated buffers to eliminate per-packet heap allocations
/// These are used for NAT rewriting and encryption operations
thread_local! {
    /// Buffer for NAT-rewritten packets (source IP rewriting)
    static NAT_BUFFER: RefCell<[u8; MAX_PACKET_SIZE]> = RefCell::new([0u8; MAX_PACKET_SIZE]);

    /// Buffer for WireGuard encryption output
    static ENCRYPT_BUFFER: RefCell<[u8; ENCRYPT_BUFFER_SIZE]> = RefCell::new([0u8; ENCRYPT_BUFFER_SIZE]);
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
    /// VPN adapter index
    vpn_adapter_idx: Option<usize>,
    /// Wintun session for VPN injection
    wintun_session: Option<Arc<wintun::Session>>,
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
    /// VPN tunnel IP (for NAT rewriting on inbound packets)
    tunnel_ip: Option<std::net::Ipv4Addr>,
    /// Physical adapter IP (for NAT rewriting on inbound packets)
    internet_ip: Option<std::net::Ipv4Addr>,
    /// Context for direct WireGuard encryption (bypasses Wintun for outbound)
    vpn_encrypt_ctx: Option<VpnEncryptContext>,
    /// Inbound handler for decrypted packets (does NAT and injects to MSTCP)
    inbound_handler: Option<Arc<dyn Fn(&[u8]) + Send + Sync>>,
    /// Inbound receiver thread handle (reads from VpnEncryptContext socket)
    inbound_receiver_handle: Option<JoinHandle<()>>,
    /// Detected game server IPs (for notification purposes)
    detected_game_servers: Arc<parking_lot::RwLock<std::collections::HashSet<std::net::Ipv4Addr>>>,
}

impl ParallelInterceptor {
    /// Create new parallel interceptor
    pub fn new(tunnel_apps: Vec<String>, routing_mode: crate::settings::RoutingMode) -> Self {
        // Use number of logical CPUs, capped at 8 for efficiency
        let num_workers = num_cpus::get().min(8).max(1);

        log::info!(
            "Creating parallel interceptor with {} workers (CPUs: {}), routing mode: {:?}",
            num_workers,
            num_cpus::get(),
            routing_mode
        );

        let worker_stats: Vec<Arc<WorkerStats>> =
            (0..num_workers).map(|_| Arc::new(WorkerStats::default())).collect();

        Self {
            num_workers,
            process_cache: Arc::new(LockFreeProcessCache::new(tunnel_apps, routing_mode)),
            stop_flag: Arc::new(AtomicBool::new(false)),
            worker_handles: Vec::new(),
            reader_handle: None,
            refresher_handle: None,
            physical_adapter_idx: None,
            physical_adapter_name: None,
            physical_adapter_friendly_name: None,
            tso_was_disabled: false,
            vpn_adapter_idx: None,
            wintun_session: None,
            active: false,
            worker_stats,
            total_packets: AtomicU64::new(0),
            total_tunneled: AtomicU64::new(0),
            total_injected: AtomicU64::new(0),
            throughput_stats: ThroughputStats::default(),
            tunnel_ip: None,
            internet_ip: None,
            vpn_encrypt_ctx: None,
            inbound_handler: None,
            inbound_receiver_handle: None,
            detected_game_servers: Arc::new(parking_lot::RwLock::new(std::collections::HashSet::new())),
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

    /// Set Wintun session for VPN packet injection
    pub fn set_wintun_session(&mut self, session: Arc<wintun::Session>) {
        self.wintun_session = Some(session);
    }

    /// Set NAT IPs for inbound packet rewriting
    ///
    /// When inbound VPN packets arrive with destination = tunnel_ip,
    /// the inbound handler rewrites it to internet_ip so the original
    /// app socket can receive the response.
    pub fn set_nat_ips(&mut self, tunnel_ip: &str, internet_ip: &str) {
        if let Ok(tun_ip) = tunnel_ip.split('/').next().unwrap_or(tunnel_ip).parse::<std::net::Ipv4Addr>() {
            self.tunnel_ip = Some(tun_ip);
            log::info!("Set NAT tunnel IP: {}", tun_ip);
        }
        if let Ok(int_ip) = internet_ip.parse::<std::net::Ipv4Addr>() {
            self.internet_ip = Some(int_ip);
            log::info!("Set NAT internet IP: {}", int_ip);
        }
    }

    /// Set VPN encryption context for direct WireGuard encryption
    ///
    /// This allows workers to encrypt packets directly and send via UDP,
    /// bypassing Wintun for outbound tunnel traffic. This is faster because
    /// it eliminates the Wintun buffer copy and context switch.
    pub fn set_vpn_encrypt_context(&mut self, ctx: VpnEncryptContext) {
        log::info!(
            "Set VPN encrypt context: server={}",
            ctx.server_addr
        );
        self.vpn_encrypt_ctx = Some(ctx);
    }

    /// Set inbound handler for decrypted packets
    ///
    /// This handler is called for each decrypted packet received on the
    /// VpnEncryptContext socket. It performs NAT rewriting and injects
    /// the packet to MSTCP so the original app can receive the response.
    pub fn set_inbound_handler(&mut self, handler: Arc<dyn Fn(&[u8]) + Send + Sync>) {
        log::info!("Set inbound handler for VPN responses");
        self.inbound_handler = Some(handler);
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
    ) -> VpnResult<()> {
        log::info!(
            "Configuring parallel interceptor for VPN adapter: {}",
            vpn_adapter_name
        );

        // Update tunnel apps in cache
        Arc::get_mut(&mut self.process_cache)
            .ok_or_else(|| VpnError::SplitTunnel("Cache in use".to_string()))?
            .set_tunnel_apps(tunnel_apps);

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
            let friendly_name = get_adapter_friendly_name(&internal_name).unwrap_or_default();

            log::debug!(
                "  Adapter {}: internal='{}' friendly='{}'",
                idx,
                internal_name,
                friendly_name
            );

            let name_lower = internal_name.to_lowercase();
            let friendly_lower = friendly_name.to_lowercase();

            let is_vpn = name_lower.contains(&vpn_adapter_name.to_lowercase())
                || name_lower.contains("swifttunnel")
                || name_lower.contains("wintun")
                || friendly_lower.contains(&vpn_adapter_name.to_lowercase())
                || friendly_lower.contains("swifttunnel")
                || friendly_lower.contains("wintun");

            let is_virtual = name_lower.contains("loopback")
                || friendly_lower.contains("loopback")
                || friendly_lower.contains("isatap")
                || friendly_lower.contains("teredo")
                || friendly_lower.is_empty();

            if is_vpn {
                vpn_adapter = Some((idx, friendly_name.clone()));
            } else if !is_virtual {
                let mut score = 0;
                if friendly_lower.contains("ethernet")
                    || friendly_lower.contains("intel")
                    || friendly_lower.contains("realtek")
                    || friendly_lower.contains("broadcom")
                {
                    score += 100;
                }
                if !friendly_name.is_empty() {
                    score += 50;
                }
                score += (10 - idx.min(10)) as i32;
                physical_candidates.push((idx, friendly_name.clone(), internal_name.to_string(), score));
            }
        }

        // Select physical adapter
        if let Some((idx, friendly_name, internal_name, _)) = physical_candidates.into_iter().max_by_key(|x| x.3) {
            self.physical_adapter_idx = Some(idx);
            self.physical_adapter_name = Some(internal_name.clone());
            self.physical_adapter_friendly_name = Some(friendly_name.clone());
            log::info!("Selected physical adapter: {} (index {}, internal: '{}')", friendly_name, idx, internal_name);
        } else {
            return Err(VpnError::SplitTunnel(
                "No physical adapter found".to_string(),
            ));
        }

        // Set VPN adapter
        if let Some((idx, name)) = vpn_adapter {
            self.vpn_adapter_idx = Some(idx);
            log::info!("Found VPN adapter: {} (index {})", name, idx);
        } else {
            return Err(VpnError::SplitTunnel(format!(
                "VPN adapter '{}' not found",
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
                        log::warn!("PowerShell timed out after {}s, killing process", timeout_secs);
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
            self.tso_was_disabled = true;
        } else {
            log::warn!("Failed to disable TSO (non-fatal) - adapter may not support these settings");
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
        } else {
            log::warn!("Failed to re-enable TSO - manual re-enable may be needed");
        }

        self.tso_was_disabled = false;
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

        self.stop_flag.store(false, Ordering::SeqCst);
        self.active = true;

        // Create channels for workers
        let (senders, receivers): (Vec<_>, Vec<_>) = (0..self.num_workers)
            .map(|_| crossbeam_channel::bounded::<PacketWork>(1024))
            .unzip();

        // Start cache refresher thread (single writer)
        let refresher_stop = Arc::clone(&self.stop_flag);
        let refresher_cache = Arc::clone(&self.process_cache);
        self.refresher_handle = Some(thread::spawn(move || {
            run_cache_refresher(refresher_cache, refresher_stop);
        }));

        // Reset throughput stats on start
        self.throughput_stats.reset();

        // Start worker threads
        for (worker_id, receiver) in receivers.into_iter().enumerate() {
            let stop_flag = Arc::clone(&self.stop_flag);
            let process_cache = Arc::clone(&self.process_cache);
            let wintun_session = self.wintun_session.clone();
            let stats = Arc::clone(&self.worker_stats[worker_id]);
            let throughput = self.throughput_stats.clone();
            let tunnel_ip = self.tunnel_ip;
            let internet_ip = self.internet_ip;
            let vpn_encrypt_ctx = self.vpn_encrypt_ctx.clone();
            let detected_game_servers = Arc::clone(&self.detected_game_servers);

            let handle = thread::spawn(move || {
                // Set CPU affinity for this worker
                set_thread_affinity(worker_id);

                run_packet_worker(
                    worker_id,
                    receiver,
                    process_cache,
                    wintun_session,
                    stats,
                    throughput,
                    stop_flag,
                    tunnel_ip,
                    internet_ip,
                    vpn_encrypt_ctx,
                    detected_game_servers,
                );
            });

            self.worker_handles.push(handle);
        }

        // Start packet reader/dispatcher thread
        let reader_stop = Arc::clone(&self.stop_flag);
        let num_workers = self.num_workers;
        let physical_name = Arc::new(
            self.physical_adapter_name
                .clone()
                .ok_or_else(|| VpnError::SplitTunnel("Physical adapter name not set".to_string()))?
        );

        self.reader_handle = Some(thread::spawn(move || {
            if let Err(e) = run_packet_reader(physical_idx, physical_name, senders, reader_stop, num_workers) {
                log::error!("Packet reader error: {}", e);
            }
        }));

        // Start inbound receiver thread (reads encrypted responses from VpnEncryptContext socket)
        // Optimized: opens driver ONCE at thread start, not per-packet
        if let Some(ref vpn_ctx) = self.vpn_encrypt_ctx {
            // Create InboundConfig with all necessary parameters
            let inbound_config = self.create_inbound_config();

            if let Some(config) = inbound_config {
                let ctx = vpn_ctx.clone();
                let inbound_stop = Arc::clone(&self.stop_flag);
                let throughput = self.throughput_stats.clone();

                // Set socket to non-blocking for clean shutdown
                if let Err(e) = ctx.socket.set_read_timeout(Some(std::time::Duration::from_millis(100))) {
                    log::warn!("Failed to set socket read timeout: {}", e);
                }

                self.inbound_receiver_handle = Some(thread::spawn(move || {
                    run_inbound_receiver(ctx, config, inbound_stop, throughput);
                }));
                log::info!("Inbound receiver thread started (optimized)");
            } else {
                log::warn!("Inbound receiver NOT started (failed to create config - physical_adapter_name not set?)");
            }
        } else {
            log::info!("Inbound receiver NOT started (no vpn_encrypt_ctx)");
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

        // Wait for threads
        if let Some(handle) = self.reader_handle.take() {
            let _ = handle.join();
        }

        for handle in self.worker_handles.drain(..) {
            let _ = handle.join();
        }

        if let Some(handle) = self.refresher_handle.take() {
            let _ = handle.join();
        }

        if let Some(handle) = self.inbound_receiver_handle.take() {
            let _ = handle.join();
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

    /// Inject an inbound IP packet to the physical adapter's MSTCP stack
    ///
    /// This is called by the WireGuard tunnel inbound task when split tunnel is active.
    /// The packet is a decrypted IP packet that should be delivered to the original app.
    pub fn inject_inbound(&self, ip_packet: &[u8]) {
        use ndisapi::{DirectionFlags, EthMRequest, IntermediateBuffer};

        let physical_name = match &self.physical_adapter_name {
            Some(name) => name,
            None => {
                log::warn!("inject_inbound: no physical adapter configured");
                return;
            }
        };

        // Open driver
        let driver = match ndisapi::Ndisapi::new("NDISRD") {
            Ok(d) => d,
            Err(e) => {
                log::warn!("inject_inbound: failed to open driver: {}", e);
                return;
            }
        };

        let adapters = match driver.get_tcpip_bound_adapters_info() {
            Ok(a) => a,
            Err(e) => {
                log::warn!("inject_inbound: failed to get adapters: {}", e);
                return;
            }
        };

        let adapter = match adapters.iter().find(|a| a.get_name() == physical_name) {
            Some(a) => a,
            None => {
                log::warn!("inject_inbound: physical adapter '{}' not found", physical_name);
                return;
            }
        };

        let adapter_handle = adapter.get_handle();

        // Create Ethernet frame with IP packet payload
        // We need to wrap the IP packet in an Ethernet frame for injection
        const MAX_ETHER_FRAME: usize = 1522;
        let frame_len = 14 + ip_packet.len();

        // Safety check: Don't process oversized packets that would overflow IntermediateBuffer
        if frame_len > MAX_ETHER_FRAME {
            log::warn!("inject_inbound: packet too large ({} bytes), dropping", frame_len);
            return;
        }

        let mut ethernet_frame = vec![0u8; frame_len];

        // Ethernet header:
        // - Destination MAC (6 bytes): Local adapter's MAC (will be filled by stack)
        // - Source MAC (6 bytes): Use zeros (will be filled by stack)
        // - EtherType (2 bytes): 0x0800 for IPv4

        // Get adapter MAC for destination
        let _medium = adapter.get_medium();
        // For now, use a broadcast-like approach - the stack will handle it
        ethernet_frame[0..6].copy_from_slice(&[0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF]); // Broadcast
        ethernet_frame[6..12].copy_from_slice(&[0x00, 0x00, 0x00, 0x00, 0x00, 0x00]); // Source zeros
        ethernet_frame[12] = 0x08; // EtherType: IPv4
        ethernet_frame[13] = 0x00;
        ethernet_frame[14..].copy_from_slice(ip_packet);

        // Create IntermediateBuffer with the Ethernet frame
        let mut buffer = IntermediateBuffer::default();
        // CRITICAL: Set direction flag to RECEIVE - we're injecting as if it came from the network
        buffer.device_flags = DirectionFlags::PACKET_FLAG_ON_RECEIVE;
        buffer.length = ethernet_frame.len() as u32;
        buffer.buffer.0[..ethernet_frame.len()].copy_from_slice(&ethernet_frame);

        // Send to MSTCP (inject into the receive path so the app gets it)
        let mut to_mstcp: EthMRequest<1> = EthMRequest::new(adapter_handle);
        if to_mstcp.push(&buffer).is_ok() {
            if let Err(e) = driver.send_packets_to_mstcp::<1>(&to_mstcp) {
                log::warn!("inject_inbound: send_packets_to_mstcp failed: {:?}", e);
            } else {
                // Update RX stats
                self.throughput_stats.add_rx(ip_packet.len() as u64);
            }
        }
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
                log::error!("create_inbound_config: physical adapter '{}' not found", physical_name);
                return None;
            }
        };

        log::info!(
            "create_inbound_config: adapter={}, MAC={:02X}:{:02X}:{:02X}:{:02X}:{:02X}:{:02X}, NAT: {:?} -> {:?}",
            physical_name,
            adapter_mac[0], adapter_mac[1], adapter_mac[2],
            adapter_mac[3], adapter_mac[4], adapter_mac[5],
            self.tunnel_ip, self.internet_ip
        );

        Some(InboundConfig {
            physical_adapter_name: physical_name,
            adapter_mac,
            tunnel_ip: self.tunnel_ip,
            internet_ip: self.internet_ip,
        })
    }

    /// Get a closure that can be used as an inbound handler for the WireGuard tunnel
    /// (Legacy - kept for compatibility, prefer using create_inbound_config with run_inbound_receiver)
    ///
    /// This creates a handler that injects packets to the physical adapter.
    /// If NAT IPs are configured, it rewrites destination IP from tunnel_ip to internet_ip.
    pub fn create_inbound_handler(&self) -> Option<std::sync::Arc<dyn Fn(&[u8]) + Send + Sync>> {
        let physical_name = self.physical_adapter_name.clone()?;
        let throughput_stats = self.throughput_stats.clone();
        let tunnel_ip = self.tunnel_ip;
        let internet_ip = self.internet_ip;

        // Pre-open driver and get adapter info for efficiency
        let driver = match ndisapi::Ndisapi::new("NDISRD") {
            Ok(d) => d,
            Err(e) => {
                log::error!("create_inbound_handler: failed to open driver: {}", e);
                return None;
            }
        };

        let adapters = match driver.get_tcpip_bound_adapters_info() {
            Ok(a) => a,
            Err(e) => {
                log::error!("create_inbound_handler: failed to get adapters: {}", e);
                return None;
            }
        };

        // Get adapter MAC address (copy, so it's Send + Sync)
        // Note: adapter_handle is NOT Send/Sync, so we look it up fresh in each call
        let adapter_mac: [u8; 6] = match adapters.iter().find(|a| a.get_name() == &physical_name) {
            Some(a) => a.get_hw_address()[0..6].try_into().unwrap_or([0; 6]),
            None => {
                log::error!("create_inbound_handler: physical adapter '{}' not found", physical_name);
                return None;
            }
        };

        log::info!(
            "create_inbound_handler: adapter={}, MAC={:02X}:{:02X}:{:02X}:{:02X}:{:02X}:{:02X}",
            physical_name,
            adapter_mac[0], adapter_mac[1], adapter_mac[2],
            adapter_mac[3], adapter_mac[4], adapter_mac[5]
        );

        // Track packets for logging (use atomic counter)
        let packet_count = std::sync::Arc::new(std::sync::atomic::AtomicU64::new(0));

        Some(std::sync::Arc::new(move |ip_packet: &[u8]| {
            use ndisapi::{DirectionFlags, EthMRequest, IntermediateBuffer};

            if ip_packet.len() < 20 {
                log::warn!("inbound_handler: packet too short ({} bytes)", ip_packet.len());
                return;
            }

            // Parse IP header
            let src_ip = std::net::Ipv4Addr::new(
                ip_packet[12], ip_packet[13], ip_packet[14], ip_packet[15]
            );
            let dst_ip = std::net::Ipv4Addr::new(
                ip_packet[16], ip_packet[17], ip_packet[18], ip_packet[19]
            );
            let protocol = ip_packet[9];

            // Parse ICMP error packets for diagnostics
            if protocol == 1 && ip_packet.len() >= 28 {
                let icmp_type = ip_packet[20];
                let icmp_code = ip_packet[21];

                // ICMP error types that indicate routing problems
                let error_desc = match (icmp_type, icmp_code) {
                    (3, 0) => Some("Network Unreachable"),
                    (3, 1) => Some("Host Unreachable"),
                    (3, 2) => Some("Protocol Unreachable"),
                    (3, 3) => Some("Port Unreachable"),
                    (3, 4) => Some("Fragmentation Needed"),
                    (3, 5) => Some("Source Route Failed"),
                    (3, 6) => Some("Destination Network Unknown"),
                    (3, 7) => Some("Destination Host Unknown"),
                    (3, 9) => Some("Network Administratively Prohibited"),
                    (3, 10) => Some("Host Administratively Prohibited"),
                    (3, 13) => Some("Communication Administratively Prohibited"),
                    (11, 0) => Some("TTL Expired in Transit"),
                    (11, 1) => Some("Fragment Reassembly Time Exceeded"),
                    _ => None,
                };

                if let Some(desc) = error_desc {
                    // Extract original destination from embedded IP header (at offset 28)
                    if ip_packet.len() >= 48 {
                        let orig_dst = std::net::Ipv4Addr::new(
                            ip_packet[44], ip_packet[45], ip_packet[46], ip_packet[47]
                        );
                        log::warn!(
                            "inbound_handler: ICMP Error - {} (type={}, code={}) for packet to {}",
                            desc, icmp_type, icmp_code, orig_dst
                        );
                    } else {
                        log::warn!(
                            "inbound_handler: ICMP Error - {} (type={}, code={})",
                            desc, icmp_type, icmp_code
                        );
                    }
                }
            }

            // Check if we need to do NAT (rewrite destination IP)
            let needs_nat = tunnel_ip.is_some() && internet_ip.is_some()
                && Some(dst_ip) == tunnel_ip;

            // Make a mutable copy for NAT rewriting
            let mut packet = ip_packet.to_vec();

            if needs_nat {
                let new_dst = internet_ip.unwrap();
                // Rewrite destination IP (bytes 16-19)
                packet[16] = new_dst.octets()[0];
                packet[17] = new_dst.octets()[1];
                packet[18] = new_dst.octets()[2];
                packet[19] = new_dst.octets()[3];

                // Recalculate IP header checksum
                // Clear existing checksum
                packet[10] = 0;
                packet[11] = 0;
                // Calculate new checksum
                let ihl = ((packet[0] & 0x0F) as usize) * 4;
                let checksum = calculate_ip_checksum(&packet[..ihl]);
                packet[10] = (checksum >> 8) as u8;
                packet[11] = (checksum & 0xFF) as u8;

                // Update TCP/UDP checksum (pseudo-header includes destination IP)
                let transport_offset = ihl;
                if protocol == 6 && packet.len() >= transport_offset + 18 {
                    // TCP: checksum at offset 16 within TCP header
                    update_transport_checksum(
                        &mut packet,
                        transport_offset + 16,
                        &dst_ip.octets(),
                        &new_dst.octets(),
                    );
                } else if protocol == 17 && packet.len() >= transport_offset + 8 {
                    // UDP: checksum at offset 6 within UDP header
                    let udp_checksum = u16::from_be_bytes([
                        packet[transport_offset + 6],
                        packet[transport_offset + 7],
                    ]);
                    if udp_checksum != 0 {
                        update_transport_checksum(
                            &mut packet,
                            transport_offset + 6,
                            &dst_ip.octets(),
                            &new_dst.octets(),
                        );
                    }
                }
            }

            // Create Ethernet frame with IP packet payload
            // Use physical adapter's MAC as destination (packet is being "received" by this adapter)
            // Use a dummy but valid-looking source MAC (simulating upstream router)
            const MAX_ETHER_FRAME: usize = 1522; // Max Ethernet frame size with VLAN tag
            let frame_len = 14 + packet.len();

            // Safety check: Don't process oversized packets that would overflow IntermediateBuffer
            if frame_len > MAX_ETHER_FRAME {
                log::warn!("inbound_handler: packet too large ({} bytes), dropping", frame_len);
                return;
            }

            let mut ethernet_frame = vec![0u8; frame_len];
            ethernet_frame[0..6].copy_from_slice(&adapter_mac); // Destination = physical adapter
            ethernet_frame[6..12].copy_from_slice(&[0x02, 0x00, 0x00, 0x00, 0x00, 0x01]); // Locally administered src MAC
            ethernet_frame[12] = 0x08; // EtherType: IPv4
            ethernet_frame[13] = 0x00;
            ethernet_frame[14..].copy_from_slice(&packet);

            // Create IntermediateBuffer
            let mut buffer = IntermediateBuffer::default();
            buffer.device_flags = DirectionFlags::PACKET_FLAG_ON_RECEIVE;
            buffer.length = ethernet_frame.len() as u32;
            buffer.buffer.0[..ethernet_frame.len()].copy_from_slice(&ethernet_frame);

            // Open driver and get adapter handle (must be done per-call since HANDLE isn't Send)
            let driver = match ndisapi::Ndisapi::new("NDISRD") {
                Ok(d) => d,
                Err(e) => {
                    log::warn!("inbound_handler: failed to open driver: {}", e);
                    return;
                }
            };

            let adapters = match driver.get_tcpip_bound_adapters_info() {
                Ok(a) => a,
                Err(e) => {
                    log::warn!("inbound_handler: failed to get adapters: {}", e);
                    return;
                }
            };

            let adapter = match adapters.iter().find(|a| a.get_name() == &physical_name) {
                Some(a) => a,
                None => {
                    log::warn!("inbound_handler: adapter not found");
                    return;
                }
            };

            let adapter_handle = adapter.get_handle();

            // Inject to MSTCP
            let mut to_mstcp: EthMRequest<1> = EthMRequest::new(adapter_handle);
            if to_mstcp.push(&buffer).is_ok() {
                if let Err(e) = driver.send_packets_to_mstcp::<1>(&to_mstcp) {
                    log::warn!("inbound_handler: send_packets_to_mstcp failed: {:?}", e);
                } else {
                    throughput_stats.add_rx(packet.len() as u64);

                    let count = packet_count.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                    // Log first 5 packets and then every 100th
                    if count < 5 || count % 100 == 0 {
                        log::info!(
                            "inbound_handler: injected {} byte packet #{} (proto={}, {} -> {}{})",
                            packet.len(), count + 1, protocol, src_ip, dst_ip,
                            if needs_nat { format!(" [NAT -> {}]", internet_ip.unwrap()) } else { String::new() }
                        );
                    }
                }
            }
        }))
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
        let _ = SetThreadAffinityMask(
            windows::Win32::System::Threading::GetCurrentThread(),
            mask,
        );
    }
}

/// Configuration for inbound packet injection
#[derive(Clone)]
struct InboundConfig {
    physical_adapter_name: String,
    adapter_mac: [u8; 6],
    tunnel_ip: Option<std::net::Ipv4Addr>,
    internet_ip: Option<std::net::Ipv4Addr>,
}

/// Inbound receiver thread - reads encrypted packets from VpnEncryptContext socket,
/// decrypts them, and injects to MSTCP (opens driver ONCE for performance)
fn run_inbound_receiver(
    ctx: VpnEncryptContext,
    config: InboundConfig,
    stop_flag: Arc<AtomicBool>,
    throughput: ThroughputStats,
) {
    log::info!("Inbound receiver started (optimized - single driver handle, with keepalives)");

    // Open driver ONCE at thread start (not per-packet!)
    let driver = match ndisapi::Ndisapi::new("NDISRD") {
        Ok(d) => d,
        Err(e) => {
            log::error!("Inbound receiver: failed to open driver: {}", e);
            return;
        }
    };

    let adapters = match driver.get_tcpip_bound_adapters_info() {
        Ok(a) => a,
        Err(e) => {
            log::error!("Inbound receiver: failed to get adapters: {}", e);
            return;
        }
    };

    let adapter = match adapters.iter().find(|a| a.get_name() == &config.physical_adapter_name) {
        Some(a) => a,
        None => {
            log::error!("Inbound receiver: physical adapter '{}' not found", config.physical_adapter_name);
            return;
        }
    };

    let adapter_handle = adapter.get_handle();
    log::info!("Inbound receiver: using adapter '{}' for MSTCP injection", config.physical_adapter_name);

    let mut recv_buf = vec![0u8; 2048]; // Max WireGuard packet size
    let mut decrypt_buf = vec![0u8; 2048];
    let mut timer_buf = vec![0u8; 256]; // For keepalive packets
    let mut packets_received = 0u64;
    let mut packets_decrypted = 0u64;
    let mut packets_injected = 0u64;
    let mut inject_errors = 0u64;
    let mut keepalives_sent = 0u64;

    // For keepalive timer - call update_timers() every 100ms
    // This is critical because tunnel's keepalive task is disabled when split tunnel is active
    // to avoid endpoint confusion. We must send keepalives from THIS socket.
    let mut last_timer_check = std::time::Instant::now();
    const TIMER_INTERVAL_MS: u64 = 100;

    loop {
        if stop_flag.load(Ordering::Relaxed) {
            break;
        }

        // Check if we need to call update_timers() for keepalives
        // CRITICAL: This keeps the WireGuard session alive and sends keepalives
        // from the correct socket (VpnEncryptContext.socket, not tunnel.socket)
        let now = std::time::Instant::now();
        if now.duration_since(last_timer_check).as_millis() >= TIMER_INTERVAL_MS as u128 {
            last_timer_check = now;

            let timer_result = {
                let mut tunn = ctx.tunn.lock();
                tunn.update_timers(&mut timer_buf)
            };

            match timer_result {
                TunnResult::WriteToNetwork(data) => {
                    // Send keepalive from this socket (the correct one!)
                    match ctx.socket.send(data) {
                        Ok(sent) => {
                            keepalives_sent += 1;
                            // Log first 5 and then every 50th
                            if keepalives_sent <= 5 || keepalives_sent % 50 == 0 {
                                log::info!(
                                    "Inbound receiver: sent keepalive #{} ({} bytes, {} sent)",
                                    keepalives_sent, data.len(), sent
                                );
                            }
                        }
                        Err(e) => {
                            log::warn!("Inbound receiver: failed to send keepalive: {} (kind={:?})", e, e.kind());
                        }
                    }
                }
                TunnResult::Err(e) => {
                    log::warn!("Inbound receiver: timer error: {:?}", e);
                }
                TunnResult::Done => {
                    // No keepalive needed this tick - this is normal
                }
                other => {
                    // Unexpected result type
                    log::warn!("Inbound receiver: unexpected timer result: {:?}",
                        match other {
                            TunnResult::WriteToTunnelV4(_, _) => "WriteToTunnelV4",
                            TunnResult::WriteToTunnelV6(_, _) => "WriteToTunnelV6",
                            _ => "Unknown",
                        }
                    );
                }
            }
        }

        // Read encrypted packet from socket (with timeout for clean shutdown)
        let n = match ctx.socket.recv(&mut recv_buf) {
            Ok(n) => n,
            Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                continue;
            }
            Err(ref e) if e.kind() == std::io::ErrorKind::TimedOut => {
                continue;
            }
            Err(e) => {
                log::warn!("Inbound receiver recv error: {}", e);
                std::thread::sleep(std::time::Duration::from_millis(2));
                continue;
            }
        };

        if n == 0 {
            continue;
        }

        packets_received += 1;

        // Log first 20 received packets to help debug (DEBUG level)
        if packets_received <= 20 {
            log::debug!("Inbound receiver: recv #{} - {} bytes from VPN server", packets_received, n);
        }

        // Decrypt the packet
        let result = {
            let mut tunn = ctx.tunn.lock();
            tunn.decapsulate(None, &recv_buf[..n], &mut decrypt_buf)
        };

        match result {
            TunnResult::WriteToTunnelV4(data, _) | TunnResult::WriteToTunnelV6(data, _) => {
                packets_decrypted += 1;
                throughput.add_rx(data.len() as u64);

                // Log decrypted packet details for first 20 (DEBUG level)
                if packets_decrypted <= 20 && data.len() >= 20 {
                    let proto = data[9];
                    let src_ip = std::net::Ipv4Addr::new(data[12], data[13], data[14], data[15]);
                    let dst_ip = std::net::Ipv4Addr::new(data[16], data[17], data[18], data[19]);
                    log::debug!(
                        "Inbound receiver: decrypted #{} - {} bytes, proto={}, {} -> {}",
                        packets_decrypted, data.len(), proto, src_ip, dst_ip
                    );
                }

                // Do NAT and inject to MSTCP
                if let Some(injected) = inject_inbound_packet(
                    data,
                    &config,
                    adapter_handle,
                    &driver,
                    packets_injected,
                ) {
                    if injected {
                        packets_injected += 1;
                    } else {
                        inject_errors += 1;
                    }
                }
            }
            TunnResult::WriteToNetwork(data) => {
                // Protocol message (handshake, etc.) - send back to VPN server
                log::debug!("Inbound receiver: got WriteToNetwork - {} bytes (handshake/protocol)", data.len());
                if let Err(e) = ctx.socket.send(data) {
                    log::warn!("Inbound receiver: failed to send protocol message: {}", e);
                }
            }
            TunnResult::Done => {
                // No plaintext output (e.g., keepalive received)
                if packets_received <= 20 {
                    log::debug!("Inbound receiver: recv #{} -> Done (keepalive?)", packets_received);
                }
            }
            TunnResult::Err(e) => {
                // Log ALL decrypt errors (not just first 20) since this is critical for debugging
                log::warn!(
                    "Inbound receiver: decrypt ERROR on packet #{} ({} bytes): {:?}",
                    packets_received, n, e
                );
            }
        }

        // Periodic logging (every 100 packets for debugging) - DEBUG level
        if packets_received > 0 && packets_received % 100 == 0 {
            log::debug!(
                "Inbound receiver: {} recv, {} decrypt, {} inject, {} errors",
                packets_received, packets_decrypted, packets_injected, inject_errors
            );
        }
    }

    // Final stats
    log::info!(
        "Inbound receiver stopped - FINAL: {} recv, {} decrypt, {} inject, {} errors, {} keepalives, {} bytes RX",
        packets_received, packets_decrypted, packets_injected, inject_errors, keepalives_sent,
        throughput.bytes_rx.load(Ordering::Relaxed)
    );
}

/// Inject a decrypted inbound packet to MSTCP after NAT rewriting
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
        log::warn!("inject_inbound_packet: packet too small ({} bytes)", ip_packet.len());
        return None;
    }

    // Parse IP header
    let src_ip = std::net::Ipv4Addr::new(
        ip_packet[12], ip_packet[13], ip_packet[14], ip_packet[15]
    );
    let dst_ip = std::net::Ipv4Addr::new(
        ip_packet[16], ip_packet[17], ip_packet[18], ip_packet[19]
    );
    let protocol = ip_packet[9];

    // Log every packet for debugging (first 10) - DEBUG level
    if packet_count < 10 {
        log::debug!(
            "inject_inbound_packet #{}: {} -> {}, proto={}, {} bytes, config.tunnel_ip={:?}, config.internet_ip={:?}",
            packet_count, src_ip, dst_ip, protocol, ip_packet.len(),
            config.tunnel_ip, config.internet_ip
        );
    }

    // Check if we need to do NAT (rewrite destination IP from tunnel_ip to internet_ip)
    let needs_nat = config.tunnel_ip.is_some() && config.internet_ip.is_some()
        && Some(dst_ip) == config.tunnel_ip;

    // Log NAT decision for debugging (first 10 packets) - DEBUG level
    if packet_count < 10 {
        log::debug!(
            "inject_inbound_packet #{}: needs_nat={} (dst={}, tunnel_ip={:?})",
            packet_count, needs_nat, dst_ip, config.tunnel_ip
        );
    }

    // Make a mutable copy for NAT rewriting
    let mut packet = ip_packet.to_vec();

    if needs_nat {
        let new_dst = config.internet_ip.unwrap();

        // Log NAT rewrites (first 10) - DEBUG level
        if packet_count < 10 {
            log::debug!(
                "Inbound NAT #{}: {} -> {}, proto={}, {} bytes",
                packet_count, dst_ip, new_dst, protocol, packet.len()
            );
        }

        // Rewrite destination IP (bytes 16-19)
        packet[16] = new_dst.octets()[0];
        packet[17] = new_dst.octets()[1];
        packet[18] = new_dst.octets()[2];
        packet[19] = new_dst.octets()[3];

        // Recalculate IP header checksum
        packet[10] = 0;
        packet[11] = 0;
        let ihl = ((packet[0] & 0x0F) as usize) * 4;
        let checksum = calculate_ip_checksum(&packet[..ihl]);
        packet[10] = (checksum >> 8) as u8;
        packet[11] = (checksum & 0xFF) as u8;

        // Update TCP/UDP checksum
        let transport_offset = ihl;
        if protocol == 6 && packet.len() >= transport_offset + 18 {
            // TCP: checksum at offset 16 within TCP header
            update_transport_checksum(
                &mut packet,
                transport_offset + 16,
                &dst_ip.octets(),
                &new_dst.octets(),
            );
        } else if protocol == 17 && packet.len() >= transport_offset + 8 {
            // UDP: checksum at offset 6 within UDP header
            let udp_checksum = u16::from_be_bytes([
                packet[transport_offset + 6],
                packet[transport_offset + 7],
            ]);
            if udp_checksum != 0 {
                update_transport_checksum(
                    &mut packet,
                    transport_offset + 6,
                    &dst_ip.octets(),
                    &new_dst.octets(),
                );
            }
        }
    }

    // Create Ethernet frame
    const MAX_ETHER_FRAME: usize = 1522;
    let frame_len = 14 + packet.len();

    if frame_len > MAX_ETHER_FRAME {
        log::warn!("Inbound: packet too large ({} bytes), dropping", frame_len);
        return None;
    }

    let mut ethernet_frame = vec![0u8; frame_len];
    ethernet_frame[0..6].copy_from_slice(&config.adapter_mac); // Destination = physical adapter
    ethernet_frame[6..12].copy_from_slice(&[0x02, 0x00, 0x00, 0x00, 0x00, 0x01]); // Locally administered src MAC
    ethernet_frame[12] = 0x08; // EtherType: IPv4
    ethernet_frame[13] = 0x00;
    ethernet_frame[14..].copy_from_slice(&packet);

    // Create IntermediateBuffer and inject
    let mut buffer = IntermediateBuffer::default();
    buffer.device_flags = DirectionFlags::PACKET_FLAG_ON_RECEIVE;
    buffer.length = ethernet_frame.len() as u32;
    buffer.buffer.0[..ethernet_frame.len()].copy_from_slice(&ethernet_frame);

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

    // Create event for packet notification
    let event: HANDLE = unsafe {
        CreateEventW(None, true, false, None)
            .map_err(|e| VpnError::SplitTunnel(format!("Failed to create event: {}", e)))?
    };

    driver
        .set_packet_event(physical_handle, event)
        .map_err(|e| VpnError::SplitTunnel(format!("Failed to set packet event: {}", e)))?;

    // Set adapter to tunnel mode
    driver
        .set_adapter_mode(
            physical_handle,
            FilterFlags::MSTCP_FLAG_SENT_RECEIVE_TUNNEL,
        )
        .map_err(|e| VpnError::SplitTunnel(format!("Failed to set adapter mode: {}", e)))?;

    let mut packets: Vec<IntermediateBuffer> = vec![Default::default(); BATCH_SIZE];
    let mut passthrough_to_adapter: EthMRequest<BATCH_SIZE>;
    let mut passthrough_to_mstcp: EthMRequest<BATCH_SIZE>;

    loop {
        if stop_flag.load(Ordering::Relaxed) {
            break;
        }

        // Wait with very short timeout (1ms) for low latency
        unsafe {
            WaitForSingleObject(event, 1);
        }

        // Read batch of packets
        let mut to_read =
            EthMRequestMut::from_iter(physical_handle, packets.iter_mut());

        let packets_read = driver
            .read_packets::<BATCH_SIZE>(&mut to_read)
            .unwrap_or(0);

        if packets_read == 0 {
            unsafe {
                let _ = ResetEvent(event);
            }
            continue;
        }

        // Prepare passthrough queues
        passthrough_to_adapter = EthMRequest::new(physical_handle);
        passthrough_to_mstcp = EthMRequest::new(physical_handle);

        // Dispatch packets to workers based on hash of source port
        for i in 0..packets_read {
            let direction_flags = packets[i].get_device_flags();
            let is_outbound = direction_flags == DirectionFlags::PACKET_FLAG_ON_SEND;
            let data = packets[i].get_data();

            if is_outbound {
                // Parse to get source port for hashing
                if let Some((src_port, _)) = parse_ports(data) {
                    // Hash by source port to select worker
                    let worker_id = (src_port as usize) % num_workers;

                    // Try to send to worker (non-blocking)
                    // Use ArrayVec for stack allocation - avoids heap alloc per packet
                    let mut packet_data: ArrayVec<u8, MAX_PACKET_SIZE> = ArrayVec::new();
                    // Truncate if packet is larger than our buffer (shouldn't happen with MTU 1500)
                    let copy_len = data.len().min(MAX_PACKET_SIZE);
                    packet_data.try_extend_from_slice(&data[..copy_len]).ok();

                    let work = PacketWork {
                        data: packet_data,
                        is_outbound: true,
                        physical_adapter_name: Arc::clone(&physical_name),
                    };

                    // If worker queue is full, send as passthrough
                    if senders[worker_id].try_send(work).is_err() {
                        let _ = passthrough_to_adapter.push(&packets[i]);
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
    process_cache: Arc<LockFreeProcessCache>,
    wintun_session: Option<Arc<wintun::Session>>,
    stats: Arc<WorkerStats>,
    throughput: ThroughputStats,
    stop_flag: Arc<AtomicBool>,
    tunnel_ip: Option<std::net::Ipv4Addr>,
    internet_ip: Option<std::net::Ipv4Addr>,
    vpn_encrypt_ctx: Option<VpnEncryptContext>,
    detected_game_servers: Arc<parking_lot::RwLock<std::collections::HashSet<std::net::Ipv4Addr>>>,
) {
    log::info!("Worker {} started", worker_id);

    // Get initial snapshot
    let mut snapshot = process_cache.get_snapshot();
    let mut snapshot_version = snapshot.version;
    let mut snapshot_check_counter = 0u32;

    // Per-worker inline cache for connection lookups
    // This caches inline_connection_lookup results to avoid repeated syscalls
    // First packet of new connection: ~500μs, subsequent packets: <1μs
    let mut inline_cache: InlineCache = std::collections::HashMap::with_capacity(1024);

    // Diagnostic logging
    let mut diagnostic_counter = 0u64;
    let mut wintun_inject_success = 0u64;
    let mut wintun_inject_fail = 0u64;
    let mut no_wintun_session = 0u64;

    // Performance timing (v0.5.57 - measure hot path latency)
    let mut total_lookup_ns = 0u64;
    let mut total_encrypt_ns = 0u64;
    let mut lookup_count = 0u64;
    let mut encrypt_count = 0u64;

    // Log initial tunnel apps
    if worker_id == 0 {
        log::info!(
            "Worker 0: Initial tunnel_apps = {:?}",
            snapshot.tunnel_apps.iter().collect::<Vec<_>>()
        );
    }

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

    // Log VPN encryption context availability
    if vpn_encrypt_ctx.is_some() {
        log::info!("Worker {}: VPN encryption context AVAILABLE - direct encryption enabled", worker_id);
    } else if wintun_session.is_some() {
        log::info!("Worker {}: Wintun session AVAILABLE - tunnel routing enabled (fallback mode)", worker_id);
    } else {
        log::warn!("Worker {}: NO VPN context - tunnel packets will be bypassed!", worker_id);
    }

    // Track direct encryption stats
    let mut direct_encrypt_success = 0u64;
    let mut direct_encrypt_fail = 0u64;

    loop {
        if stop_flag.load(Ordering::Relaxed) {
            break;
        }

        // Receive packet with timeout (1ms for low latency)
        let work = match receiver.recv_timeout(std::time::Duration::from_millis(1)) {
            Ok(w) => w,
            Err(crossbeam_channel::RecvTimeoutError::Timeout) => continue,
            Err(crossbeam_channel::RecvTimeoutError::Disconnected) => break,
        };

        // Periodically refresh snapshot (every 10 packets for faster detection)
        // Reduced from 100 to catch newly registered processes quicker
        snapshot_check_counter += 1;
        if snapshot_check_counter >= 10 {
            snapshot_check_counter = 0;
            let old_apps_count = snapshot.tunnel_apps.len();
            let new_snapshot = process_cache.get_snapshot();

            // Clear inline cache if snapshot version changed (connections may have changed)
            if new_snapshot.version != snapshot_version {
                snapshot_version = new_snapshot.version;
                inline_cache.clear();
            }

            snapshot = new_snapshot;

            // Log if tunnel apps changed (only worker 0)
            if worker_id == 0 && snapshot.tunnel_apps.len() != old_apps_count {
                log::info!(
                    "Worker 0: tunnel_apps updated, now {} apps",
                    snapshot.tunnel_apps.len()
                );
            }
        }

        // Process packet
        stats.packets_processed.fetch_add(1, Ordering::Relaxed);
        let packet_len = work.data.len() as u64;
        diagnostic_counter += 1;

        if work.is_outbound {
            // Check if should tunnel (timed for performance measurement)
            // Uses hybrid approach: snapshot cache (fast) + per-worker inline cache (for misses)
            let lookup_start = std::time::Instant::now();
            let should_tunnel = should_route_to_vpn_with_inline_cache(&work.data, &snapshot, &mut inline_cache);
            total_lookup_ns += lookup_start.elapsed().as_nanos() as u64;
            lookup_count += 1;

            // Periodic diagnostic logging (every 500 packets on worker 0)
            if worker_id == 0 && diagnostic_counter % 500 == 0 {
                let tunneled = stats.packets_tunneled.load(Ordering::Relaxed);
                let bypassed = stats.packets_bypassed.load(Ordering::Relaxed);
                let total = tunneled + bypassed;
                let tunnel_pct = if total > 0 { (tunneled as f64 / total as f64) * 100.0 } else { 0.0 };

                // Calculate average latencies
                let avg_lookup_ns = if lookup_count > 0 { total_lookup_ns / lookup_count } else { 0 };
                let avg_encrypt_ns = if encrypt_count > 0 { total_encrypt_ns / encrypt_count } else { 0 };

                log::info!(
                    "Worker 0 PERF: lookup={:.1}μs encrypt={:.1}μs | {} tunneled, {} bypassed ({:.1}%), direct: {}/{}, Wintun: {}/{}/{}",
                    avg_lookup_ns as f64 / 1000.0,
                    avg_encrypt_ns as f64 / 1000.0,
                    tunneled, bypassed, tunnel_pct,
                    direct_encrypt_success, direct_encrypt_fail,
                    wintun_inject_success, wintun_inject_fail, no_wintun_session
                );
            }

            if should_tunnel {
                stats.packets_tunneled.fetch_add(1, Ordering::Relaxed);
                stats.bytes_tunneled.fetch_add(packet_len, Ordering::Relaxed);
                throughput.add_tx(packet_len);

                // Extract IP packet from Ethernet frame
                if work.data.len() <= 14 {
                    continue;
                }
                let ip_packet = &work.data[14..];

                // === GAME SERVER DETECTION (Bloxstrap-style) ===
                // Track Roblox game server IPs for notifications
                if ip_packet.len() >= 20 {
                    let dst_ip = Ipv4Addr::new(
                        ip_packet[16], ip_packet[17], ip_packet[18], ip_packet[19]
                    );
                    if is_roblox_game_server_ip(dst_ip) {
                        // Record game server (lock-free write, deduplicates via HashSet)
                        let mut servers = detected_game_servers.write();
                        if servers.insert(dst_ip) {
                            log::info!("Game server detected: {} (tunneled by SwiftTunnel)", dst_ip);
                        }
                    }
                }

                // === ZERO-ALLOCATION NAT REWRITING ===
                // Use thread-local buffer instead of heap allocation for NAT
                // This eliminates ~200-500ns per packet from malloc/free overhead
                let (packet_to_send_ptr, packet_to_send_len): (*const u8, usize) = if ip_packet.len() >= 20 {
                    let src_ip = std::net::Ipv4Addr::new(
                        ip_packet[12], ip_packet[13], ip_packet[14], ip_packet[15]
                    );

                    // Check if we need source NAT
                    if tunnel_ip.is_some() && internet_ip.is_some() && Some(src_ip) == internet_ip {
                        let new_src = tunnel_ip.unwrap();

                        // Use thread-local NAT buffer (zero allocation!)
                        NAT_BUFFER.with(|buf| {
                            let mut nat_buf = buf.borrow_mut();
                            let pkt_len = ip_packet.len().min(MAX_PACKET_SIZE);
                            nat_buf[..pkt_len].copy_from_slice(&ip_packet[..pkt_len]);

                            // Rewrite source IP (bytes 12-15)
                            nat_buf[12] = new_src.octets()[0];
                            nat_buf[13] = new_src.octets()[1];
                            nat_buf[14] = new_src.octets()[2];
                            nat_buf[15] = new_src.octets()[3];

                            // CHECKSUM OFFLOAD FIX: Recalculate all checksums from scratch
                            // This handles both:
                            // 1. IP checksum update after NAT rewrite
                            // 2. TCP/UDP checksums that may be placeholders (0x0000) from hardware offload
                            fix_packet_checksums(&mut nat_buf[..pkt_len]);

                            // Log first few NAT operations
                            let protocol = nat_buf[9];
                            if direct_encrypt_success + wintun_inject_success < 5 {
                                log::info!(
                                    "Worker {}: Source NAT {} -> {}, {} bytes, proto={}",
                                    worker_id, src_ip, new_src, pkt_len, protocol
                                );
                            }

                            // Return pointer and length (buffer is valid for this scope)
                            (nat_buf.as_ptr(), pkt_len)
                        })
                    } else {
                        // CHECKSUM OFFLOAD FIX: Always recalculate checksums for tunneled packets
                        // Modern NICs use hardware checksum offload - we intercept packets BEFORE
                        // the NIC computes checksums, so they have placeholder values (0x0000)
                        NAT_BUFFER.with(|buf| {
                            let mut fix_buf = buf.borrow_mut();
                            let pkt_len = ip_packet.len().min(MAX_PACKET_SIZE);
                            fix_buf[..pkt_len].copy_from_slice(&ip_packet[..pkt_len]);

                            fix_packet_checksums(&mut fix_buf[..pkt_len]);

                            (fix_buf.as_ptr(), pkt_len)
                        })
                    }
                } else {
                    (ip_packet.as_ptr(), ip_packet.len())
                };

                // SAFETY: The pointer is either from ip_packet (still in scope) or
                // from NAT_BUFFER (thread-local, valid for duration of this function)
                let packet_to_send = unsafe { std::slice::from_raw_parts(packet_to_send_ptr, packet_to_send_len) };

                // === ZERO-ALLOCATION ENCRYPTION ===
                // Use thread-local buffer instead of heap allocation
                // All work (encrypt + send) must happen inside the thread-local scope
                if let Some(ref ctx) = vpn_encrypt_ctx {
                    // Encrypt and send within thread-local scope (zero allocation!)
                    let encrypt_start = std::time::Instant::now();
                    let (success, encrypted_len) = ENCRYPT_BUFFER.with(|buf| {
                        let mut encrypt_buf = buf.borrow_mut();
                        let result = {
                            let mut tunn = ctx.tunn.lock();
                            tunn.encapsulate(packet_to_send, &mut encrypt_buf[..])
                        };

                        match result {
                            TunnResult::WriteToNetwork(data) => {
                                // Send encrypted packet directly via UDP
                                // CRITICAL: Use send() not send_to() because socket is connected
                                match ctx.socket.send(data) {
                                    Ok(_) => (true, data.len()),
                                    Err(_) => (false, 0),
                                }
                            }
                            TunnResult::Done => {
                                // Packet was queued internally (handshake in progress)
                                (true, 0)
                            }
                            TunnResult::Err(_) | _ => {
                                (false, 0)
                            }
                        }
                    });
                    total_encrypt_ns += encrypt_start.elapsed().as_nanos() as u64;
                    encrypt_count += 1;

                    if success {
                        direct_encrypt_success += 1;
                        if direct_encrypt_success <= 5 && encrypted_len > 0 {
                            log::info!(
                                "Worker {}: Direct encrypt OK - {} bytes -> {} bytes",
                                worker_id, packet_to_send_len, encrypted_len
                            );
                        }
                    } else {
                        direct_encrypt_fail += 1;
                        if direct_encrypt_fail <= 10 {
                            log::warn!("Worker {}: Encrypt/send failed", worker_id);
                        }
                    }
                }
                // FALLBACK: Wintun injection (if no encryption context)
                else if let Some(ref session) = wintun_session {
                    match session.allocate_send_packet(packet_to_send.len() as u16) {
                        Ok(mut packet) => {
                            packet.bytes_mut().copy_from_slice(packet_to_send);
                            session.send_packet(packet);
                            wintun_inject_success += 1;
                        }
                        Err(_) => {
                            wintun_inject_fail += 1;
                            // Wintun allocation failed - forward to adapter as fallback
                            send_bypass_packet(&driver, &adapters, &work);
                        }
                    }
                } else {
                    no_wintun_session += 1;
                    // No VPN context at all - forward to adapter (bypass)
                    send_bypass_packet(&driver, &adapters, &work);
                }
            } else {
                stats.packets_bypassed.fetch_add(1, Ordering::Relaxed);
                stats.bytes_bypassed.fetch_add(packet_len, Ordering::Relaxed);

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
    let adapter = match adapters.iter().find(|a| a.get_name() == work.physical_adapter_name.as_str()) {
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
        log::warn!("send_bypass_packet: packet too large ({} bytes), dropping", work.data.len());
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
fn run_cache_refresher(cache: Arc<LockFreeProcessCache>, stop_flag: Arc<AtomicBool>) {
    use sysinfo::{ProcessRefreshKind, ProcessesToUpdate, System, UpdateKind};
    use windows::Win32::NetworkManagement::IpHelper::*;

    log::info!("Cache refresher started (2ms refresh interval, WireSock-style)");

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

    loop {
        if stop_flag.load(Ordering::Relaxed) {
            break;
        }

        // On first run, don't sleep - immediately refresh to populate cache
        if first_run {
            first_run = false;
            log::info!("Cache refresher: Performing initial refresh immediately");
        } else {
            // WireSock-style: Ultra-fast 2ms refresh for instant game detection
            // Critical: Without inline lookup fallback, cache must be very fresh
            // to catch new connections before packets bypass
            std::thread::sleep(std::time::Duration::from_millis(2));
        }

        // Collect connections
        let mut connections: HashMap<ConnectionKey, u32> = HashMap::with_capacity(1024);
        let mut pid_names: HashMap<u32, String> = HashMap::with_capacity(256);

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
                    let table = &*(buffer.as_ptr() as *const MIB_TCPTABLE_OWNER_PID);
                    let entries = std::slice::from_raw_parts(
                        table.table.as_ptr(),
                        table.dwNumEntries as usize,
                    );

                    for entry in entries {
                        let local_ip = Ipv4Addr::from(entry.dwLocalAddr.to_ne_bytes());
                        let local_port = u16::from_be(entry.dwLocalPort as u16);
                        let key = ConnectionKey::new(local_ip, local_port, Protocol::Tcp);
                        connections.insert(key, entry.dwOwningPid);
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
                    let table = &*(buffer.as_ptr() as *const MIB_UDPTABLE_OWNER_PID);
                    let entries = std::slice::from_raw_parts(
                        table.table.as_ptr(),
                        table.dwNumEntries as usize,
                    );

                    for entry in entries {
                        let local_ip = Ipv4Addr::from(entry.dwLocalAddr.to_ne_bytes());
                        let local_port = u16::from_be(entry.dwLocalPort as u16);
                        let key = ConnectionKey::new(local_ip, local_port, Protocol::Udp);
                        connections.insert(key, entry.dwOwningPid);
                    }
                }
            }
        }

        // Refresh process names
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

        // Also scan for tunnel apps
        let tunnel_apps = cache.tunnel_apps();
        let mut tunnel_pids_found: Vec<(u32, String)> = Vec::new();

        for (_pid, process) in system.processes() {
            let name = process.name().to_string_lossy().to_lowercase();
            for app in tunnel_apps {
                if name.contains(app.trim_end_matches(".exe")) {
                    let pid_u32 = _pid.as_u32();
                    pid_names.insert(pid_u32, process.name().to_string_lossy().to_string());
                    tunnel_pids_found.push((pid_u32, process.name().to_string_lossy().to_string()));

                    // Log the exact PID for debugging
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

        // Also log connections owned by tunnel apps
        if refresh_count < 10 && !tunnel_pids_found.is_empty() {
            for ((key, &pid), (tunnel_pid, _name)) in connections.iter().flat_map(|c| {
                tunnel_pids_found.iter().filter_map(move |tp| {
                    if *c.1 == tp.0 { Some((c, tp)) } else { None }
                })
            }) {
                log::info!(
                    "Cache refresher: Tunnel app connection {}:{} ({:?}) owned by PID {}",
                    key.local_ip, key.local_port, key.protocol, pid
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
                .filter(|(_, &pid)| tunnel_pids_found.iter().any(|(tp, _)| *tp == pid))
                .collect();

            if !tunnel_pids_found.is_empty() || tunnel_connections.len() > 0 {
                log::debug!(
                    "Cache #{}: {} tunnel PIDs found: {:?}, {} tunnel connections",
                    refresh_count,
                    tunnel_pids_found.len(),
                    tunnel_pids_found.iter().map(|(_, n)| n.as_str()).collect::<Vec<_>>(),
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

/// Check if packet should be routed to VPN (legacy, for reference)
///
/// NOTE: This is now replaced by should_route_to_vpn_with_inline_cache
/// which adds per-worker caching for inline lookups.
#[allow(dead_code)]
fn should_route_to_vpn(data: &[u8], snapshot: &ProcessSnapshot) -> bool {
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

    // Parse transport header
    let transport_start = ip_start + ihl;
    if data.len() < transport_start + 4 {
        return false;
    }

    let src_port = u16::from_be_bytes([data[transport_start], data[transport_start + 1]]);

    // WireSock-style: Trust the cache completely (O(1) hash lookup, <1μs)
    // No expensive inline_connection_lookup (~500μs syscall eliminated!)
    // First few packets of new connections may bypass (max 2ms until cache refresh)
    // This is the same approach WireSock uses for high-performance split tunneling
    snapshot.should_tunnel(src_ip, src_port, protocol)
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
    // Use V2 routing if enabled (checks destination IP + protocol)
    if snapshot.should_tunnel_v2(src_ip, src_port, protocol, dst_ip, dst_port) {
        SNAPSHOT_HITS.with(|c| c.set(c.get() + 1));
        return true;
    }

    // Phase 2: Check per-worker inline cache (fast path, O(1))
    // Cache stores: is this source connection from a tunnel app? (process check only)
    let cache_key = (src_ip, src_port, protocol);
    if let Some(&is_tunnel_app) = inline_cache.get(&cache_key) {
        INLINE_HITS.with(|c| c.set(c.get() + 1));
        // For V2: also check destination is game server
        // For V1: is_tunnel_app is the final result
        if !is_tunnel_app {
            // SPECULATIVE TUNNELING: Even if cache says "not tunnel app", still check
            // if destination is a game server. This handles the race condition where
            // PID lookup failed due to UDP table latency but destination is known.
            return match snapshot.routing_mode {
                crate::settings::RoutingMode::V1 => false, // V1 doesn't use destination filtering
                crate::settings::RoutingMode::V2 => {
                    // Speculatively tunnel to known game server IPs
                    super::process_cache::is_game_server(dst_ip, dst_port, protocol)
                }
            };
        }
        return match snapshot.routing_mode {
            crate::settings::RoutingMode::V1 => true,
            crate::settings::RoutingMode::V2 => {
                super::process_cache::is_game_server(dst_ip, dst_port, protocol)
            }
        };
    }

    // Phase 3: Inline lookup (slow path, ~500μs, but only once per connection)
    // This checks if the source process is a tunnel app
    SYSCALL_LOOKUPS.with(|c| c.set(c.get() + 1));
    let is_tunnel_app = inline_connection_lookup(src_ip, src_port, protocol, snapshot);

    // Cache the process check result for subsequent packets from this connection
    // Limit cache size to prevent unbounded growth
    if inline_cache.len() < 10000 {
        inline_cache.insert(cache_key, is_tunnel_app);
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
                    src_ip, src_port, dst_ip, dst_port
                );
            }
            true // Speculatively tunnel to game server
        } else {
            false
        }
    } else {
        match snapshot.routing_mode {
            crate::settings::RoutingMode::V1 => true,
            crate::settings::RoutingMode::V2 => {
                super::process_cache::is_game_server(dst_ip, dst_port, protocol)
            }
        }
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
                total, snapshot_h, inline_h, syscall_l,
                snapshot.tunnel_apps.len(), snapshot.connections.len()
            );
        }
    }

    // Log first 10 packets for debugging - DEBUG level
    if total < 10 {
        log::debug!(
            "Packet #{}: {}:{} {:?} -> result={} (tunnel_apps={:?})",
            total, src_ip, src_port, protocol, result,
            snapshot.tunnel_apps.iter().take(5).collect::<Vec<_>>()
        );
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

                let table = &*(buffer.as_ptr() as *const MIB_TCPTABLE_OWNER_PID);
                let rows = std::slice::from_raw_parts(
                    table.table.as_ptr(),
                    table.dwNumEntries as usize,
                );

                if debug_log {
                    log::debug!(
                        "inline_lookup #{}: searching TCP table ({} entries) for {}:{}",
                        lookup_num, rows.len(), src_ip, src_port
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
                                lookup_num, local_ip, local_port, row.dwOwningPid, is_tunnel
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
                                lookup_num, local_port, src_ip, src_port, row.dwOwningPid, is_tunnel
                            );
                        }
                        return is_tunnel;
                    }
                }

                if debug_log {
                    log::debug!(
                        "inline_lookup #{}: NOT FOUND in TCP table for {}:{}",
                        lookup_num, src_ip, src_port
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

                let table = &*(buffer.as_ptr() as *const MIB_UDPTABLE_OWNER_PID);
                let rows = std::slice::from_raw_parts(
                    table.table.as_ptr(),
                    table.dwNumEntries as usize,
                );

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
            lookup_num, found, tunneled,
            if lookup_num > 0 { (found as f64 / lookup_num as f64) * 100.0 } else { 0.0 }
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
    use windows::Win32::System::Threading::{OpenProcess, QueryFullProcessImageNameW, PROCESS_NAME_FORMAT, PROCESS_QUERY_LIMITED_INFORMATION};

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

            if QueryFullProcessImageNameW(h, PROCESS_NAME_FORMAT(0), windows::core::PWSTR(buffer.as_mut_ptr()), &mut size).is_ok() {
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

/// Update transport (TCP/UDP) checksum after NAT IP change
/// Uses incremental checksum update per RFC 1624:
/// HC' = ~(~HC + ~m + m')
/// Where HC is old checksum, m is old value, m' is new value
fn update_transport_checksum(
    packet: &mut [u8],
    checksum_offset: usize,
    old_ip: &[u8; 4],
    new_ip: &[u8; 4],
) {
    // Read old checksum
    let old_checksum = u16::from_be_bytes([
        packet[checksum_offset],
        packet[checksum_offset + 1],
    ]);

    // RFC 1624 formula: HC' = ~(~HC + ~m + m')
    // ~HC: one's complement of old checksum
    // ~m: one's complement of old IP (both 16-bit words)
    // m': new IP (both 16-bit words)
    let mut sum: u32 = (!old_checksum) as u32;

    // Add one's complement of old IP words (~m)
    let old_ip_hi = u16::from_be_bytes([old_ip[0], old_ip[1]]);
    let old_ip_lo = u16::from_be_bytes([old_ip[2], old_ip[3]]);
    sum += (!old_ip_hi) as u32;
    sum += (!old_ip_lo) as u32;

    // Add new IP words (m')
    let new_ip_hi = u16::from_be_bytes([new_ip[0], new_ip[1]]);
    let new_ip_lo = u16::from_be_bytes([new_ip[2], new_ip[3]]);
    sum += new_ip_hi as u32;
    sum += new_ip_lo as u32;

    // Fold 32-bit sum to 16 bits
    while sum > 0xFFFF {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }

    // One's complement of result
    let new_checksum = !(sum as u16);
    packet[checksum_offset] = (new_checksum >> 8) as u8;
    packet[checksum_offset + 1] = (new_checksum & 0xFF) as u8;
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

#[cfg(test)]
mod tests {
    use super::*;

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
}
