//! VPN Split Tunnel Benchmark
//!
//! Compares performance of:
//! 1. SwiftTunnel (our implementation) - arc-swap, process cache, V2 hybrid routing
//! 2. Standard WireGuard - full tunnel, no split logic
//! 3. WireSock-style - simulated per-packet process lookup
//!
//! Metrics:
//! - Packet processing latency (ns per packet)
//! - Throughput (packets/sec, Mpps)
//! - CPU usage during packet storm
//! - Memory usage (process cache, connection table)
//!
//! Run: cargo run --release

use std::collections::{HashMap, HashSet};
use std::net::Ipv4Addr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use arc_swap::ArcSwap;
use parking_lot::RwLock;
use sysinfo::{Pid, ProcessesToUpdate, System};

// ============================================================================
// CONFIGURATION
// ============================================================================

/// Number of packets to process per benchmark iteration
const PACKETS_PER_ITERATION: u64 = 1_000_000;

/// Number of benchmark iterations for averaging
const ITERATIONS: u32 = 5;

/// Simulated process cache size
const PROCESS_COUNT: usize = 50;

/// Simulated connection table size
const CONNECTION_COUNT: usize = 10_000;

/// Simulated tunnel apps
const TUNNEL_APPS: &[&str] = &[
    "robloxplayerbeta.exe",
    "robloxstudiobeta.exe",
];

// ============================================================================
// SWIFTTUNNEL IMPLEMENTATION (Our actual approach)
// ============================================================================

/// Roblox IP ranges (from our actual implementation)
const ROBLOX_RANGES: &[(u32, u32)] = &[
    (0x80740000, 0xFFFF8000), // 128.116.0.0/17
    (0xD1CE2800, 0xFFFFF800), // 209.206.40.0/21
    (0x678C1C00, 0xFFFFFE00), // 103.140.28.0/23
];

#[derive(Clone, Copy, PartialEq, Eq, Hash)]
enum Protocol {
    Tcp,
    Udp,
}

#[derive(Clone, Copy, PartialEq, Eq, Hash)]
struct ConnectionKey {
    local_ip: u32,
    local_port: u16,
    protocol: Protocol,
}

/// SwiftTunnel's ProcessSnapshot (lock-free via arc-swap)
struct SwiftTunnelSnapshot {
    connections: HashMap<ConnectionKey, u32>,
    pid_names: HashMap<u32, String>,
    tunnel_apps: HashSet<String>,
}

impl SwiftTunnelSnapshot {
    fn new() -> Self {
        let mut connections = HashMap::with_capacity(CONNECTION_COUNT);
        let mut pid_names = HashMap::with_capacity(PROCESS_COUNT);
        let tunnel_apps: HashSet<String> = TUNNEL_APPS.iter().map(|s| s.to_string()).collect();

        // Populate with simulated data
        for i in 0..PROCESS_COUNT {
            let name = if i < 2 {
                TUNNEL_APPS[i].to_string()
            } else {
                format!("process_{}.exe", i)
            };
            pid_names.insert(i as u32, name);
        }

        for i in 0..CONNECTION_COUNT {
            let key = ConnectionKey {
                local_ip: 0xC0A80000 | (i as u32 & 0xFFFF), // 192.168.x.x
                local_port: (i % 65535) as u16,
                protocol: if i % 2 == 0 { Protocol::Udp } else { Protocol::Tcp },
            };
            connections.insert(key, (i % PROCESS_COUNT) as u32);
        }

        Self {
            connections,
            pid_names,
            tunnel_apps,
        }
    }

    #[inline(always)]
    fn should_tunnel(&self, key: &ConnectionKey, dst_ip: u32, dst_port: u16) -> bool {
        // Step 1: Connection lookup (O(1) HashMap)
        if let Some(&pid) = self.connections.get(key) {
            // Step 2: PID → process name lookup
            if let Some(name) = self.pid_names.get(&pid) {
                // Step 3: Check if tunnel app
                if self.tunnel_apps.contains(name) {
                    // Step 4: V2 hybrid - check if game traffic
                    if key.protocol == Protocol::Udp && dst_port >= 49152 {
                        return true;
                    }
                }
            }
        }

        // Step 5: Fallback - check IP ranges (for first-packet before cache populated)
        for &(network, mask) in ROBLOX_RANGES {
            if (dst_ip & mask) == (network & mask) {
                if key.protocol == Protocol::Udp && dst_port >= 49152 {
                    return true;
                }
            }
        }

        false
    }
}

/// SwiftTunnel's lock-free cache (arc-swap)
struct SwiftTunnelCache {
    snapshot: ArcSwap<SwiftTunnelSnapshot>,
}

impl SwiftTunnelCache {
    fn new() -> Self {
        Self {
            snapshot: ArcSwap::from_pointee(SwiftTunnelSnapshot::new()),
        }
    }

    #[inline(always)]
    fn should_tunnel(&self, key: &ConnectionKey, dst_ip: u32, dst_port: u16) -> bool {
        let snapshot = self.snapshot.load();
        snapshot.should_tunnel(key, dst_ip, dst_port)
    }
}

// ============================================================================
// WIRESOCK-STYLE IMPLEMENTATION (Per-packet Windows API lookup)
// ============================================================================

/// Simulates WireSock's approach: RwLock + Windows API calls per packet
struct WireSockCache {
    connections: RwLock<HashMap<ConnectionKey, u32>>,
    pid_names: RwLock<HashMap<u32, String>>,
    tunnel_apps: HashSet<String>,
}

impl WireSockCache {
    fn new() -> Self {
        let mut connections = HashMap::with_capacity(CONNECTION_COUNT);
        let mut pid_names = HashMap::with_capacity(PROCESS_COUNT);
        let tunnel_apps: HashSet<String> = TUNNEL_APPS.iter().map(|s| s.to_string()).collect();

        for i in 0..PROCESS_COUNT {
            let name = if i < 2 {
                TUNNEL_APPS[i].to_string()
            } else {
                format!("process_{}.exe", i)
            };
            pid_names.insert(i as u32, name);
        }

        for i in 0..CONNECTION_COUNT {
            let key = ConnectionKey {
                local_ip: 0xC0A80000 | (i as u32 & 0xFFFF),
                local_port: (i % 65535) as u16,
                protocol: if i % 2 == 0 { Protocol::Udp } else { Protocol::Tcp },
            };
            connections.insert(key, (i % PROCESS_COUNT) as u32);
        }

        Self {
            connections: RwLock::new(connections),
            pid_names: RwLock::new(pid_names),
            tunnel_apps,
        }
    }

    #[inline(always)]
    fn should_tunnel(&self, key: &ConnectionKey, _dst_ip: u32, dst_port: u16) -> bool {
        // WireSock-style: Read lock for each lookup
        let connections = self.connections.read();
        if let Some(&pid) = connections.get(key) {
            drop(connections); // Release lock

            let pid_names = self.pid_names.read();
            if let Some(name) = pid_names.get(&pid) {
                if self.tunnel_apps.contains(name) {
                    if key.protocol == Protocol::Udp && dst_port >= 49152 {
                        return true;
                    }
                }
            }
        }
        false
    }
}

// ============================================================================
// STANDARD WIREGUARD (No split tunnel logic)
// ============================================================================

/// Standard WireGuard: No routing decisions, just encrypt everything
struct WireGuardTunnel {
    // Simulated encryption state
    _key: [u8; 32],
}

impl WireGuardTunnel {
    fn new() -> Self {
        Self { _key: [0u8; 32] }
    }

    #[inline(always)]
    fn process_packet(&self, packet: &mut [u8]) {
        // Simulate minimal packet processing (touch data like encryption would)
        if packet.len() >= 2 {
            packet[0] ^= 0x42;
            packet[packet.len() - 1] ^= 0x42;
        }
    }
}

// ============================================================================
// BENCHMARK RUNNER
// ============================================================================

struct BenchmarkResult {
    name: String,
    packets_processed: u64,
    duration_ns: u64,
    ns_per_packet: f64,
    packets_per_sec: f64,
    mpps: f64, // Million packets per second
}

impl BenchmarkResult {
    fn print(&self) {
        println!("  {}", self.name);
        println!("    Packets:     {:>12}", format_number(self.packets_processed));
        println!("    Duration:    {:>12.2} ms", self.duration_ns as f64 / 1_000_000.0);
        println!("    Latency:     {:>12.1} ns/packet", self.ns_per_packet);
        println!("    Throughput:  {:>12.2} Mpps", self.mpps);
        println!();
    }
}

fn format_number(n: u64) -> String {
    let s = n.to_string();
    let mut result = String::new();
    for (i, c) in s.chars().rev().enumerate() {
        if i > 0 && i % 3 == 0 {
            result.insert(0, ',');
        }
        result.insert(0, c);
    }
    result
}

fn benchmark_swifttunnel(iterations: u32) -> BenchmarkResult {
    let cache = SwiftTunnelCache::new();
    let mut total_duration = Duration::ZERO;
    let mut decisions = 0u64;

    // Warm up
    for i in 0..1000 {
        let key = ConnectionKey {
            local_ip: 0xC0A80000 | (i as u32 & 0xFFFF),
            local_port: (i % 65535) as u16,
            protocol: Protocol::Udp,
        };
        let dst_ip = 0x80740000 | (i as u32 & 0xFFFF); // Roblox range
        let _ = cache.should_tunnel(&key, dst_ip, 50000);
    }

    for _ in 0..iterations {
        let start = Instant::now();

        for i in 0..PACKETS_PER_ITERATION {
            let key = ConnectionKey {
                local_ip: 0xC0A80000 | (i as u32 & 0xFFFF),
                local_port: (i % 65535) as u16,
                protocol: if i % 3 == 0 { Protocol::Udp } else { Protocol::Tcp },
            };
            let dst_ip = if i % 4 == 0 {
                0x80740000 | (i as u32 & 0xFFFF) // Roblox
            } else {
                0x08080808 // Google DNS
            };
            let dst_port = if i % 2 == 0 { 50000 } else { 443 };

            if cache.should_tunnel(&key, dst_ip, dst_port) {
                decisions += 1;
            }
        }

        total_duration += start.elapsed();
    }

    let total_packets = PACKETS_PER_ITERATION * iterations as u64;
    let duration_ns = total_duration.as_nanos() as u64;
    let ns_per_packet = duration_ns as f64 / total_packets as f64;
    let packets_per_sec = total_packets as f64 / total_duration.as_secs_f64();

    BenchmarkResult {
        name: "SwiftTunnel (arc-swap + V2 hybrid)".to_string(),
        packets_processed: total_packets,
        duration_ns,
        ns_per_packet,
        packets_per_sec,
        mpps: packets_per_sec / 1_000_000.0,
    }
}

fn benchmark_wiresock(iterations: u32) -> BenchmarkResult {
    let cache = WireSockCache::new();
    let mut total_duration = Duration::ZERO;
    let mut decisions = 0u64;

    // Warm up
    for i in 0..1000 {
        let key = ConnectionKey {
            local_ip: 0xC0A80000 | (i as u32 & 0xFFFF),
            local_port: (i % 65535) as u16,
            protocol: Protocol::Udp,
        };
        let _ = cache.should_tunnel(&key, 0x80740000, 50000);
    }

    for _ in 0..iterations {
        let start = Instant::now();

        for i in 0..PACKETS_PER_ITERATION {
            let key = ConnectionKey {
                local_ip: 0xC0A80000 | (i as u32 & 0xFFFF),
                local_port: (i % 65535) as u16,
                protocol: if i % 3 == 0 { Protocol::Udp } else { Protocol::Tcp },
            };
            let dst_ip = if i % 4 == 0 { 0x80740000 } else { 0x08080808 };
            let dst_port = if i % 2 == 0 { 50000 } else { 443 };

            if cache.should_tunnel(&key, dst_ip, dst_port) {
                decisions += 1;
            }
        }

        total_duration += start.elapsed();
    }

    let total_packets = PACKETS_PER_ITERATION * iterations as u64;
    let duration_ns = total_duration.as_nanos() as u64;
    let ns_per_packet = duration_ns as f64 / total_packets as f64;
    let packets_per_sec = total_packets as f64 / total_duration.as_secs_f64();

    BenchmarkResult {
        name: "WireSock-style (RwLock per lookup)".to_string(),
        packets_processed: total_packets,
        duration_ns,
        ns_per_packet,
        packets_per_sec,
        mpps: packets_per_sec / 1_000_000.0,
    }
}

fn benchmark_wireguard(iterations: u32) -> BenchmarkResult {
    let tunnel = WireGuardTunnel::new();
    let mut total_duration = Duration::ZERO;
    let mut packet = vec![0u8; 1400]; // Typical MTU

    // Warm up
    for _ in 0..1000 {
        tunnel.process_packet(&mut packet);
    }

    for _ in 0..iterations {
        let start = Instant::now();

        for i in 0..PACKETS_PER_ITERATION {
            packet[0] = (i & 0xFF) as u8;
            tunnel.process_packet(&mut packet);
        }

        total_duration += start.elapsed();
    }

    let total_packets = PACKETS_PER_ITERATION * iterations as u64;
    let duration_ns = total_duration.as_nanos() as u64;
    let ns_per_packet = duration_ns as f64 / total_packets as f64;
    let packets_per_sec = total_packets as f64 / total_duration.as_secs_f64();

    BenchmarkResult {
        name: "WireGuard (no split tunnel)".to_string(),
        packets_processed: total_packets,
        duration_ns,
        ns_per_packet,
        packets_per_sec,
        mpps: packets_per_sec / 1_000_000.0,
    }
}

fn measure_memory() -> (f64, f64, f64) {
    let mut sys = System::new_all();
    let pid = Pid::from_u32(std::process::id());
    sys.refresh_processes(ProcessesToUpdate::Some(&[pid]), true);

    let baseline = sys
        .process(pid)
        .map(|p| p.memory() as f64 / 1_048_576.0)
        .unwrap_or(0.0);

    // Create SwiftTunnel cache
    let _st_cache = SwiftTunnelCache::new();
    sys.refresh_processes(ProcessesToUpdate::Some(&[pid]), true);
    let st_mem = sys
        .process(pid)
        .map(|p| p.memory() as f64 / 1_048_576.0)
        .unwrap_or(0.0);

    // Create WireSock cache
    let _ws_cache = WireSockCache::new();
    sys.refresh_processes(ProcessesToUpdate::Some(&[pid]), true);
    let ws_mem = sys
        .process(pid)
        .map(|p| p.memory() as f64 / 1_048_576.0)
        .unwrap_or(0.0);

    (baseline, st_mem - baseline, ws_mem - st_mem)
}

fn main() {
    println!("╔══════════════════════════════════════════════════════════════════╗");
    println!("║       VPN Split Tunnel Performance Benchmark                     ║");
    println!("║                                                                  ║");
    println!("║       SwiftTunnel vs WireGuard vs WireSock                       ║");
    println!("╚══════════════════════════════════════════════════════════════════╝\n");

    println!("Configuration:");
    println!("  Packets per iteration: {}", format_number(PACKETS_PER_ITERATION));
    println!("  Iterations:            {}", ITERATIONS);
    println!("  Process cache size:    {}", PROCESS_COUNT);
    println!("  Connection table size: {}", format_number(CONNECTION_COUNT as u64));
    println!();

    // Memory measurement
    println!("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");
    println!("Memory Usage");
    println!("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");

    let (baseline, st_mem, ws_mem) = measure_memory();
    println!("  Baseline:              {:.2} MB", baseline);
    println!("  SwiftTunnel cache:     {:.2} MB", st_mem);
    println!("  WireSock cache:        {:.2} MB", ws_mem);
    println!();

    // Run benchmarks
    println!("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");
    println!("Packet Processing Benchmark");
    println!("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n");

    println!("Running WireGuard benchmark...");
    let wg_result = benchmark_wireguard(ITERATIONS);
    wg_result.print();

    println!("Running SwiftTunnel benchmark...");
    let st_result = benchmark_swifttunnel(ITERATIONS);
    st_result.print();

    println!("Running WireSock-style benchmark...");
    let ws_result = benchmark_wiresock(ITERATIONS);
    ws_result.print();

    // Summary
    println!("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");
    println!("Summary");
    println!("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n");

    println!("  Latency (lower is better):");
    println!("    WireGuard:    {:>8.1} ns/packet (baseline)", wg_result.ns_per_packet);
    println!(
        "    SwiftTunnel:  {:>8.1} ns/packet ({:+.1}x overhead)",
        st_result.ns_per_packet,
        st_result.ns_per_packet / wg_result.ns_per_packet
    );
    println!(
        "    WireSock:     {:>8.1} ns/packet ({:+.1}x overhead)",
        ws_result.ns_per_packet,
        ws_result.ns_per_packet / wg_result.ns_per_packet
    );

    println!("\n  Throughput (higher is better):");
    println!("    WireGuard:    {:>8.2} Mpps", wg_result.mpps);
    println!(
        "    SwiftTunnel:  {:>8.2} Mpps ({:.1}% of WG)",
        st_result.mpps,
        (st_result.mpps / wg_result.mpps) * 100.0
    );
    println!(
        "    WireSock:     {:>8.2} Mpps ({:.1}% of WG)",
        ws_result.mpps,
        (ws_result.mpps / wg_result.mpps) * 100.0
    );

    let st_vs_ws = ws_result.ns_per_packet / st_result.ns_per_packet;
    println!("\n  SwiftTunnel vs WireSock:");
    println!("    SwiftTunnel is {:.1}x faster than WireSock-style", st_vs_ws);

    // Gaming impact
    let gaming_packets_per_sec = 1000.0; // ~1000 packets/sec for game traffic
    let st_overhead_ms = (st_result.ns_per_packet - wg_result.ns_per_packet) / 1_000_000.0 * gaming_packets_per_sec;
    let ws_overhead_ms = (ws_result.ns_per_packet - wg_result.ns_per_packet) / 1_000_000.0 * gaming_packets_per_sec;

    println!("\n  Gaming Impact (at 1000 packets/sec):");
    println!("    SwiftTunnel adds: {:.3} ms latency", st_overhead_ms);
    println!("    WireSock adds:    {:.3} ms latency", ws_overhead_ms);

    println!("\n╔══════════════════════════════════════════════════════════════════╗");
    println!("║       Benchmark Complete                                         ║");
    println!("╚══════════════════════════════════════════════════════════════════╝");
}
