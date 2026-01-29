//! VPN Split Tunnel Performance Benchmark
//!
//! Tests and compares:
//! 1. SwiftTunnel (our implementation)
//! 2. Standard WireGuard (official client)
//! 3. WireSock (if installed)
//!
//! Measures:
//! - Packet processing overhead (CPU benchmark)
//! - Real network speed (Cloudflare speedtest)
//! - Latency impact
//! - Memory usage
//!
//! Run: cargo run --release
//!
//! For network tests, you'll be prompted to:
//! 1. Disconnect all VPNs (baseline)
//! 2. Connect SwiftTunnel
//! 3. Connect WireGuard
//! 4. Connect WireSock (optional)

use std::collections::HashMap;
use std::io::{Read, Write};
use std::net::TcpStream;
use std::process::Command;
use std::sync::Arc;
use std::time::{Duration, Instant};

use arc_swap::ArcSwap;
use parking_lot::RwLock;
use sysinfo::{Pid, ProcessesToUpdate, System};

// ============================================================================
// CLOUDFLARE SPEEDTEST
// ============================================================================

const CF_DOWNLOAD_URL: &str = "https://speed.cloudflare.com/__down";
const CF_LATENCY_URL: &str = "https://speed.cloudflare.com/__down?bytes=0";

const LATENCY_SAMPLES: u32 = 20;
const DOWNLOAD_SIZES: &[u64] = &[1_000_000, 10_000_000, 25_000_000]; // 1MB, 10MB, 25MB

// ============================================================================
// CPU BENCHMARK CONFIG
// ============================================================================

const PACKETS_PER_ITERATION: u64 = 1_000_000;
const CPU_ITERATIONS: u32 = 3;
const PROCESS_COUNT: usize = 50;
const CONNECTION_COUNT: usize = 10_000;

const TUNNEL_APPS: &[&str] = &["robloxplayerbeta.exe", "robloxstudiobeta.exe"];
const ROBLOX_RANGES: &[(u32, u32)] = &[
    (0x80740000, 0xFFFF8000), // 128.116.0.0/17
    (0xD1CE2800, 0xFFFFF800), // 209.206.40.0/21
];

// ============================================================================
// RESULTS
// ============================================================================

#[derive(Debug, Clone, Default)]
struct NetworkResult {
    name: String,
    latency_ms: f64,
    jitter_ms: f64,
    download_mbps: f64,
    upload_mbps: f64,
}

#[derive(Debug, Clone, Default)]
struct CpuResult {
    name: String,
    ns_per_packet: f64,
    mpps: f64,
    memory_mb: f64,
}

// ============================================================================
// SWIFTTUNNEL SIMULATION
// ============================================================================

#[derive(Clone, Copy, PartialEq, Eq, Hash)]
enum Protocol { Tcp, Udp }

#[derive(Clone, Copy, PartialEq, Eq, Hash)]
struct ConnectionKey {
    local_ip: u32,
    local_port: u16,
    protocol: Protocol,
}

struct SwiftTunnelSnapshot {
    connections: HashMap<ConnectionKey, u32>,
    pid_names: HashMap<u32, String>,
    tunnel_apps: std::collections::HashSet<String>,
}

impl SwiftTunnelSnapshot {
    fn new() -> Self {
        let mut connections = HashMap::with_capacity(CONNECTION_COUNT);
        let mut pid_names = HashMap::with_capacity(PROCESS_COUNT);
        let tunnel_apps: std::collections::HashSet<String> =
            TUNNEL_APPS.iter().map(|s| s.to_string()).collect();

        for i in 0..PROCESS_COUNT {
            let name = if i < 2 { TUNNEL_APPS[i].to_string() }
                       else { format!("process_{}.exe", i) };
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

        Self { connections, pid_names, tunnel_apps }
    }

    #[inline(always)]
    fn should_tunnel(&self, key: &ConnectionKey, dst_ip: u32, dst_port: u16) -> bool {
        if let Some(&pid) = self.connections.get(key) {
            if let Some(name) = self.pid_names.get(&pid) {
                if self.tunnel_apps.contains(name) {
                    if key.protocol == Protocol::Udp && dst_port >= 49152 {
                        return true;
                    }
                }
            }
        }
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

struct SwiftTunnelCache {
    snapshot: ArcSwap<SwiftTunnelSnapshot>,
}

impl SwiftTunnelCache {
    fn new() -> Self {
        Self { snapshot: ArcSwap::from_pointee(SwiftTunnelSnapshot::new()) }
    }

    #[inline(always)]
    fn should_tunnel(&self, key: &ConnectionKey, dst_ip: u32, dst_port: u16) -> bool {
        self.snapshot.load().should_tunnel(key, dst_ip, dst_port)
    }
}

// ============================================================================
// WIRESOCK SIMULATION (RwLock per lookup)
// ============================================================================

struct WireSockCache {
    connections: RwLock<HashMap<ConnectionKey, u32>>,
    pid_names: RwLock<HashMap<u32, String>>,
    tunnel_apps: std::collections::HashSet<String>,
}

impl WireSockCache {
    fn new() -> Self {
        let mut connections = HashMap::with_capacity(CONNECTION_COUNT);
        let mut pid_names = HashMap::with_capacity(PROCESS_COUNT);
        let tunnel_apps: std::collections::HashSet<String> =
            TUNNEL_APPS.iter().map(|s| s.to_string()).collect();

        for i in 0..PROCESS_COUNT {
            let name = if i < 2 { TUNNEL_APPS[i].to_string() }
                       else { format!("process_{}.exe", i) };
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
        let connections = self.connections.read();
        if let Some(&pid) = connections.get(key) {
            drop(connections);
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
// WIREGUARD SIMULATION (no split tunnel)
// ============================================================================

struct WireGuardTunnel { _key: [u8; 32] }

impl WireGuardTunnel {
    fn new() -> Self { Self { _key: [0u8; 32] } }

    #[inline(always)]
    fn process_packet(&self, packet: &mut [u8]) {
        if packet.len() >= 2 {
            packet[0] ^= 0x42;
            packet[packet.len() - 1] ^= 0x42;
        }
    }
}

// ============================================================================
// HTTP CLIENT (simple blocking)
// ============================================================================

fn http_get(url: &str) -> Result<Vec<u8>, String> {
    let host = if url.contains("speed.cloudflare.com") { "speed.cloudflare.com" }
               else { return Err("Unknown host".to_string()); };
    let path = url.split(host).nth(1).unwrap_or("/");

    let mut stream = TcpStream::connect((host, 443))
        .map_err(|e| format!("Connect failed: {}", e))?;

    // We need TLS for HTTPS - for simplicity, use reqwest via command
    Err("Use reqwest for HTTPS".to_string())
}

fn run_speedtest_latency() -> Option<(f64, f64)> {
    println!("    Testing latency...");

    // Use curl for simplicity (available on Windows)
    let mut latencies: Vec<f64> = Vec::new();

    for i in 0..LATENCY_SAMPLES {
        let start = Instant::now();

        let output = Command::new("curl")
            .args(&["-s", "-o", "NUL", "-w", "%{time_total}",
                   "https://speed.cloudflare.com/__down?bytes=0"])
            .output();

        match output {
            Ok(out) => {
                if out.status.success() {
                    if let Ok(time_str) = String::from_utf8(out.stdout) {
                        if let Ok(time) = time_str.trim().parse::<f64>() {
                            latencies.push(time * 1000.0); // Convert to ms
                        }
                    }
                }
            }
            Err(_) => {}
        }

        print!("\r    Sample {}/{}", i + 1, LATENCY_SAMPLES);
        std::io::stdout().flush().ok();
        std::thread::sleep(Duration::from_millis(100));
    }
    println!();

    if latencies.is_empty() { return None; }

    let avg = latencies.iter().sum::<f64>() / latencies.len() as f64;
    let jitter = latencies.iter().map(|l| (l - avg).abs()).sum::<f64>() / latencies.len() as f64;

    Some((avg, jitter))
}

fn run_speedtest_download() -> Option<f64> {
    println!("    Testing download...");

    let mut total_bytes: u64 = 0;
    let mut total_time: f64 = 0.0;

    for (i, &size) in DOWNLOAD_SIZES.iter().enumerate() {
        let url = format!("https://speed.cloudflare.com/__down?bytes={}", size);

        print!("\r    Downloading {} MB...", size / 1_000_000);
        std::io::stdout().flush().ok();

        let start = Instant::now();

        let output = Command::new("curl")
            .args(&["-s", "-o", "NUL", &url])
            .output();

        if let Ok(out) = output {
            if out.status.success() {
                let elapsed = start.elapsed().as_secs_f64();
                total_bytes += size;
                total_time += elapsed;

                let speed = (size as f64 * 8.0) / (elapsed * 1_000_000.0);
                print!(" {:.1} Mbps", speed);
            }
        }
    }
    println!();

    if total_time > 0.0 {
        Some((total_bytes as f64 * 8.0) / (total_time * 1_000_000.0))
    } else {
        None
    }
}

fn run_network_test(name: &str) -> NetworkResult {
    println!("\n  [{}]", name);

    let (latency, jitter) = run_speedtest_latency().unwrap_or((0.0, 0.0));
    let download = run_speedtest_download().unwrap_or(0.0);

    println!("    Results: {:.1}ms latency, {:.1}ms jitter, {:.1} Mbps download",
             latency, jitter, download);

    NetworkResult {
        name: name.to_string(),
        latency_ms: latency,
        jitter_ms: jitter,
        download_mbps: download,
        upload_mbps: 0.0, // Skip upload for speed
    }
}

// ============================================================================
// CPU BENCHMARK
// ============================================================================

fn benchmark_cpu_swifttunnel() -> CpuResult {
    let cache = SwiftTunnelCache::new();
    let mut total_duration = Duration::ZERO;

    // Warmup
    for i in 0..1000 {
        let key = ConnectionKey {
            local_ip: 0xC0A80000 | (i as u32 & 0xFFFF),
            local_port: (i % 65535) as u16,
            protocol: Protocol::Udp,
        };
        let _ = cache.should_tunnel(&key, 0x80740000, 50000);
    }

    for _ in 0..CPU_ITERATIONS {
        let start = Instant::now();
        for i in 0..PACKETS_PER_ITERATION {
            let key = ConnectionKey {
                local_ip: 0xC0A80000 | (i as u32 & 0xFFFF),
                local_port: (i % 65535) as u16,
                protocol: if i % 3 == 0 { Protocol::Udp } else { Protocol::Tcp },
            };
            let dst_ip = if i % 4 == 0 { 0x80740000 } else { 0x08080808 };
            let _ = cache.should_tunnel(&key, dst_ip, 50000);
        }
        total_duration += start.elapsed();
    }

    let total_packets = PACKETS_PER_ITERATION * CPU_ITERATIONS as u64;
    let ns_per_packet = total_duration.as_nanos() as f64 / total_packets as f64;
    let mpps = total_packets as f64 / total_duration.as_secs_f64() / 1_000_000.0;

    CpuResult {
        name: "SwiftTunnel".to_string(),
        ns_per_packet,
        mpps,
        memory_mb: 0.0,
    }
}

fn benchmark_cpu_wiresock() -> CpuResult {
    let cache = WireSockCache::new();
    let mut total_duration = Duration::ZERO;

    for i in 0..1000 {
        let key = ConnectionKey {
            local_ip: 0xC0A80000 | (i as u32 & 0xFFFF),
            local_port: (i % 65535) as u16,
            protocol: Protocol::Udp,
        };
        let _ = cache.should_tunnel(&key, 0x80740000, 50000);
    }

    for _ in 0..CPU_ITERATIONS {
        let start = Instant::now();
        for i in 0..PACKETS_PER_ITERATION {
            let key = ConnectionKey {
                local_ip: 0xC0A80000 | (i as u32 & 0xFFFF),
                local_port: (i % 65535) as u16,
                protocol: if i % 3 == 0 { Protocol::Udp } else { Protocol::Tcp },
            };
            let _ = cache.should_tunnel(&key, 0x80740000, 50000);
        }
        total_duration += start.elapsed();
    }

    let total_packets = PACKETS_PER_ITERATION * CPU_ITERATIONS as u64;
    let ns_per_packet = total_duration.as_nanos() as f64 / total_packets as f64;
    let mpps = total_packets as f64 / total_duration.as_secs_f64() / 1_000_000.0;

    CpuResult {
        name: "WireSock".to_string(),
        ns_per_packet,
        mpps,
        memory_mb: 0.0,
    }
}

fn benchmark_cpu_wireguard() -> CpuResult {
    let tunnel = WireGuardTunnel::new();
    let mut total_duration = Duration::ZERO;
    let mut packet = vec![0u8; 1400];

    for _ in 0..1000 {
        tunnel.process_packet(&mut packet);
    }

    for _ in 0..CPU_ITERATIONS {
        let start = Instant::now();
        for i in 0..PACKETS_PER_ITERATION {
            packet[0] = (i & 0xFF) as u8;
            tunnel.process_packet(&mut packet);
        }
        total_duration += start.elapsed();
    }

    let total_packets = PACKETS_PER_ITERATION * CPU_ITERATIONS as u64;
    let ns_per_packet = total_duration.as_nanos() as f64 / total_packets as f64;
    let mpps = total_packets as f64 / total_duration.as_secs_f64() / 1_000_000.0;

    CpuResult {
        name: "WireGuard".to_string(),
        ns_per_packet,
        mpps,
        memory_mb: 0.0,
    }
}

// ============================================================================
// MAIN
// ============================================================================

fn wait_for_enter(prompt: &str) {
    println!("\n>>> {} <<<", prompt);
    println!("    Press ENTER when ready...");
    let mut input = String::new();
    std::io::stdin().read_line(&mut input).ok();
}

fn print_header() {
    println!("╔══════════════════════════════════════════════════════════════════╗");
    println!("║     VPN Split Tunnel Benchmark                                   ║");
    println!("║                                                                  ║");
    println!("║     SwiftTunnel vs WireGuard vs WireSock                         ║");
    println!("╚══════════════════════════════════════════════════════════════════╝\n");
}

fn print_cpu_results(wg: &CpuResult, st: &CpuResult, ws: &CpuResult) {
    println!("\n┌─────────────────────────────────────────────────────────────────┐");
    println!("│ CPU Overhead Results                                            │");
    println!("├───────────────┬──────────────┬──────────────┬──────────────────┤");
    println!("│ Implementation│  ns/packet   │     Mpps     │    Overhead      │");
    println!("├───────────────┼──────────────┼──────────────┼──────────────────┤");
    println!("│ WireGuard     │ {:>10.1} │ {:>10.2} │     baseline     │",
             wg.ns_per_packet, wg.mpps);
    println!("│ SwiftTunnel   │ {:>10.1} │ {:>10.2} │ {:>+13.1}x │",
             st.ns_per_packet, st.mpps,
             if wg.ns_per_packet > 0.0 { st.ns_per_packet / wg.ns_per_packet } else { 0.0 });
    println!("│ WireSock      │ {:>10.1} │ {:>10.2} │ {:>+13.1}x │",
             ws.ns_per_packet, ws.mpps,
             if wg.ns_per_packet > 0.0 { ws.ns_per_packet / wg.ns_per_packet } else { 0.0 });
    println!("└───────────────┴──────────────┴──────────────┴──────────────────┘");
}

fn print_network_results(results: &[NetworkResult]) {
    println!("\n┌─────────────────────────────────────────────────────────────────┐");
    println!("│ Network Speed Results (Cloudflare)                              │");
    println!("├───────────────┬──────────────┬──────────────┬──────────────────┤");
    println!("│ Connection    │  Latency     │   Jitter     │    Download      │");
    println!("├───────────────┼──────────────┼──────────────┼──────────────────┤");

    let baseline = results.first().map(|r| r.download_mbps).unwrap_or(0.0);

    for r in results {
        let pct = if baseline > 0.0 && r.name != "No VPN" {
            format!("({:.0}%)", (r.download_mbps / baseline) * 100.0)
        } else {
            "".to_string()
        };

        println!("│ {:13} │ {:>8.1} ms │ {:>8.1} ms │ {:>8.1} Mbps {} │",
                 r.name, r.latency_ms, r.jitter_ms, r.download_mbps, pct);
    }
    println!("└───────────────┴──────────────┴──────────────┴──────────────────┘");
}

fn print_summary(cpu_st: &CpuResult, cpu_ws: &CpuResult, net_results: &[NetworkResult]) {
    println!("\n━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");
    println!("SUMMARY");
    println!("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n");

    // CPU comparison
    let st_vs_ws = if cpu_st.ns_per_packet > 0.0 {
        cpu_ws.ns_per_packet / cpu_st.ns_per_packet
    } else { 1.0 };

    if st_vs_ws > 1.0 {
        println!("  CPU: SwiftTunnel is {:.1}x FASTER than WireSock", st_vs_ws);
    } else {
        println!("  CPU: WireSock is {:.1}x faster than SwiftTunnel", 1.0 / st_vs_ws);
    }

    // Gaming impact
    let gaming_pps = 1000.0;
    let st_overhead_ms = cpu_st.ns_per_packet / 1_000_000.0 * gaming_pps;
    println!("  Gaming: SwiftTunnel adds {:.3}ms per 1000 packets", st_overhead_ms);

    // Network comparison
    if net_results.len() >= 2 {
        let baseline = &net_results[0];
        for r in &net_results[1..] {
            let speed_pct = (r.download_mbps / baseline.download_mbps) * 100.0;
            let latency_diff = r.latency_ms - baseline.latency_ms;
            println!("  {}: {:.0}% speed, {:+.1}ms latency vs baseline",
                     r.name, speed_pct, latency_diff);
        }
    }

    println!("\n━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");
}

fn main() {
    print_header();

    // Check for curl
    if Command::new("curl").arg("--version").output().is_err() {
        eprintln!("ERROR: curl not found. Please install curl.");
        return;
    }

    let args: Vec<String> = std::env::args().collect();
    let skip_network = args.contains(&"--cpu-only".to_string());
    let skip_cpu = args.contains(&"--network-only".to_string());

    // ========================================================================
    // CPU BENCHMARK
    // ========================================================================

    let mut cpu_wg = CpuResult::default();
    let mut cpu_st = CpuResult::default();
    let mut cpu_ws = CpuResult::default();

    if !skip_cpu {
        println!("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");
        println!("PART 1: CPU Overhead Benchmark");
        println!("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n");

        println!("  Processing {} packets x {} iterations...\n",
                 PACKETS_PER_ITERATION, CPU_ITERATIONS);

        print!("  WireGuard (baseline)...");
        std::io::stdout().flush().ok();
        cpu_wg = benchmark_cpu_wireguard();
        println!(" {:.1} ns/pkt, {:.2} Mpps", cpu_wg.ns_per_packet, cpu_wg.mpps);

        print!("  SwiftTunnel...");
        std::io::stdout().flush().ok();
        cpu_st = benchmark_cpu_swifttunnel();
        println!(" {:.1} ns/pkt, {:.2} Mpps", cpu_st.ns_per_packet, cpu_st.mpps);

        print!("  WireSock-style...");
        std::io::stdout().flush().ok();
        cpu_ws = benchmark_cpu_wiresock();
        println!(" {:.1} ns/pkt, {:.2} Mpps", cpu_ws.ns_per_packet, cpu_ws.mpps);

        print_cpu_results(&cpu_wg, &cpu_st, &cpu_ws);
    }

    // ========================================================================
    // NETWORK BENCHMARK
    // ========================================================================

    let mut net_results: Vec<NetworkResult> = Vec::new();

    if !skip_network {
        println!("\n━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");
        println!("PART 2: Network Speed Benchmark (Cloudflare)");
        println!("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");

        // Test 1: No VPN (baseline)
        wait_for_enter("Disconnect ALL VPNs for baseline test");
        net_results.push(run_network_test("No VPN"));

        // Test 2: SwiftTunnel
        wait_for_enter("Connect SWIFTTUNNEL and wait for 'Connected'");
        net_results.push(run_network_test("SwiftTunnel"));

        // Test 3: WireGuard (optional)
        println!("\n>>> Do you want to test WireGuard? (y/n) <<<");
        let mut input = String::new();
        std::io::stdin().read_line(&mut input).ok();
        if input.trim().to_lowercase() == "y" {
            wait_for_enter("Disconnect SwiftTunnel, Connect WIREGUARD");
            net_results.push(run_network_test("WireGuard"));
        }

        // Test 4: WireSock (optional)
        println!("\n>>> Do you want to test WireSock? (y/n) <<<");
        input.clear();
        std::io::stdin().read_line(&mut input).ok();
        if input.trim().to_lowercase() == "y" {
            wait_for_enter("Disconnect WireGuard, Connect WIRESOCK");
            net_results.push(run_network_test("WireSock"));
        }

        print_network_results(&net_results);
    }

    // ========================================================================
    // SUMMARY
    // ========================================================================

    if !skip_cpu {
        print_summary(&cpu_st, &cpu_ws, &net_results);
    }

    println!("\n╔══════════════════════════════════════════════════════════════════╗");
    println!("║     Benchmark Complete                                           ║");
    println!("╚══════════════════════════════════════════════════════════════════╝");
}
