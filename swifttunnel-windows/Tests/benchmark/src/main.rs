//! VPN Benchmark - Real CPU Usage & Network Performance
//!
//! Compares SwiftTunnel vs WireGuard vs WireSock with:
//! - Actual CPU % usage during network tests
//! - Real network speed via Cloudflare
//! - Memory usage
//!
//! Prerequisites:
//! - WireGuard installed: C:\Program Files\WireGuard\wireguard.exe
//! - WireSock installed: C:\Program Files\WireSock Secure Connect\bin\wiresock-client.exe
//! - SwiftTunnel installed (optional)
//! - Config file: C:\Users\testbench\benchmark-configs\mumbai.conf

use std::io::Write as IoWrite;
use std::process::{Child, Command, Stdio};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::thread;
use std::time::{Duration, Instant};

use parking_lot::Mutex;
use sysinfo::{ProcessesToUpdate, System};

// ============================================================================
// CONSTANTS
// ============================================================================

const CONFIG_PATH: &str = r"C:\Users\testbench\benchmark-configs\mumbai.conf";
const WIREGUARD_EXE: &str = r"C:\Program Files\WireGuard\wireguard.exe";
const WIRESOCK_EXE: &str = r"C:\Program Files\WireSock Secure Connect\bin\wiresock-client.exe";

const LATENCY_SAMPLES: u32 = 10;
const DOWNLOAD_SIZES: &[u64] = &[1_000_000, 10_000_000, 25_000_000]; // 1MB, 10MB, 25MB

// ============================================================================
// RESULTS
// ============================================================================

#[derive(Debug, Clone, Default)]
struct BenchmarkResult {
    name: String,
    latency_ms: f64,
    jitter_ms: f64,
    download_mbps: f64,
    avg_cpu_percent: f64,
    peak_cpu_percent: f64,
    avg_memory_mb: f64,
}

// ============================================================================
// CPU MONITORING
// ============================================================================

struct CpuMonitor {
    running: Arc<AtomicBool>,
    samples: Arc<Mutex<Vec<(f64, f64)>>>, // (cpu%, memory_mb)
    handle: Option<thread::JoinHandle<()>>,
}

impl CpuMonitor {
    fn new(process_names: &[&str]) -> Self {
        let running = Arc::new(AtomicBool::new(true));
        let samples = Arc::new(Mutex::new(Vec::new()));

        let running_clone = running.clone();
        let samples_clone = samples.clone();
        let names: Vec<String> = process_names.iter().map(|s| s.to_lowercase()).collect();

        let handle = thread::spawn(move || {
            let mut sys = System::new_all();

            while running_clone.load(Ordering::Relaxed) {
                sys.refresh_processes(ProcessesToUpdate::All, true);

                let mut total_cpu = 0.0;
                let mut total_mem = 0.0;

                for process in sys.processes().values() {
                    let proc_name = process.name().to_string_lossy().to_lowercase();
                    if names.iter().any(|n| proc_name.contains(n)) {
                        total_cpu += process.cpu_usage() as f64;
                        total_mem += process.memory() as f64 / 1024.0 / 1024.0;
                    }
                }

                samples_clone.lock().push((total_cpu, total_mem));
                thread::sleep(Duration::from_millis(200));
            }
        });

        CpuMonitor {
            running,
            samples,
            handle: Some(handle),
        }
    }

    fn stop(mut self) -> (f64, f64, f64) {
        self.running.store(false, Ordering::Relaxed);
        if let Some(h) = self.handle.take() {
            let _ = h.join();
        }

        let samples = self.samples.lock();
        if samples.is_empty() {
            return (0.0, 0.0, 0.0);
        }

        let avg_cpu = samples.iter().map(|(c, _)| c).sum::<f64>() / samples.len() as f64;
        let peak_cpu = samples.iter().map(|(c, _)| *c).fold(0.0f64, |a, b| a.max(b));
        let avg_mem = samples.iter().map(|(_, m)| m).sum::<f64>() / samples.len() as f64;

        (avg_cpu, peak_cpu, avg_mem)
    }
}

// ============================================================================
// VPN CONTROL
// ============================================================================

fn start_wireguard(config: &str) -> Result<(), String> {
    println!("    Starting WireGuard...");

    let output = Command::new(WIREGUARD_EXE)
        .args(["/installtunnelservice", config])
        .output()
        .map_err(|e| format!("Failed to start WireGuard: {}", e))?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        if !stderr.contains("already exists") {
            return Err(format!("WireGuard failed: {}", stderr));
        }
    }

    thread::sleep(Duration::from_secs(3));
    println!("    WireGuard connected");
    Ok(())
}

fn stop_wireguard(tunnel_name: &str) -> Result<(), String> {
    println!("    Stopping WireGuard...");

    let _ = Command::new(WIREGUARD_EXE)
        .args(["/uninstalltunnelservice", tunnel_name])
        .output();

    thread::sleep(Duration::from_secs(2));
    Ok(())
}

fn start_wiresock(config: &str) -> Result<Child, String> {
    println!("    Starting WireSock...");

    let child = Command::new(WIRESOCK_EXE)
        .args(["run", "-config", config, "-log-level", "none"])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .map_err(|e| format!("Failed to start WireSock: {}", e))?;

    thread::sleep(Duration::from_secs(3));
    println!("    WireSock connected");
    Ok(child)
}

fn stop_wiresock(mut child: Child) {
    println!("    Stopping WireSock...");
    let _ = child.kill();
    let _ = child.wait();
    thread::sleep(Duration::from_secs(1));
}

// ============================================================================
// NETWORK TESTS
// ============================================================================

fn test_latency() -> Option<(f64, f64)> {
    let mut latencies: Vec<f64> = Vec::new();

    for i in 0..LATENCY_SAMPLES {
        print!("\r      Sample {}/{}...", i + 1, LATENCY_SAMPLES);
        let _ = std::io::stdout().flush();

        let output = Command::new("curl")
            .args(["-s", "-o", "nul", "-w", "%{time_total}",
                   "https://speed.cloudflare.com/__down?bytes=0"])
            .output();

        if let Ok(out) = output {
            if out.status.success() {
                if let Ok(time_str) = String::from_utf8(out.stdout) {
                    if let Ok(time) = time_str.trim().parse::<f64>() {
                        latencies.push(time * 1000.0);
                    }
                }
            }
        }

        thread::sleep(Duration::from_millis(150));
    }
    println!();

    if latencies.is_empty() {
        return None;
    }

    let avg = latencies.iter().sum::<f64>() / latencies.len() as f64;
    let jitter = latencies.iter().map(|l| (l - avg).abs()).sum::<f64>() / latencies.len() as f64;

    Some((avg, jitter))
}

fn test_download() -> Option<f64> {
    let mut total_bytes: u64 = 0;
    let mut total_time: f64 = 0.0;

    for (i, &size) in DOWNLOAD_SIZES.iter().enumerate() {
        let url = format!("https://speed.cloudflare.com/__down?bytes={}", size);
        let size_mb = size as f64 / 1_000_000.0;

        print!("\r      Downloading {:.0} MB ({}/{})...", size_mb, i + 1, DOWNLOAD_SIZES.len());
        let _ = std::io::stdout().flush();

        let output = Command::new("curl")
            .args(["-s", "-o", "nul", "-w", "%{time_total},%{size_download}", &url])
            .output();

        if let Ok(out) = output {
            if out.status.success() {
                let result = String::from_utf8_lossy(&out.stdout);
                let parts: Vec<&str> = result.trim().split(',').collect();
                if parts.len() == 2 {
                    if let (Ok(time), Ok(bytes)) = (parts[0].parse::<f64>(), parts[1].parse::<u64>()) {
                        total_time += time;
                        total_bytes += bytes;

                        let speed = (bytes as f64 * 8.0) / (time * 1_000_000.0);
                        print!(" {:.1} Mbps", speed);
                    }
                }
            }
        }
    }
    println!();

    if total_bytes == 0 || total_time == 0.0 {
        return None;
    }

    Some((total_bytes as f64 * 8.0) / (total_time * 1_000_000.0))
}

fn run_network_test(process_names: &[&str]) -> BenchmarkResult {
    // Start CPU monitoring
    let monitor = CpuMonitor::new(process_names);

    // Small delay to get baseline CPU readings
    thread::sleep(Duration::from_millis(500));

    // Run latency test
    println!("    Testing latency...");
    let (latency, jitter) = test_latency().unwrap_or((0.0, 0.0));

    // Run download test
    println!("    Testing download...");
    let download = test_download().unwrap_or(0.0);

    // Stop monitoring and get results
    let (avg_cpu, peak_cpu, avg_mem) = monitor.stop();

    BenchmarkResult {
        name: String::new(),
        latency_ms: latency,
        jitter_ms: jitter,
        download_mbps: download,
        avg_cpu_percent: avg_cpu,
        peak_cpu_percent: peak_cpu,
        avg_memory_mb: avg_mem,
    }
}

// ============================================================================
// MAIN
// ============================================================================

fn print_header() {
    println!("╔══════════════════════════════════════════════════════════════════╗");
    println!("║     VPN Benchmark - Real CPU Usage                               ║");
    println!("║                                                                  ║");
    println!("║     SwiftTunnel vs WireGuard vs WireSock                         ║");
    println!("╚══════════════════════════════════════════════════════════════════╝");
    println!();
}

fn print_results(results: &[BenchmarkResult]) {
    println!("\n━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");
    println!("RESULTS");
    println!("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");
    println!();
    println!("┌─────────────────┬───────────┬──────────┬─────────────────┬────────────┬────────────┬────────────┐");
    println!("│ Connection      │ Latency   │ Jitter   │ Download        │ Avg CPU %  │ Peak CPU % │ Memory MB  │");
    println!("├─────────────────┼───────────┼──────────┼─────────────────┼────────────┼────────────┼────────────┤");

    let baseline_speed = results.first().map(|r| r.download_mbps).unwrap_or(1.0);

    for result in results {
        let speed_diff = if result.name != "No VPN" && baseline_speed > 0.0 {
            format!(" ({:.0}%)", (result.download_mbps / baseline_speed) * 100.0)
        } else {
            String::new()
        };

        println!(
            "│ {:15} │ {:7.1}ms │ {:6.1}ms │ {:7.1} Mbps{:5} │ {:8.1}%  │ {:8.1}%  │ {:8.1}   │",
            result.name,
            result.latency_ms,
            result.jitter_ms,
            result.download_mbps,
            speed_diff,
            result.avg_cpu_percent,
            result.peak_cpu_percent,
            result.avg_memory_mb
        );
    }

    println!("└─────────────────┴───────────┴──────────┴─────────────────┴────────────┴────────────┴────────────┘");
}

fn wait_for_enter(msg: &str) {
    println!("\n>>> {} <<<", msg);
    print!("    Press ENTER when ready...");
    let _ = std::io::stdout().flush();
    let mut input = String::new();
    let _ = std::io::stdin().read_line(&mut input);
}

fn ask_yes_no(msg: &str) -> bool {
    print!("\n>>> {} (y/n) <<<  ", msg);
    let _ = std::io::stdout().flush();
    let mut input = String::new();
    let _ = std::io::stdin().read_line(&mut input);
    input.trim().to_lowercase().starts_with('y')
}

fn main() {
    print_header();

    let mut results: Vec<BenchmarkResult> = Vec::new();

    // Check if config exists
    if !std::path::Path::new(CONFIG_PATH).exists() {
        eprintln!("ERROR: Config not found at {}", CONFIG_PATH);
        eprintln!("Create the config file first.");
        return;
    }

    println!("Config found: {}", CONFIG_PATH);
    println!();

    // ========================================================================
    // BASELINE (No VPN)
    // ========================================================================
    println!("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");
    println!("TEST 1: No VPN (Baseline)");
    println!("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");

    wait_for_enter("Disconnect ALL VPNs for baseline test");

    println!("\n  Running baseline test...");
    let mut baseline = run_network_test(&["curl"]);
    baseline.name = "No VPN".to_string();
    println!("\n    Result: {:.1}ms latency | {:.1}ms jitter | {:.1} Mbps",
             baseline.latency_ms, baseline.jitter_ms, baseline.download_mbps);
    results.push(baseline);

    // ========================================================================
    // WIREGUARD
    // ========================================================================
    if ask_yes_no("Test WireGuard?") {
        println!("\n━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");
        println!("TEST 2: WireGuard (Official Client)");
        println!("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");

        match start_wireguard(CONFIG_PATH) {
            Ok(()) => {
                println!("\n  Running WireGuard test...");
                // Monitor wireguard.exe process
                let mut wg_result = run_network_test(&["wireguard"]);
                wg_result.name = "WireGuard".to_string();
                println!("\n    Result: {:.1}ms | {:.1} Mbps | CPU: {:.1}% avg / {:.1}% peak | Mem: {:.1} MB",
                         wg_result.latency_ms, wg_result.download_mbps,
                         wg_result.avg_cpu_percent, wg_result.peak_cpu_percent, wg_result.avg_memory_mb);
                results.push(wg_result);

                let tunnel_name = std::path::Path::new(CONFIG_PATH)
                    .file_stem()
                    .and_then(|s| s.to_str())
                    .unwrap_or("mumbai");
                let _ = stop_wireguard(tunnel_name);
            }
            Err(e) => {
                eprintln!("    Failed to start WireGuard: {}", e);
            }
        }
    }

    // ========================================================================
    // WIRESOCK
    // ========================================================================
    if ask_yes_no("Test WireSock?") {
        println!("\n━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");
        println!("TEST 3: WireSock");
        println!("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");

        match start_wiresock(CONFIG_PATH) {
            Ok(child) => {
                println!("\n  Running WireSock test...");
                // Monitor wiresock-client.exe process
                let mut ws_result = run_network_test(&["wiresock"]);
                ws_result.name = "WireSock".to_string();
                println!("\n    Result: {:.1}ms | {:.1} Mbps | CPU: {:.1}% avg / {:.1}% peak | Mem: {:.1} MB",
                         ws_result.latency_ms, ws_result.download_mbps,
                         ws_result.avg_cpu_percent, ws_result.peak_cpu_percent, ws_result.avg_memory_mb);
                results.push(ws_result);

                stop_wiresock(child);
            }
            Err(e) => {
                eprintln!("    Failed to start WireSock: {}", e);
            }
        }
    }

    // ========================================================================
    // SWIFTTUNNEL
    // ========================================================================
    if ask_yes_no("Test SwiftTunnel?") {
        println!("\n━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");
        println!("TEST 4: SwiftTunnel");
        println!("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");

        wait_for_enter("Connect SwiftTunnel manually and wait for 'Connected'");

        println!("\n  Running SwiftTunnel test...");
        // Monitor swifttunnel-fps-booster.exe process
        let mut st_result = run_network_test(&["swifttunnel", "fps-booster"]);
        st_result.name = "SwiftTunnel".to_string();
        println!("\n    Result: {:.1}ms | {:.1} Mbps | CPU: {:.1}% avg / {:.1}% peak | Mem: {:.1} MB",
                 st_result.latency_ms, st_result.download_mbps,
                 st_result.avg_cpu_percent, st_result.peak_cpu_percent, st_result.avg_memory_mb);
        results.push(st_result);

        wait_for_enter("Disconnect SwiftTunnel when done");
    }

    // ========================================================================
    // RESULTS
    // ========================================================================
    print_results(&results);

    // Summary
    println!("\n━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");
    println!("SUMMARY");
    println!("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");

    if results.len() > 1 {
        let baseline = &results[0];

        for result in results.iter().skip(1) {
            let latency_diff = result.latency_ms - baseline.latency_ms;
            let speed_pct = if baseline.download_mbps > 0.0 {
                (result.download_mbps / baseline.download_mbps) * 100.0
            } else { 0.0 };

            println!(
                "  {:15}: {:+.1}ms latency | {:.0}% speed | {:.1}% CPU avg | {:.1}% CPU peak | {:.1} MB RAM",
                result.name, latency_diff, speed_pct,
                result.avg_cpu_percent, result.peak_cpu_percent, result.avg_memory_mb
            );
        }
    }

    println!("\n╔══════════════════════════════════════════════════════════════════╗");
    println!("║     Benchmark Complete                                           ║");
    println!("╚══════════════════════════════════════════════════════════════════╝");
}
