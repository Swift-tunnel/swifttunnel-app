//! Cloudflare Speed Test
//!
//! Uses Cloudflare's speed.cloudflare.com endpoints to measure:
//! - Download speed (Mbps)
//! - Upload speed (Mbps)
//! - Latency (ms)
//!
//! Usage:
//!   speedtest.exe              # Run full test
//!   speedtest.exe --download   # Download only
//!   speedtest.exe --upload     # Upload only
//!   speedtest.exe --latency    # Latency only
//!
//! To test VPN performance:
//! 1. Add "speedtest.exe" to SwiftTunnel split tunnel apps
//! 2. Connect to VPN
//! 3. Run speedtest.exe
//! 4. Compare results with VPN disconnected
//!
//! Build: cargo build --release
//! Output: target/release/speedtest.exe

use std::io::Read;
use std::time::{Duration, Instant};

use clap::Parser;
use reqwest::blocking::Client;

// ============================================================================
// CLOUDFLARE SPEED TEST ENDPOINTS
// ============================================================================

const CF_DOWNLOAD_URL: &str = "https://speed.cloudflare.com/__down";
const CF_UPLOAD_URL: &str = "https://speed.cloudflare.com/__up";
const CF_LATENCY_URL: &str = "https://speed.cloudflare.com/__down?bytes=0";

// Test sizes
const DOWNLOAD_SIZES: &[u64] = &[
    100_000,      // 100 KB warmup
    1_000_000,    // 1 MB
    10_000_000,   // 10 MB
    25_000_000,   // 25 MB
    100_000_000,  // 100 MB
];

const UPLOAD_SIZE: usize = 10_000_000; // 10 MB
const LATENCY_SAMPLES: u32 = 20;

// ============================================================================
// CLI
// ============================================================================

#[derive(Parser, Debug)]
#[command(name = "speedtest")]
#[command(about = "Cloudflare Speed Test - measure your connection speed")]
struct Args {
    /// Run download test only
    #[arg(short, long)]
    download: bool,

    /// Run upload test only
    #[arg(short, long)]
    upload: bool,

    /// Run latency test only
    #[arg(short, long)]
    latency: bool,

    /// Number of test iterations
    #[arg(short, long, default_value = "3")]
    iterations: u32,
}

// ============================================================================
// RESULTS
// ============================================================================

#[derive(Debug, Clone)]
struct LatencyResult {
    min_ms: f64,
    max_ms: f64,
    avg_ms: f64,
    jitter_ms: f64,
}

#[derive(Debug, Clone)]
struct SpeedResult {
    speed_mbps: f64,
    bytes_transferred: u64,
    duration_secs: f64,
}

// ============================================================================
// TESTS
// ============================================================================

fn create_client() -> Client {
    Client::builder()
        .timeout(Duration::from_secs(60))
        .connect_timeout(Duration::from_secs(10))
        .user_agent("SwiftTunnel-SpeedTest/1.0")
        .build()
        .expect("Failed to create HTTP client")
}

fn test_latency(client: &Client) -> Option<LatencyResult> {
    println!("\n  Testing latency ({} samples)...", LATENCY_SAMPLES);

    let mut latencies: Vec<f64> = Vec::with_capacity(LATENCY_SAMPLES as usize);

    for i in 0..LATENCY_SAMPLES {
        let start = Instant::now();

        match client.get(CF_LATENCY_URL).send() {
            Ok(resp) => {
                if resp.status().is_success() {
                    let elapsed = start.elapsed().as_secs_f64() * 1000.0;
                    latencies.push(elapsed);
                    print!("\r    Sample {}/{}: {:.1}ms", i + 1, LATENCY_SAMPLES, elapsed);
                }
            }
            Err(e) => {
                eprintln!("\r    Sample {}/{}: Failed - {}", i + 1, LATENCY_SAMPLES, e);
            }
        }

        std::thread::sleep(Duration::from_millis(100));
    }

    println!();

    if latencies.is_empty() {
        println!("    Failed - no successful samples");
        return None;
    }

    latencies.sort_by(|a, b| a.partial_cmp(b).unwrap());

    let min = latencies[0];
    let max = latencies[latencies.len() - 1];
    let avg = latencies.iter().sum::<f64>() / latencies.len() as f64;
    let jitter = latencies.iter().map(|l| (l - avg).abs()).sum::<f64>() / latencies.len() as f64;

    println!("    Min: {:.1}ms | Avg: {:.1}ms | Max: {:.1}ms | Jitter: {:.1}ms",
             min, avg, max, jitter);

    Some(LatencyResult {
        min_ms: min,
        max_ms: max,
        avg_ms: avg,
        jitter_ms: jitter,
    })
}

fn test_download(client: &Client, iterations: u32) -> Option<SpeedResult> {
    println!("\n  Testing download speed...");

    let mut total_bytes: u64 = 0;
    let mut total_duration = Duration::ZERO;

    // Warmup
    print!("    Warmup...");
    let url = format!("{}?bytes={}", CF_DOWNLOAD_URL, DOWNLOAD_SIZES[0]);
    if let Ok(mut resp) = client.get(&url).send() {
        let mut buf = Vec::new();
        let _ = resp.read_to_end(&mut buf);
    }
    println!(" done");

    // Main tests
    for (i, &size) in DOWNLOAD_SIZES[1..].iter().enumerate() {
        let url = format!("{}?bytes={}", CF_DOWNLOAD_URL, size);
        let size_mb = size as f64 / 1_000_000.0;

        for iter in 0..iterations {
            print!("\r    Test {}/{}: Downloading {:.0} MB (iter {}/{})...",
                   i + 1, DOWNLOAD_SIZES.len() - 1, size_mb, iter + 1, iterations);

            let start = Instant::now();

            match client.get(&url).send() {
                Ok(mut resp) => {
                    if resp.status().is_success() {
                        let mut buf = vec![0u8; 65536];
                        let mut downloaded: u64 = 0;

                        loop {
                            match resp.read(&mut buf) {
                                Ok(0) => break,
                                Ok(n) => downloaded += n as u64,
                                Err(_) => break,
                            }
                        }

                        let elapsed = start.elapsed();
                        total_bytes += downloaded;
                        total_duration += elapsed;

                        let speed = (downloaded as f64 * 8.0) / (elapsed.as_secs_f64() * 1_000_000.0);
                        print!(" {:.1} Mbps", speed);
                    }
                }
                Err(e) => {
                    print!(" Error: {}", e);
                }
            }
        }
        println!();
    }

    if total_bytes == 0 {
        println!("    Failed - no data downloaded");
        return None;
    }

    let speed_mbps = (total_bytes as f64 * 8.0) / (total_duration.as_secs_f64() * 1_000_000.0);

    println!("\n    Average: {:.2} Mbps ({:.2} MB in {:.1}s)",
             speed_mbps,
             total_bytes as f64 / 1_000_000.0,
             total_duration.as_secs_f64());

    Some(SpeedResult {
        speed_mbps,
        bytes_transferred: total_bytes,
        duration_secs: total_duration.as_secs_f64(),
    })
}

fn test_upload(client: &Client, iterations: u32) -> Option<SpeedResult> {
    println!("\n  Testing upload speed...");

    let mut total_bytes: u64 = 0;
    let mut total_duration = Duration::ZERO;

    let payload = vec![0u8; UPLOAD_SIZE];

    for iter in 0..iterations {
        print!("\r    Uploading {} MB (iter {}/{})...",
               UPLOAD_SIZE / 1_000_000, iter + 1, iterations);

        let start = Instant::now();

        match client.post(CF_UPLOAD_URL)
            .body(payload.clone())
            .send()
        {
            Ok(resp) => {
                if resp.status().is_success() {
                    let elapsed = start.elapsed();
                    total_bytes += UPLOAD_SIZE as u64;
                    total_duration += elapsed;

                    let speed = (UPLOAD_SIZE as f64 * 8.0) / (elapsed.as_secs_f64() * 1_000_000.0);
                    print!(" {:.1} Mbps", speed);
                }
            }
            Err(e) => {
                print!(" Error: {}", e);
            }
        }
    }
    println!();

    if total_bytes == 0 {
        println!("    Failed - no data uploaded");
        return None;
    }

    let speed_mbps = (total_bytes as f64 * 8.0) / (total_duration.as_secs_f64() * 1_000_000.0);

    println!("\n    Average: {:.2} Mbps ({:.2} MB in {:.1}s)",
             speed_mbps,
             total_bytes as f64 / 1_000_000.0,
             total_duration.as_secs_f64());

    Some(SpeedResult {
        speed_mbps,
        bytes_transferred: total_bytes,
        duration_secs: total_duration.as_secs_f64(),
    })
}

// ============================================================================
// MAIN
// ============================================================================

fn print_header() {
    println!("╔══════════════════════════════════════════════════════════════════╗");
    println!("║           Cloudflare Speed Test                                  ║");
    println!("║                                                                  ║");
    println!("║  Add 'speedtest.exe' to split tunnel apps to test VPN speed     ║");
    println!("╚══════════════════════════════════════════════════════════════════╝");
}

fn print_summary(latency: Option<&LatencyResult>, download: Option<&SpeedResult>, upload: Option<&SpeedResult>) {
    println!("\n━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");
    println!("Results Summary");
    println!("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n");

    if let Some(l) = latency {
        println!("  Latency:    {:.1} ms (jitter: {:.1} ms)", l.avg_ms, l.jitter_ms);
    }

    if let Some(d) = download {
        println!("  Download:   {:.2} Mbps", d.speed_mbps);
    }

    if let Some(u) = upload {
        println!("  Upload:     {:.2} Mbps", u.speed_mbps);
    }

    // Connection quality rating
    if let Some(l) = latency {
        let rating = if l.avg_ms < 20.0 && l.jitter_ms < 5.0 {
            ("EXCELLENT", "★★★★★")
        } else if l.avg_ms < 50.0 && l.jitter_ms < 10.0 {
            ("GREAT", "★★★★☆")
        } else if l.avg_ms < 100.0 && l.jitter_ms < 20.0 {
            ("GOOD", "★★★☆☆")
        } else if l.avg_ms < 150.0 {
            ("FAIR", "★★☆☆☆")
        } else {
            ("POOR", "★☆☆☆☆")
        };

        println!("\n  Quality:    {} {}", rating.1, rating.0);
    }

    println!("\n━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");
    println!("Tip: Run WITH and WITHOUT VPN to compare performance.");
    println!("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");
}

fn main() {
    let args = Args::parse();

    print_header();

    let run_all = !args.download && !args.upload && !args.latency;

    println!("\nConnecting to speed.cloudflare.com...");

    let client = create_client();

    // Quick connectivity check
    match client.get(CF_LATENCY_URL).send() {
        Ok(resp) if resp.status().is_success() => {
            println!("Connected successfully!\n");
        }
        Ok(resp) => {
            eprintln!("Server returned error: {}", resp.status());
            return;
        }
        Err(e) => {
            eprintln!("Failed to connect: {}", e);
            eprintln!("\nMake sure you have internet connectivity.");
            return;
        }
    }

    let mut latency_result = None;
    let mut download_result = None;
    let mut upload_result = None;

    // Latency test
    if run_all || args.latency {
        println!("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");
        println!("Latency Test");
        println!("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");
        latency_result = test_latency(&client);
    }

    // Download test
    if run_all || args.download {
        println!("\n━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");
        println!("Download Test");
        println!("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");
        download_result = test_download(&client, args.iterations);
    }

    // Upload test
    if run_all || args.upload {
        println!("\n━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");
        println!("Upload Test");
        println!("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");
        upload_result = test_upload(&client, args.iterations);
    }

    print_summary(latency_result.as_ref(), download_result.as_ref(), upload_result.as_ref());
}
