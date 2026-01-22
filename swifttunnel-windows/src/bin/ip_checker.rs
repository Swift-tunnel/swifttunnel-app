//! Simple IP Checker - Test App for Split Tunnel Verification
//!
//! This minimal app fetches and displays the public IP address.
//! Use it to verify split tunnel routing:
//!   - Without split tunnel: shows your real IP
//!   - With split tunnel (this exe added): shows VPN server IP
//!
//! Run: cargo build --bin ip_checker
//! Then: target\release\ip_checker.exe

use std::io::{Read, Write};
use std::net::TcpStream;
use std::time::Duration;

fn main() {
    let args: Vec<String> = std::env::args().collect();

    if args.len() > 1 && (args[1] == "--speedtest" || args[1] == "-s") {
        run_speed_test();
        return;
    }

    println!("=== SwiftTunnel IP Checker ===\n");
    println!("Usage: ip_checker.exe [--speedtest|-s]\n");

    // Try multiple IP check services
    let services = [
        ("api.ipify.org", "api.ipify.org", "/"),
        ("ifconfig.me", "ifconfig.me", "/ip"),
        ("icanhazip.com", "icanhazip.com", "/"),
    ];

    for (name, host, path) in services {
        print!("Checking via {}... ", name);
        match check_ip(host, path) {
            Ok(ip) => {
                println!("SUCCESS");
                println!("\n  Your public IP: {}\n", ip.trim());
                return;
            }
            Err(e) => {
                println!("FAILED ({})", e);
            }
        }
    }

    eprintln!("\nERROR: Could not determine public IP from any service");
    std::process::exit(1);
}

fn run_speed_test() {
    println!("=== SwiftTunnel Speed Test ===\n");

    // First check our IP
    print!("Checking IP... ");
    match check_ip("api.ipify.org", "/") {
        Ok(ip) => println!("{}", ip.trim()),
        Err(e) => println!("failed: {}", e),
    }

    println!("\nDownloading test file (10MB)...");

    // Use Cloudflare speed test endpoint (more reliable)
    let host = "speed.cloudflare.com";
    let path = "/__down?bytes=10000000"; // 10MB

    match download_speed_test(host, path, 10_000_000) {
        Ok((bytes, elapsed_ms)) => {
            let mbps = (bytes as f64 * 8.0) / (elapsed_ms as f64 / 1000.0) / 1_000_000.0;
            println!("\n=== Results ===");
            println!("  Downloaded: {} bytes", bytes);
            println!("  Time: {:.2} seconds", elapsed_ms as f64 / 1000.0);
            println!("  Speed: {:.2} Mbps", mbps);
        }
        Err(e) => {
            eprintln!("\nSpeed test failed: {}", e);
            std::process::exit(1);
        }
    }
}

fn download_speed_test(host: &str, path: &str, expected_size: usize) -> Result<(usize, u128), String> {
    use std::net::ToSocketAddrs;
    use std::time::Instant;

    // Resolve hostname
    let addr_str = format!("{}:443", host);
    let addr = addr_str.to_socket_addrs()
        .map_err(|e| format!("DNS failed: {}", e))?
        .next()
        .ok_or_else(|| "No addresses".to_string())?;

    // For HTTPS, we need to use a TLS library, but for simplicity let's use HTTP
    // Try HTTP on port 80 with a different host
    let host = "speedtest.tele2.net";
    let path = "/10MB.zip";
    let addr_str = format!("{}:80", host);
    let addr = addr_str.to_socket_addrs()
        .map_err(|e| format!("DNS failed: {}", e))?
        .next()
        .ok_or_else(|| "No addresses".to_string())?;

    println!("  Connecting to {}...", host);

    let stream = TcpStream::connect_timeout(&addr, Duration::from_secs(10))
        .map_err(|e| format!("Connect failed: {}", e))?;

    stream.set_read_timeout(Some(Duration::from_secs(60)))
        .map_err(|e| format!("Set timeout failed: {}", e))?;

    let mut stream = stream;

    // Send HTTP request
    let request = format!(
        "GET {} HTTP/1.1\r\nHost: {}\r\nConnection: close\r\nUser-Agent: SwiftTunnel-SpeedTest/1.0\r\n\r\n",
        path, host
    );
    stream.write_all(request.as_bytes())
        .map_err(|e| format!("Write failed: {}", e))?;

    // Read response headers first
    let mut header_buf = [0u8; 4096];
    let mut headers_end = 0;
    let mut total_header_read = 0;

    loop {
        let n = stream.read(&mut header_buf[total_header_read..])
            .map_err(|e| format!("Read headers failed: {}", e))?;
        if n == 0 { break; }
        total_header_read += n;

        // Look for end of headers
        if let Some(pos) = find_header_end(&header_buf[..total_header_read]) {
            headers_end = pos;
            break;
        }
    }

    println!("  Starting download...");

    // Now read the body, measuring speed
    let start = Instant::now();
    let mut total_bytes = total_header_read - headers_end; // Body bytes already read
    let mut buf = [0u8; 65536];

    loop {
        match stream.read(&mut buf) {
            Ok(0) => break,
            Ok(n) => {
                total_bytes += n;
                // Progress every 1MB
                if total_bytes % 1_000_000 < 65536 {
                    print!(".");
                    let _ = std::io::stdout().flush();
                }
            }
            Err(e) => {
                if e.kind() == std::io::ErrorKind::TimedOut {
                    break;
                }
                return Err(format!("Read failed: {}", e));
            }
        }
    }

    let elapsed = start.elapsed().as_millis();
    println!(); // Newline after progress dots

    Ok((total_bytes, elapsed))
}

fn find_header_end(buf: &[u8]) -> Option<usize> {
    for i in 0..buf.len().saturating_sub(3) {
        if buf[i] == b'\r' && buf[i+1] == b'\n' && buf[i+2] == b'\r' && buf[i+3] == b'\n' {
            return Some(i + 4);
        }
    }
    None
}

fn check_ip(host: &str, path: &str) -> Result<String, String> {
    use std::net::ToSocketAddrs;

    // Resolve hostname to IP address
    let addr_str = format!("{}:80", host);
    let addr = addr_str.to_socket_addrs()
        .map_err(|e| format!("DNS resolution failed: {}", e))?
        .next()
        .ok_or_else(|| "No addresses found".to_string())?;

    // Connect with timeout
    let stream = TcpStream::connect_timeout(&addr, Duration::from_secs(5))
        .map_err(|e| format!("Connect failed: {}", e))?;

    stream.set_read_timeout(Some(Duration::from_secs(5)))
        .map_err(|e| format!("Set timeout failed: {}", e))?;
    stream.set_write_timeout(Some(Duration::from_secs(5)))
        .map_err(|e| format!("Set timeout failed: {}", e))?;

    let mut stream = stream;

    // Send HTTP request
    let request = format!(
        "GET {} HTTP/1.1\r\nHost: {}\r\nConnection: close\r\nUser-Agent: SwiftTunnel-IPChecker/1.0\r\n\r\n",
        path, host
    );
    stream.write_all(request.as_bytes())
        .map_err(|e| format!("Write failed: {}", e))?;

    // Read response
    let mut response = String::new();
    stream.read_to_string(&mut response)
        .map_err(|e| format!("Read failed: {}", e))?;

    // Parse response - find body after \r\n\r\n
    if let Some(body_start) = response.find("\r\n\r\n") {
        let body = &response[body_start + 4..];
        // The body should be just the IP address
        let ip = body.trim();
        if !ip.is_empty() && ip.len() < 50 {
            return Ok(ip.to_string());
        }
    }

    Err("Could not parse IP from response".to_string())
}
