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
    println!("=== SwiftTunnel IP Checker ===\n");

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
