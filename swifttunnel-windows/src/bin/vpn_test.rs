//! VPN Tunnel Test Binary
//!
//! Run with: cargo run --bin vpn_test
//! With config: cargo run --bin vpn_test -- config.json
//!
//! Requires: Administrator privileges, wintun.dll in working directory

use std::net::{Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;
use tokio::net::UdpSocket;
use boringtun::noise::{Tunn, TunnResult};

#[tokio::main]
async fn main() {
    // Set up logging
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info"))
        .format_timestamp_millis()
        .init();

    println!("=== SwiftTunnel VPN Test ===\n");

    // Step 1: Check admin privileges
    println!("[1] Checking administrator privileges...");
    if !is_admin() {
        eprintln!("ERROR: Administrator privileges required!");
        eprintln!("Please run this program as Administrator.");
        std::process::exit(1);
    }
    println!("    ✓ Running as Administrator\n");

    // Step 2: Check wintun.dll
    println!("[2] Checking wintun.dll...");
    if let Some(path) = find_wintun_dll() {
        println!("    ✓ Found wintun.dll at: {:?}\n", path);
    } else {
        eprintln!("ERROR: wintun.dll not found!");
        eprintln!("Please place wintun.dll in the same directory as this executable.");
        std::process::exit(1);
    }

    // Step 3: Test adapter creation
    println!("[3] Testing Wintun adapter creation...");
    match test_adapter_creation() {
        Ok(()) => println!("    ✓ Adapter created and destroyed successfully\n"),
        Err(e) => {
            eprintln!("ERROR: Failed to create adapter: {}", e);
            std::process::exit(1);
        }
    }

    // Step 4: Check for config file argument
    let args: Vec<String> = std::env::args().collect();
    if args.len() > 1 {
        let config_path = &args[1];
        println!("[4] Testing WireGuard handshake with config file...");
        println!("    Config file: {}\n", config_path);

        match test_wireguard_handshake(config_path).await {
            Ok(()) => println!("    ✓ WireGuard handshake successful!\n"),
            Err(e) => {
                eprintln!("ERROR: Handshake failed: {}", e);
                std::process::exit(1);
            }
        }
    } else {
        println!("[4] Testing WireGuard handshake...");
        println!("    (Skipped - no config file provided)");
        println!("    Usage: vpn_test.exe <config.json>\n");
    }

    println!("=== All tests passed! ===");
}

fn is_admin() -> bool {
    unsafe {
        use windows::Win32::Security::{
            GetTokenInformation, TokenElevation, TOKEN_ELEVATION, TOKEN_QUERY,
        };
        use windows::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};
        use windows::Win32::Foundation::CloseHandle;

        let mut token_handle = windows::Win32::Foundation::HANDLE::default();

        if OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token_handle).is_err() {
            return false;
        }

        let mut elevation = TOKEN_ELEVATION::default();
        let mut return_length: u32 = 0;

        let result = GetTokenInformation(
            token_handle,
            TokenElevation,
            Some(&mut elevation as *mut _ as *mut std::ffi::c_void),
            std::mem::size_of::<TOKEN_ELEVATION>() as u32,
            &mut return_length,
        );

        let _ = CloseHandle(token_handle);

        if result.is_ok() {
            elevation.TokenIsElevated != 0
        } else {
            false
        }
    }
}

fn find_wintun_dll() -> Option<std::path::PathBuf> {
    // Try executable directory first
    if let Ok(exe_path) = std::env::current_exe() {
        if let Some(exe_dir) = exe_path.parent() {
            let dll_path = exe_dir.join("wintun.dll");
            if dll_path.exists() {
                return Some(dll_path);
            }
        }
    }

    // Try current working directory
    if let Ok(cwd) = std::env::current_dir() {
        let dll_path = cwd.join("wintun.dll");
        if dll_path.exists() {
            return Some(dll_path);
        }
    }

    None
}

fn test_adapter_creation() -> Result<(), String> {
    use wintun::Adapter;

    // Load wintun.dll
    let wintun = unsafe {
        wintun::load_from_path(find_wintun_dll().unwrap())
            .map_err(|e| format!("Failed to load wintun.dll: {:?}", e))?
    };

    // Create adapter
    let adapter = Adapter::create(&wintun, "SwiftTunnelTest", "SwiftTunnel", None)
        .map_err(|e| format!("Failed to create adapter: {:?}", e))?;

    println!("    Created adapter: SwiftTunnelTest");

    // Get adapter info
    let _luid = adapter.get_luid();
    println!("    Adapter LUID obtained");

    // Set IP address
    let ip: Ipv4Addr = "10.0.99.1".parse().unwrap();
    adapter.set_address(ip)
        .map_err(|e| format!("Failed to set IP address: {:?}", e))?;
    println!("    Set IP address: {}", ip);

    // Create session
    let session = adapter.start_session(0x400000) // 4MB ring buffer
        .map_err(|e| format!("Failed to start session: {:?}", e))?;
    println!("    Session started with 4MB ring buffer");

    // Session and adapter will be dropped here, cleaning up
    drop(session);
    println!("    Session closed");

    Ok(())
}

/// VPN config structure matching the API response
#[derive(Debug, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
struct VpnConfig {
    region: String,
    #[serde(rename = "serverEndpoint")]
    endpoint: String,
    server_public_key: String,
    private_key: String,
    #[serde(default)]
    public_key: Option<String>, // Client public key (derived from private if not provided)
    assigned_ip: String,
    #[serde(default)]
    allowed_ips: Vec<String>,
    #[serde(default)]
    dns: Vec<String>,
}

async fn test_wireguard_handshake(config_path: &str) -> Result<(), String> {
    use base64::{Engine as _, engine::general_purpose::STANDARD};

    // Load config from file
    let config_data = std::fs::read_to_string(config_path)
        .map_err(|e| format!("Failed to read config file: {}", e))?;

    let config: VpnConfig = serde_json::from_str(&config_data)
        .map_err(|e| format!("Failed to parse config JSON: {}", e))?;

    println!("    Region: {}", config.region);
    println!("    Endpoint: {}", config.endpoint);
    println!("    Assigned IP: {}", config.assigned_ip);

    // Parse endpoint
    let endpoint: SocketAddr = config.endpoint.parse()
        .map_err(|e| format!("Invalid endpoint: {}", e))?;

    // Parse keys
    let private_key_bytes = STANDARD.decode(&config.private_key)
        .map_err(|e| format!("Invalid private key: {}", e))?;
    let peer_public_key_bytes = STANDARD.decode(&config.server_public_key)
        .map_err(|e| format!("Invalid server public key: {}", e))?;

    if private_key_bytes.len() != 32 {
        return Err(format!("Private key must be 32 bytes, got {}", private_key_bytes.len()));
    }
    if peer_public_key_bytes.len() != 32 {
        return Err(format!("Public key must be 32 bytes, got {}", peer_public_key_bytes.len()));
    }

    let mut private_key: [u8; 32] = [0; 32];
    let mut peer_public_key: [u8; 32] = [0; 32];
    private_key.copy_from_slice(&private_key_bytes);
    peer_public_key.copy_from_slice(&peer_public_key_bytes);

    println!("    Keys parsed successfully");

    // Create BoringTun instance
    let tunn = Tunn::new(
        private_key.into(),
        peer_public_key.into(),
        None, // No preshared key
        Some(25), // 25s keepalive
        0, // Tunnel index
        None, // No rate limiter
    ).map_err(|e| format!("Failed to create Tunn: {:?}", e))?;

    let tunn = Arc::new(std::sync::Mutex::new(tunn));
    println!("    BoringTun instance created");

    // Create UDP socket
    let socket = UdpSocket::bind("0.0.0.0:0")
        .await
        .map_err(|e| format!("Failed to bind UDP socket: {}", e))?;

    socket.connect(endpoint)
        .await
        .map_err(|e| format!("Failed to connect to endpoint: {}", e))?;

    println!("    UDP socket bound and connected to {}", endpoint);

    // Generate handshake initiation
    let mut buf = vec![0u8; 65535];
    let handshake_init = {
        let mut tunn = tunn.lock().unwrap();
        tunn.format_handshake_initiation(&mut buf, false)
    };

    match handshake_init {
        TunnResult::WriteToNetwork(data) => {
            println!("    Sending handshake initiation ({} bytes)...", data.len());
            socket.send(data)
                .await
                .map_err(|e| format!("Failed to send handshake: {}", e))?;
        }
        other => {
            return Err(format!("Unexpected handshake init result: {:?}", other));
        }
    }

    // Wait for response with timeout
    let mut response_buf = vec![0u8; 65535];
    let timeout = Duration::from_secs(10);

    println!("    Waiting for handshake response (10s timeout)...");

    match tokio::time::timeout(timeout, socket.recv(&mut response_buf)).await {
        Ok(Ok(n)) => {
            println!("    Received response ({} bytes)", n);

            let result = {
                let mut tunn = tunn.lock().unwrap();
                tunn.decapsulate(None, &response_buf[..n], &mut buf)
            };

            match result {
                TunnResult::Done => {
                    println!("    Handshake completed successfully!");
                }
                TunnResult::WriteToNetwork(data) => {
                    println!("    Sending handshake response ({} bytes)...", data.len());
                    socket.send(data).await.ok();
                    println!("    Handshake completed with response!");
                }
                TunnResult::Err(e) => {
                    return Err(format!("Handshake decapsulation error: {:?}", e));
                }
                other => {
                    println!("    Unexpected result: {:?}", other);
                    println!("    Handshake may still have completed");
                }
            }
        }
        Ok(Err(e)) => {
            return Err(format!("Socket receive error: {}", e));
        }
        Err(_) => {
            return Err("Handshake timeout - server may be unreachable or UDP blocked".to_string());
        }
    }

    // Try update_timers to see if we're in a connected state
    let timer_result = {
        let mut tunn = tunn.lock().unwrap();
        tunn.update_timers(&mut buf)
    };

    match timer_result {
        TunnResult::Done => println!("    Timer check: connection stable"),
        TunnResult::WriteToNetwork(_) => println!("    Timer check: sent keepalive"),
        TunnResult::Err(e) => println!("    Timer check warning: {:?}", e),
        _ => println!("    Timer check: OK"),
    }

    Ok(())
}
