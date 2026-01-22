//! SwiftTunnel CLI Testbench
//!
//! A headless CLI tool for testing VPN and split tunnel functionality
//! without requiring a GUI or user interaction.
//!
//! Usage:
//!   testbench              - Run all tests
//!   testbench driver       - Check driver status only
//!   testbench init         - Test driver initialization
//!   testbench full         - Test full split tunnel flow
//!   testbench info         - Show system info
//!   testbench verify       - Verify actual traffic routing (requires network)

use std::collections::HashSet;
use std::env;
use std::time::Duration;

use anyhow::Result;
use tokio::runtime::Runtime;

// Import from main crate
use swifttunnel_fps_booster::auth::AuthManager;
use swifttunnel_fps_booster::vpn::split_tunnel::{SplitTunnelDriver, SplitTunnelConfig, GamePreset, get_apps_for_preset_set};
use swifttunnel_fps_booster::vpn::{WireguardContext, VpnEncryptContext};
use swifttunnel_fps_booster::vpn::adapter::WintunAdapter;
use swifttunnel_fps_booster::vpn::tunnel::WireguardTunnel;
use swifttunnel_fps_booster::vpn::config::fetch_vpn_config;
use swifttunnel_fps_booster::vpn::routes::{RouteManager, get_internet_interface_ip};
use swifttunnel_fps_booster::auth::types::AuthState;

/// Testbench credentials
const TESTBENCH_EMAIL: &str = "testbench@swifttunnel.net";
const TESTBENCH_PASSWORD: &str = "TestBench2026";

/// Test region
const TEST_REGION: &str = "singapore";

fn main() -> Result<()> {
    // Initialize logging
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info"))
        .format_timestamp_millis()
        .init();

    println!("\n╔════════════════════════════════════════════════════════════╗");
    println!("║          SwiftTunnel CLI Testbench v0.6.0                  ║");
    println!("║          Using ndisapi for split tunnel                    ║");
    println!("╚════════════════════════════════════════════════════════════╝\n");

    let args: Vec<String> = env::args().collect();
    let command = args.get(1).map(|s| s.as_str()).unwrap_or("all");

    match command {
        "driver" => {
            check_driver_status();
        }
        "init" => {
            test_split_tunnel_driver();
        }
        "full" => {
            test_full_split_tunnel_flow();
        }
        "info" => {
            show_system_info();
        }
        "verify" => {
            verify_traffic_routing();
        }
        "ping" => {
            test_ping_functionality();
        }
        "split" => {
            test_split_tunnel_two_apps();
        }
        "all" => {
            println!("Running all tests...\n");
            check_driver_status();
            test_split_tunnel_driver();
            test_full_split_tunnel_flow();
            show_system_info();
        }
        "help" | "-h" | "--help" => {
            print_usage();
        }
        _ => {
            println!("Unknown command: {}\n", command);
            print_usage();
            std::process::exit(1);
        }
    }

    println!("\nTestbench complete.");
    Ok(())
}

fn print_usage() {
    println!("Usage: testbench [COMMAND]");
    println!();
    println!("Commands:");
    println!("  all      Run all tests (default)");
    println!("  driver   Check driver status");
    println!("  init     Test driver initialization");
    println!("  full     Test full split tunnel flow");
    println!("  info     Show system info");
    println!("  verify   Verify actual traffic routing (connects to VPN)");
    println!("  ping     Test ping functionality (fetch servers & measure latency)");
    println!("  split    Test split tunnel with two apps (ip_checker=tunnel, testbench=bypass)");
    println!("  help     Show this help message");
}

/// Check public IP using multiple services
/// Get public IP using direct HTTP request from THIS process.
/// This is critical for split tunnel testing - we need the request to come from
/// the testbench.exe process itself, not a spawned child process.
/// The testbench.exe process is registered as excluded from VPN, so its sockets
/// should be bound to the internet IP if split tunnel is working.
fn get_public_ip() -> Option<String> {
    let services = [
        "https://api.ipify.org",
        "https://ifconfig.me/ip",
        "https://icanhazip.com",
    ];

    // Create a small runtime for the HTTP request
    // IMPORTANT: We use reqwest directly instead of spawning PowerShell because:
    // 1. This process (testbench.exe) is registered with the split tunnel driver
    // 2. Spawned processes (PowerShell) have new PIDs not registered with the driver
    // 3. The driver tracks by PID, so only registered processes get their sockets redirected
    let rt = match tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
    {
        Ok(rt) => rt,
        Err(_) => return None,
    };

    let client = match reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(5))
        .build()
    {
        Ok(c) => c,
        Err(_) => return None,
    };

    for service in services {
        let result = rt.block_on(async {
            client.get(service).send().await?.text().await
        });

        if let Ok(ip) = result {
            let ip = ip.trim().to_string();
            if !ip.is_empty() && ip.chars().all(|c| c.is_ascii_digit() || c == '.') {
                return Some(ip);
            }
        }
    }
    None
}

fn verify_traffic_routing() {
    println!("═══ Traffic Routing Verification ═══\n");
    println!("This test connects to a real VPN server and verifies traffic routing.\n");

    // Create tokio runtime
    let rt = Runtime::new().expect("Failed to create tokio runtime");

    // Step 1: Get original IP before VPN
    println!("Step 1: Getting original IP (before VPN)...");
    let original_ip = match get_public_ip() {
        Some(ip) => {
            println!("   ✅ Original IP: {}", ip);
            ip
        }
        None => {
            println!("   ❌ Failed to get original IP");
            return;
        }
    };

    // Step 2: Authenticate
    println!("\nStep 2: Authenticating with testbench account...");
    let auth_manager = match AuthManager::new() {
        Ok(m) => m,
        Err(e) => {
            println!("   ❌ Failed to create AuthManager: {}", e);
            return;
        }
    };

    let access_token = rt.block_on(async {
        // Sign in
        if let Err(e) = auth_manager.sign_in(TESTBENCH_EMAIL, TESTBENCH_PASSWORD).await {
            println!("   ❌ Sign in failed: {}", e);
            return None;
        }
        println!("   ✅ Signed in as {}", TESTBENCH_EMAIL);

        // Get access token
        match auth_manager.get_state() {
            AuthState::LoggedIn(session) => Some(session.access_token),
            _ => {
                println!("   ❌ Not logged in after sign_in");
                None
            }
        }
    });

    let access_token = match access_token {
        Some(t) => t,
        None => return,
    };

    // Step 3: Fetch VPN config
    println!("\nStep 3: Fetching VPN config for region '{}'...", TEST_REGION);
    let vpn_config = rt.block_on(async {
        match fetch_vpn_config(&access_token, TEST_REGION).await {
            Ok(config) => {
                println!("   ✅ Got VPN config: endpoint={}", config.endpoint);
                println!("   Assigned IP: {}", config.assigned_ip);
                Some(config)
            }
            Err(e) => {
                println!("   ❌ Failed to fetch VPN config: {}", e);
                None
            }
        }
    });

    let vpn_config = match vpn_config {
        Some(c) => c,
        None => return,
    };

    // Step 4: Create Wintun adapter
    println!("\nStep 4: Creating Wintun adapter...");
    let (ip, cidr) = match parse_ip_cidr(&vpn_config.assigned_ip) {
        Ok((ip, cidr)) => (ip, cidr),
        Err(e) => {
            println!("   ❌ Failed to parse assigned IP: {}", e);
            return;
        }
    };

    let adapter = match WintunAdapter::create(std::net::IpAddr::V4(ip), cidr) {
        Ok(a) => {
            println!("   ✅ Wintun adapter created");
            std::sync::Arc::new(a)
        }
        Err(e) => {
            println!("   ❌ Failed to create adapter: {}", e);
            return;
        }
    };

    // Set DNS
    if !vpn_config.dns.is_empty() {
        if let Err(e) = adapter.set_dns(&vpn_config.dns) {
            println!("   ⚠ Failed to set DNS: {}", e);
        }
    }

    let interface_luid = adapter.get_luid();
    println!("   Interface LUID: {}", interface_luid);

    // Step 5: Create and start WireGuard tunnel
    println!("\nStep 5: Starting WireGuard tunnel...");
    let tunnel = match WireguardTunnel::new(vpn_config.clone()) {
        Ok(t) => {
            println!("   ✅ WireGuard tunnel created");
            std::sync::Arc::new(t)
        }
        Err(e) => {
            println!("   ❌ Failed to create tunnel: {}", e);
            adapter.shutdown();
            return;
        }
    };

    // Start tunnel in background
    let tunnel_clone = tunnel.clone();
    let adapter_clone = adapter.clone();
    rt.spawn(async move {
        if let Err(e) = tunnel_clone.start(adapter_clone).await {
            log::error!("Tunnel error: {}", e);
        }
    });

    // Wait for tunnel to establish
    println!("   Waiting for tunnel handshake...");
    std::thread::sleep(Duration::from_secs(3));

    // Step 6: Get internet IP BEFORE applying routes
    // This is critical - after routes are applied, the default gateway changes to VPN
    println!("\nStep 6: Getting internet IP (BEFORE routes change default gateway)...");
    let original_internet_ip = match get_internet_interface_ip() {
        Ok(ip) => {
            println!("   ✅ Internet interface IP: {} (will use for split tunnel)", ip);
            ip.to_string()
        }
        Err(e) => {
            println!("   ❌ Failed to get internet IP: {}", e);
            tunnel.stop();
            adapter.shutdown();
            return;
        }
    };

    // Step 7: Setup routes (split tunnel mode - no default VPN route)
    println!("\nStep 7: Setting up routes (SPLIT TUNNEL MODE)...");
    let server_ip: std::net::Ipv4Addr = vpn_config.endpoint
        .split(':')
        .next()
        .unwrap_or("0.0.0.0")
        .parse()
        .unwrap_or(std::net::Ipv4Addr::new(0, 0, 0, 0));

    let if_index = get_interface_index("SwiftTunnel").unwrap_or(1);
    let mut route_manager = RouteManager::new(server_ip, if_index);

    // Enable split tunnel mode - only tunnel apps will use VPN
    // Non-tunnel apps (like testbench.exe) will bypass VPN
    route_manager.set_split_tunnel_mode(true);

    if let Err(e) = route_manager.apply_routes() {
        println!("   ⚠ Failed to apply routes: {}", e);
    } else {
        println!("   ✅ Routes applied (split tunnel mode - no default route)");
    }

    // Wait for routes to settle
    std::thread::sleep(Duration::from_secs(2));

    // Step 8: Check IP (in split tunnel mode, should stay ORIGINAL - traffic bypasses VPN by default)
    println!("\nStep 8: Checking IP (split tunnel mode - should be ORIGINAL IP)...");
    let vpn_ip = match get_public_ip() {
        Some(ip) => {
            println!("   Current IP: {}", ip);
            if ip == original_ip {
                println!("   ✅ IP unchanged ({}) - split tunnel mode working (traffic bypasses VPN)", ip);
            } else {
                println!("   ⚠ IP changed to {} - unexpected (split tunnel mode should bypass VPN)", ip);
            }
            ip
        }
        None => {
            println!("   ❌ Failed to get public IP");
            route_manager.remove_routes().ok();
            tunnel.stop();
            adapter.shutdown();
            return;
        }
    };

    // Step 9: Now setup split tunnel using ndisapi
    println!("\nStep 9: Setting up split tunnel (testbench.exe should bypass VPN)...");

    // Initialize driver
    let mut driver = SplitTunnelDriver::new();

    // Check if driver is available (static method)
    if !SplitTunnelDriver::is_available() {
        println!("   ❌ ndisapi driver not available");
        println!("   Please install Windows Packet Filter driver");
        route_manager.remove_routes().ok();
        tunnel.stop();
        adapter.shutdown();
        return;
    }
    println!("   ✅ ndisapi driver available");

    // Open and initialize the driver
    if let Err(e) = driver.open() {
        println!("   ❌ Failed to open driver: {}", e);
        route_manager.remove_routes().ok();
        tunnel.stop();
        adapter.shutdown();
        return;
    }
    println!("   ✅ Driver opened");

    if let Err(e) = driver.initialize() {
        println!("   ❌ Failed to initialize driver: {}", e);
        route_manager.remove_routes().ok();
        tunnel.stop();
        adapter.shutdown();
        return;
    }
    println!("   ✅ Driver initialized");

    // Create WireGuard context for packet injection into Wintun
    // This allows tunnel app packets to be injected into Wintun -> tunnel.rs encrypts -> VPN server
    let wg_ctx = std::sync::Arc::new(WireguardContext {
        session: adapter.session(),
        packets_injected: std::sync::atomic::AtomicU64::new(0),
    });
    driver.set_wireguard_context(wg_ctx.clone());
    println!("   ✅ Wintun injection context set");

    // Configure split tunnel with Roblox apps only
    // testbench.exe is NOT in this list, so it should bypass VPN
    let presets = HashSet::from([GamePreset::Roblox]);
    let tunnel_apps = get_apps_for_preset_set(&presets);
    println!("   Tunnel apps (will use VPN): {:?}", tunnel_apps);
    println!("   Everything else (including testbench.exe) will BYPASS VPN");

    // Use the internet IP we captured BEFORE routes were applied
    println!("   Using saved internet IP: {} (captured before VPN routes)", original_internet_ip);

    let split_config = SplitTunnelConfig::new(
        tunnel_apps,
        vpn_config.assigned_ip.clone(),
        original_internet_ip.clone(),
        interface_luid,
    );

    if let Err(e) = driver.configure(split_config) {
        println!("   ❌ Split tunnel configure failed: {}", e);
        let _ = driver.close();
        route_manager.remove_routes().ok();
        tunnel.stop();
        adapter.shutdown();
        return;
    }
    println!("   ✅ Split tunnel configured and started");

    // Wait for split tunnel to take effect
    std::thread::sleep(Duration::from_millis(500));

    // Step 10: Check IP again (should be ORIGINAL IP since testbench.exe bypasses)
    println!("\nStep 10: Checking IP (testbench.exe should bypass VPN)...");
    let split_ip = match get_public_ip() {
        Some(ip) => {
            println!("   Current IP: {}", ip);
            ip
        }
        None => {
            println!("   ❌ Failed to get public IP");
            "unknown".to_string()
        }
    };

    // Results
    println!("\n════════════════════════════════════════");
    println!("         TRAFFIC ROUTING RESULTS        ");
    println!("════════════════════════════════════════\n");
    println!("   Original IP (no VPN):           {}", original_ip);
    println!("   IP after VPN (split mode):      {}", vpn_ip);
    println!("   IP with split tunnel active:    {}", split_ip);
    println!();

    // In split tunnel mode:
    // - Non-tunnel apps should ALWAYS bypass VPN (use original IP)
    // - Only tunnel apps (Roblox) would use VPN
    // Since testbench.exe is NOT a tunnel app, both vpn_ip and split_ip should be original_ip

    if vpn_ip == original_ip && split_ip == original_ip {
        println!("   ✅ SPLIT TUNNEL MODE WORKING!");
        println!("   - testbench.exe (non-tunnel app) bypasses VPN correctly");
        println!("   - Traffic uses original IP: {}", original_ip);
        println!("   - Only Roblox apps would go through VPN tunnel");
    } else if vpn_ip != original_ip {
        println!("   ⚠ VPN ROUTING UNEXPECTED");
        println!("   - Split tunnel mode should NOT add default VPN route");
        println!("   - But traffic went through VPN (IP: {})", vpn_ip);
        println!("   - Check if split_tunnel_mode is enabled in routes");
    } else if split_ip != original_ip {
        println!("   ⚠ SPLIT TUNNEL INTERCEPTOR ISSUE");
        println!("   - Non-tunnel apps should bypass VPN");
        println!("   - But IP changed after interceptor: {}", split_ip);
    } else {
        println!("   ⚠ UNEXPECTED RESULTS");
    }

    println!("\n════════════════════════════════════════\n");

    // Cleanup
    println!("Cleaning up...");
    let _ = driver.close();
    let _ = route_manager.remove_routes();
    tunnel.stop();
    adapter.shutdown();
    println!("   ✅ Cleanup complete");
}

fn parse_ip_cidr(ip_cidr: &str) -> Result<(std::net::Ipv4Addr, u8), String> {
    let parts: Vec<&str> = ip_cidr.split('/').collect();
    let ip: std::net::Ipv4Addr = parts[0].parse().map_err(|e| format!("Invalid IP: {}", e))?;
    let cidr: u8 = if parts.len() > 1 {
        parts[1].parse().unwrap_or(24)
    } else {
        24
    };
    Ok((ip, cidr))
}

fn get_interface_index(name: &str) -> Result<u32, String> {
    use std::process::Command;

    let output = Command::new("powershell")
        .args(["-Command", &format!(
            "(Get-NetAdapter -Name '{}' -ErrorAction SilentlyContinue).ifIndex",
            name
        )])
        .output()
        .map_err(|e| e.to_string())?;

    if output.status.success() {
        let index_str = String::from_utf8_lossy(&output.stdout).trim().to_string();
        index_str.parse().map_err(|e| format!("Parse error: {}", e))
    } else {
        Err("Adapter not found".to_string())
    }
}

fn check_driver_status() {
    println!("═══ Driver Status ═══\n");

    // Check if ndisapi driver service exists (NDISRD)
    let output = std::process::Command::new("sc")
        .args(["query", "NDISRD"])
        .output();

    match output {
        Ok(out) => {
            let stdout = String::from_utf8_lossy(&out.stdout);
            let stderr = String::from_utf8_lossy(&out.stderr);

            if out.status.success() {
                println!("✅ NDISRD (Windows Packet Filter) service found:\n");
                println!("{}", stdout);

                // Also get service config
                if let Ok(config_out) = std::process::Command::new("sc")
                    .args(["qc", "NDISRD"])
                    .output()
                {
                    println!("Service Configuration:");
                    println!("{}", String::from_utf8_lossy(&config_out.stdout));
                }
            } else {
                println!("❌ NDISRD driver service not found or not accessible");
                println!("Error: {}", stderr);
                println!("\nPlease install Windows Packet Filter driver from:");
                println!("  https://www.ntkernel.com/windows-packet-filter/");
            }
        }
        Err(e) => {
            println!("❌ Failed to query service: {}", e);
        }
    }

    // Check if ndisapi driver file exists
    let driver_paths = [
        r"C:\Windows\System32\drivers\ndisrd.sys",
        r"C:\Program Files\SwiftTunnel\drivers\ndisrd.sys",
    ];

    let mut driver_found = false;
    for driver_path in &driver_paths {
        if std::path::Path::new(driver_path).exists() {
            println!("✅ Driver file exists: {}", driver_path);
            driver_found = true;
            break;
        }
    }

    if !driver_found {
        println!("❌ Driver file NOT found in any expected location");
        for path in &driver_paths {
            println!("   Checked: {}", path);
        }
    }

    println!();
}

fn test_split_tunnel_driver() {
    println!("═══ Split Tunnel Driver Test (ndisapi) ═══\n");

    println!("1. Creating driver instance...");
    let mut driver = SplitTunnelDriver::new();

    // Check availability (static method)
    println!("\n2. Checking driver availability...");
    if SplitTunnelDriver::is_available() {
        println!("   ✅ ndisapi driver is available");
    } else {
        println!("   ❌ ndisapi driver NOT available");
        println!("\n   Please install Windows Packet Filter driver:");
        println!("   https://www.ntkernel.com/windows-packet-filter/");
        return;
    }

    // Open
    println!("\n3. Opening driver...");
    match driver.open() {
        Ok(_) => {
            println!("   ✅ Driver opened");
        }
        Err(e) => {
            println!("   ❌ Open failed: {}", e);
            return;
        }
    }

    // Initialize
    println!("\n4. Initializing driver...");
    match driver.initialize() {
        Ok(_) => {
            println!("   ✅ Driver initialized");
            println!("   Driver state: {:?}", driver.state());
        }
        Err(e) => {
            println!("   ❌ Initialize failed: {}", e);
            return;
        }
    }

    // Configure with test apps
    println!("\n5. Configuring with test apps...");
    let presets = HashSet::from([GamePreset::Roblox]);
    let tunnel_apps = get_apps_for_preset_set(&presets);
    println!("   Tunnel apps: {:?}", tunnel_apps);

    let config = SplitTunnelConfig::new(
        tunnel_apps,
        "10.64.0.1".to_string(),
        "192.168.1.1".to_string(),
        0,
    );

    match driver.configure(config) {
        Ok(_) => {
            println!("   ✅ Configuration applied and interception started");
            println!("   Driver state: {:?}", driver.state());
        }
        Err(e) => {
            println!("   ❌ Configure failed: {}", e);
        }
    }

    // Cleanup
    println!("\n6. Cleaning up...");
    let _ = driver.close();
    println!("   ✅ Driver closed");

    println!();
}

fn test_full_split_tunnel_flow() {
    println!("═══ Full Split Tunnel Flow Test ═══\n");
    println!("This tests: Initialize → Configure → Start → Stop\n");

    // Step 1: Create and initialize driver
    println!("Step 1: Creating and initializing driver...");
    let mut driver = SplitTunnelDriver::new();

    if !SplitTunnelDriver::is_available() {
        println!("   ❌ ndisapi driver not available");
        return;
    }
    println!("   ✅ Driver available");

    if let Err(e) = driver.open() {
        println!("   ❌ Open failed: {}", e);
        return;
    }
    println!("   ✅ Driver opened");

    if let Err(e) = driver.initialize() {
        println!("   ❌ Initialize failed: {}", e);
        return;
    }
    println!("   ✅ Driver initialized");

    // Step 2: Configure split tunnel with Roblox apps
    println!("\nStep 2: Configuring split tunnel with Roblox apps...");
    let presets = HashSet::from([GamePreset::Roblox]);
    let tunnel_apps = get_apps_for_preset_set(&presets);
    println!("   Tunnel apps: {:?}", tunnel_apps);

    // Need dummy values for IP and LUID since we're not actually connected
    let tunnel_ip = "10.64.0.1".to_string();
    let tunnel_luid: u64 = 0;

    // Get real internet interface IP (or use dummy for testing)
    let internet_ip = match get_internet_interface_ip() {
        Ok(ip) => ip.to_string(),
        Err(_) => "192.168.1.1".to_string(), // fallback for testing
    };
    println!("   Internet IP: {}", internet_ip);

    let config = SplitTunnelConfig::new(tunnel_apps, tunnel_ip, internet_ip, tunnel_luid);

    match driver.configure(config) {
        Ok(_) => {
            println!("   ✅ Split tunnel configured successfully!");
            println!("   Driver state: {:?}", driver.state());
        }
        Err(e) => {
            println!("   ❌ Configure failed: {}", e);
            let _ = driver.close();
            return;
        }
    }

    // Step 3: Show process tracker status
    println!("\nStep 3: Checking process tracker...");
    let running_apps = driver.get_running_tunnel_apps();
    if running_apps.is_empty() {
        println!("   No tunnel apps currently running (expected if Roblox isn't open)");
    } else {
        println!("   Running tunnel apps:");
        for app in &running_apps {
            println!("   - {}", app);
        }
    }

    // Step 4: Cleanup
    println!("\nStep 4: Cleaning up...");
    let _ = driver.close();
    println!("   ✅ Driver closed");

    println!("\n════════════════════════════════════════");
    println!("Full split tunnel flow test complete!");
    println!("════════════════════════════════════════\n");
}

fn show_system_info() {
    println!("═══ System Info ═══\n");

    // OS info
    println!("Operating System:");
    if let Ok(output) = std::process::Command::new("cmd")
        .args(["/c", "ver"])
        .output()
    {
        println!("  {}", String::from_utf8_lossy(&output.stdout).trim());
    }

    // Check admin rights
    println!("\nAdmin Rights:");
    let is_admin = is_elevated();
    if is_admin {
        println!("  ✅ Running as Administrator");
    } else {
        println!("  ❌ NOT running as Administrator");
        println!("     Some features require admin rights!");
    }

    // Network adapters
    println!("\nNetwork Adapters:");
    if let Ok(output) = std::process::Command::new("netsh")
        .args(["interface", "show", "interface"])
        .output()
    {
        println!("{}", String::from_utf8_lossy(&output.stdout));
    }

    // Check for Wintun
    println!("Wintun DLL:");
    let wintun_paths = [
        r"C:\Program Files\SwiftTunnel\wintun.dll",
        r".\wintun.dll",
    ];
    let mut found = false;
    for path in wintun_paths {
        if std::path::Path::new(path).exists() {
            println!("  ✅ Found: {}", path);
            found = true;
            break;
        }
    }
    if !found {
        println!("  ❌ wintun.dll not found");
    }

    println!();
}

fn is_elevated() -> bool {
    use std::mem;
    use windows::Win32::Foundation::HANDLE;
    use windows::Win32::Security::{GetTokenInformation, TokenElevation, TOKEN_ELEVATION, TOKEN_QUERY};
    use windows::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};

    unsafe {
        let mut token_handle = HANDLE::default();
        if OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token_handle).is_err() {
            return false;
        }

        let mut elevation = TOKEN_ELEVATION::default();
        let mut size = 0u32;

        let result = GetTokenInformation(
            token_handle,
            TokenElevation,
            Some(&mut elevation as *mut _ as *mut _),
            mem::size_of::<TOKEN_ELEVATION>() as u32,
            &mut size,
        );

        let _ = windows::Win32::Foundation::CloseHandle(token_handle);

        result.is_ok() && elevation.TokenIsElevated != 0
    }
}

/// Test ping functionality - fetches server list and pings all servers
fn test_ping_functionality() {
    use swifttunnel_fps_booster::vpn::servers::load_server_list;

    println!("═══ Ping Functionality Test ═══\n");

    let rt = Runtime::new().expect("Failed to create tokio runtime");

    // Step 1: Fetch server list
    println!("Step 1: Fetching server list from API...");
    let (servers, regions, source) = match rt.block_on(load_server_list()) {
        Ok(data) => {
            println!("   ✅ Loaded {} servers, {} regions from {}", data.0.len(), data.1.len(), data.2);
            data
        }
        Err(e) => {
            println!("   ❌ Failed to load server list: {}", e);
            return;
        }
    };

    // Step 2: Test raw ping command
    println!("\nStep 2: Testing raw ping command...");
    let test_ip = servers.first().map(|s| s.ip.as_str()).unwrap_or("1.1.1.1");
    println!("   Testing ping to: {}", test_ip);

    let ping_output = std::process::Command::new("ping")
        .args(["-n", "1", "-w", "2000", test_ip])
        .output();

    match ping_output {
        Ok(output) => {
            let stdout = String::from_utf8_lossy(&output.stdout);
            let stderr = String::from_utf8_lossy(&output.stderr);
            println!("   Status: {:?}", output.status);
            println!("   Stdout: {}", stdout.lines().take(5).collect::<Vec<_>>().join("\n          "));
            if !stderr.is_empty() {
                println!("   Stderr: {}", stderr.trim());
            }

            // Test parse function
            if let Some(ms) = parse_ping_output_test(&stdout) {
                println!("   ✅ Parsed latency: {}ms", ms);
            } else {
                println!("   ❌ Failed to parse latency from output");
            }
        }
        Err(e) => {
            println!("   ❌ Ping command failed: {}", e);
        }
    }

    // Step 3: Test server mapping
    println!("\nStep 3: Testing server-to-region mapping...");
    for region in regions.iter().take(3) {
        println!("\n   Region '{}' ({}):", region.id, region.name);
        println!("   Server IDs in region: {:?}", region.servers);

        let server_ips: Vec<(String, String)> = region.servers.iter()
            .filter_map(|server_id| {
                servers.iter()
                    .find(|s| &s.region == server_id)
                    .map(|s| (server_id.clone(), s.ip.clone()))
            })
            .collect();

        println!("   Mapped server IPs: {:?}", server_ips);

        if server_ips.is_empty() {
            println!("   ⚠ No servers found for this region!");
        }
    }

    // Step 4: Ping first 3 servers from first region
    println!("\nStep 4: Pinging servers in first region...");
    if let Some(region) = regions.first() {
        println!("   Region: {} ({})", region.id, region.name);

        let server_ips: Vec<(String, String)> = region.servers.iter()
            .filter_map(|server_id| {
                servers.iter()
                    .find(|s| &s.region == server_id)
                    .map(|s| (server_id.clone(), s.ip.clone()))
            })
            .take(3)
            .collect();

        for (server_id, ip) in &server_ips {
            println!("\n   Pinging {} ({})...", server_id, ip);

            // Do 2 pings like the real code
            let mut total = 0u32;
            let mut count = 0u32;

            for ping_num in 0..2 {
                let output = std::process::Command::new("ping")
                    .args(["-n", "1", "-w", "1000", ip])
                    .output();

                match output {
                    Ok(out) => {
                        let stdout = String::from_utf8_lossy(&out.stdout);
                        if out.status.success() {
                            if let Some(ms) = parse_ping_output_test(&stdout) {
                                println!("      Ping {}: {}ms", ping_num + 1, ms);
                                total += ms;
                                count += 1;
                            } else {
                                println!("      Ping {}: success but parse failed", ping_num + 1);
                                println!("         Output: {}", stdout.lines().next().unwrap_or("(empty)"));
                            }
                        } else {
                            println!("      Ping {}: command failed (status: {})", ping_num + 1, out.status);
                        }
                    }
                    Err(e) => {
                        println!("      Ping {}: error: {}", ping_num + 1, e);
                    }
                }

                std::thread::sleep(Duration::from_millis(50));
            }

            if count > 0 {
                let avg = total / count;
                println!("      ✅ Average: {}ms ({} successful)", avg, count);
            } else {
                println!("      ❌ All pings failed");
            }
        }
    }

    println!("\n════════════════════════════════════════");
    println!("Ping functionality test complete!");
    println!("════════════════════════════════════════\n");
}

/// Parse ping output - copied from gui.rs for testing
fn parse_ping_output_test(stdout: &str) -> Option<u32> {
    for line in stdout.lines() {
        if let Some(idx) = line.find("time=") {
            let rest = &line[idx + 5..];
            if let Some(ms_idx) = rest.find("ms") {
                let time_str = rest[..ms_idx].trim();
                if let Ok(ms) = time_str.parse::<u32>() {
                    return Some(ms);
                }
            }
        } else if line.contains("time<1ms") {
            return Some(1);
        }
    }
    None
}

/// Test split tunnel with two apps:
/// - ip_checker.exe = TUNNEL (should show VPN IP)
/// - testbench.exe = BYPASS (should show original IP)
///
/// This tests the exact same flow as the GUI app.
fn test_split_tunnel_two_apps() {
    println!("╔═══════════════════════════════════════════════════════════════╗");
    println!("║    SPLIT TUNNEL TWO-APP TEST                                   ║");
    println!("║    ip_checker.exe = TUNNEL (VPN IP)                             ║");
    println!("║    testbench.exe  = BYPASS (Original IP)                        ║");
    println!("╚═══════════════════════════════════════════════════════════════╝\n");

    // Create tokio runtime
    let rt = Runtime::new().expect("Failed to create tokio runtime");

    // Find ip_checker.exe
    let ip_checker_path = find_ip_checker_exe();
    if ip_checker_path.is_none() {
        println!("❌ ip_checker.exe not found!");
        println!("   Build it with: cargo build --release --bin ip_checker");
        return;
    }
    let ip_checker_path = ip_checker_path.unwrap();
    println!("✅ Found ip_checker.exe: {}\n", ip_checker_path.display());

    // Step 1: Get original IP
    println!("Step 1: Getting original IPs BEFORE VPN...");
    let original_testbench_ip = match get_public_ip() {
        Some(ip) => {
            println!("   testbench.exe IP: {}", ip);
            ip
        }
        None => {
            println!("   ❌ Failed to get testbench IP");
            return;
        }
    };

    let original_ipchecker_ip = match run_ip_checker(&ip_checker_path) {
        Some(ip) => {
            println!("   ip_checker.exe IP: {}", ip);
            ip
        }
        None => {
            println!("   ❌ Failed to run ip_checker");
            return;
        }
    };

    if original_testbench_ip != original_ipchecker_ip {
        println!("   ⚠ IPs differ without VPN - unexpected!");
    } else {
        println!("   ✅ Both apps show same IP (expected)");
    }

    // Step 2: Authenticate
    println!("\nStep 2: Authenticating...");
    let auth_manager = match AuthManager::new() {
        Ok(m) => m,
        Err(e) => {
            println!("   ❌ Failed to create AuthManager: {}", e);
            return;
        }
    };

    let access_token = rt.block_on(async {
        if let Err(e) = auth_manager.sign_in(TESTBENCH_EMAIL, TESTBENCH_PASSWORD).await {
            println!("   ❌ Sign in failed: {}", e);
            return None;
        }
        match auth_manager.get_state() {
            AuthState::LoggedIn(session) => Some(session.access_token),
            _ => None,
        }
    });

    let access_token = match access_token {
        Some(t) => {
            println!("   ✅ Signed in");
            t
        }
        None => return,
    };

    // Step 3: Fetch VPN config
    println!("\nStep 3: Fetching VPN config...");
    let vpn_config = rt.block_on(async {
        match fetch_vpn_config(&access_token, TEST_REGION).await {
            Ok(config) => {
                println!("   ✅ Region: {}, Endpoint: {}", TEST_REGION, config.endpoint);
                Some(config)
            }
            Err(e) => {
                println!("   ❌ Failed: {}", e);
                None
            }
        }
    });

    let vpn_config = match vpn_config {
        Some(c) => c,
        None => return,
    };

    // Step 4: Create Wintun adapter
    println!("\nStep 4: Creating Wintun adapter...");
    let (ip, cidr) = match parse_ip_cidr(&vpn_config.assigned_ip) {
        Ok((ip, cidr)) => (ip, cidr),
        Err(e) => {
            println!("   ❌ Failed: {}", e);
            return;
        }
    };

    let adapter = match WintunAdapter::create(std::net::IpAddr::V4(ip), cidr) {
        Ok(a) => {
            println!("   ✅ Adapter created");
            std::sync::Arc::new(a)
        }
        Err(e) => {
            println!("   ❌ Failed: {}", e);
            return;
        }
    };

    if !vpn_config.dns.is_empty() {
        let _ = adapter.set_dns(&vpn_config.dns);
    }
    let interface_luid = adapter.get_luid();

    // Step 5: Start WireGuard tunnel
    println!("\nStep 5: Starting WireGuard tunnel...");
    let tunnel = match WireguardTunnel::new(vpn_config.clone()) {
        Ok(t) => {
            println!("   ✅ Tunnel created");
            std::sync::Arc::new(t)
        }
        Err(e) => {
            println!("   ❌ Failed: {}", e);
            adapter.shutdown();
            return;
        }
    };

    let tunnel_clone = tunnel.clone();
    let adapter_clone = adapter.clone();
    rt.spawn(async move {
        if let Err(e) = tunnel_clone.start(adapter_clone).await {
            log::error!("Tunnel error: {}", e);
        }
    });

    println!("   Waiting for handshake...");
    std::thread::sleep(Duration::from_secs(3));

    // Step 6: Get internet IP before routes
    println!("\nStep 6: Capturing internet IP (before routes)...");
    let original_internet_ip = match get_internet_interface_ip() {
        Ok(ip) => {
            println!("   ✅ Internet interface IP: {}", ip);
            ip.to_string()
        }
        Err(e) => {
            println!("   ❌ Failed: {}", e);
            tunnel.stop();
            adapter.shutdown();
            return;
        }
    };

    // Step 7: Setup routes (split tunnel mode)
    println!("\nStep 7: Setting up routes (SPLIT TUNNEL MODE)...");
    let server_ip: std::net::Ipv4Addr = vpn_config.endpoint
        .split(':')
        .next()
        .unwrap_or("0.0.0.0")
        .parse()
        .unwrap_or(std::net::Ipv4Addr::new(0, 0, 0, 0));

    let if_index = get_interface_index("SwiftTunnel").unwrap_or(1);
    let mut route_manager = RouteManager::new(server_ip, if_index);
    route_manager.set_split_tunnel_mode(true);

    if let Err(e) = route_manager.apply_routes() {
        println!("   ⚠ Failed to apply routes: {}", e);
    } else {
        println!("   ✅ Routes applied (split tunnel mode)");
    }
    std::thread::sleep(Duration::from_secs(1));

    // Step 8: Setup split tunnel with ip_checker.exe as TUNNEL app
    println!("\nStep 8: Setting up split tunnel...");
    println!("   TUNNEL apps: [ip_checker.exe]");
    println!("   BYPASS apps: everything else (including testbench.exe)");

    let mut driver = SplitTunnelDriver::new();

    if !SplitTunnelDriver::is_available() {
        println!("   ❌ ndisapi driver not available");
        route_manager.remove_routes().ok();
        tunnel.stop();
        adapter.shutdown();
        return;
    }

    if let Err(e) = driver.open() {
        println!("   ❌ Open failed: {}", e);
        route_manager.remove_routes().ok();
        tunnel.stop();
        adapter.shutdown();
        return;
    }

    if let Err(e) = driver.initialize() {
        println!("   ❌ Initialize failed: {}", e);
        route_manager.remove_routes().ok();
        tunnel.stop();
        adapter.shutdown();
        return;
    }

    // Set Wintun injection context
    let wg_ctx = std::sync::Arc::new(WireguardContext {
        session: adapter.session(),
        packets_injected: std::sync::atomic::AtomicU64::new(0),
    });
    driver.set_wireguard_context(wg_ctx.clone());

    // TUNNEL ONLY ip_checker.exe
    let tunnel_apps = vec!["ip_checker.exe".to_string()];

    let split_config = SplitTunnelConfig::new(
        tunnel_apps,
        vpn_config.assigned_ip.clone(),
        original_internet_ip.clone(),
        interface_luid,
    );

    if let Err(e) = driver.configure(split_config) {
        println!("   ❌ Configure failed: {}", e);
        let _ = driver.close();
        route_manager.remove_routes().ok();
        tunnel.stop();
        adapter.shutdown();
        return;
    }
    println!("   ✅ Split tunnel started");

    // Set up VpnEncryptContext for direct encryption (bypasses Wintun injection)
    // This is critical for split tunnel - without it, tunnel packets won't actually go through VPN
    if let Some(tunn) = tunnel.get_tunn() {
        let endpoint = tunnel.get_endpoint();
        match std::net::UdpSocket::bind("0.0.0.0:0") {
            Ok(socket) => {
                if let Err(e) = socket.connect(endpoint) {
                    println!("   ⚠ Failed to connect encryption socket: {}", e);
                } else {
                    let ctx = VpnEncryptContext {
                        tunn,
                        socket: std::sync::Arc::new(socket),
                        server_addr: endpoint,
                    };
                    driver.set_vpn_encrypt_context(ctx);
                    println!("   ✅ VPN encrypt context set (direct encryption enabled)");
                }
            }
            Err(e) => {
                println!("   ⚠ Failed to create encryption socket: {}", e);
                println!("   Falling back to Wintun injection (may not work for tunnel apps)");
            }
        }
    } else {
        println!("   ⚠ Could not get tunnel context (falling back to Wintun injection)");
    }

    // Set up inbound handler so VPN responses get injected to physical adapter
    if let Some(handler) = driver.create_inbound_handler() {
        println!("   ✅ Inbound handler set on tunnel");
        tunnel.set_inbound_handler(handler);
    } else {
        println!("   ⚠ No inbound handler available");
    }

    // Wait for interceptor to start
    std::thread::sleep(Duration::from_secs(2));

    // Step 9: Test IP routing
    println!("\n╔═══════════════════════════════════════════════════════════════╗");
    println!("║    TESTING IP ROUTING                                          ║");
    println!("╚═══════════════════════════════════════════════════════════════╝\n");

    // Test testbench.exe (should BYPASS)
    println!("Testing testbench.exe (expected: BYPASS = original IP)...");
    let testbench_ip = match get_public_ip() {
        Some(ip) => {
            println!("   IP: {}", ip);
            ip
        }
        None => {
            println!("   ❌ Failed to get IP");
            "unknown".to_string()
        }
    };

    // Test ip_checker.exe (should TUNNEL)
    println!("\nTesting ip_checker.exe (expected: TUNNEL = VPN IP)...");
    let ipchecker_ip = match run_ip_checker(&ip_checker_path) {
        Some(ip) => {
            println!("   IP: {}", ip);
            ip
        }
        None => {
            println!("   ❌ Failed to run ip_checker");
            "unknown".to_string()
        }
    };

    // Results
    println!("\n╔═══════════════════════════════════════════════════════════════╗");
    println!("║                    RESULTS                                      ║");
    println!("╚═══════════════════════════════════════════════════════════════╝\n");

    println!("   Original IP (before VPN):    {}", original_testbench_ip);
    println!("   testbench.exe IP (bypass):   {}", testbench_ip);
    println!("   ip_checker.exe IP (tunnel):  {}", ipchecker_ip);
    println!();

    let testbench_bypassed = testbench_ip == original_testbench_ip;
    let ipchecker_tunneled = ipchecker_ip != original_testbench_ip;

    if testbench_bypassed && ipchecker_tunneled {
        println!("   ✅✅ SUCCESS! Split tunnel is WORKING!");
        println!("      - testbench.exe bypassed VPN (original IP)");
        println!("      - ip_checker.exe went through VPN (different IP)");
    } else if !testbench_bypassed && !ipchecker_tunneled {
        println!("   ❌❌ FAILURE: Neither bypass nor tunnel working");
        println!("      - Both apps show same IP, nothing changed");
        if testbench_ip == original_testbench_ip {
            println!("      - Both are using original IP (VPN not routing traffic at all)");
        } else {
            println!("      - Both are using VPN IP (no split, all traffic tunneled)");
        }
    } else if !testbench_bypassed {
        println!("   ⚠ PARTIAL: Bypass not working");
        println!("      - testbench.exe should show original IP but shows: {}", testbench_ip);
        println!("      - ip_checker.exe correctly tunneled");
    } else if !ipchecker_tunneled {
        println!("   ⚠ PARTIAL: Tunnel not working");
        println!("      - testbench.exe correctly bypassed");
        println!("      - ip_checker.exe should show VPN IP but shows: {}", ipchecker_ip);
    }

    // Show throughput stats
    if let Some(stats) = driver.get_throughput_stats() {
        println!("\n   Throughput stats:");
        println!("      TX (to VPN): {} bytes", stats.bytes_tx.load(std::sync::atomic::Ordering::Relaxed));
        println!("      RX (from VPN): {} bytes", stats.bytes_rx.load(std::sync::atomic::Ordering::Relaxed));
    }

    // Cleanup
    println!("\nCleaning up...");
    let _ = driver.close();
    let _ = route_manager.remove_routes();
    tunnel.stop();
    adapter.shutdown();
    println!("   ✅ Done");
}

/// Find ip_checker.exe in common locations
fn find_ip_checker_exe() -> Option<std::path::PathBuf> {
    let locations = [
        // Same directory as testbench
        std::env::current_exe()
            .ok()
            .and_then(|p| p.parent().map(|p| p.join("ip_checker.exe"))),
        // Release directory
        Some(std::path::PathBuf::from("target/release/ip_checker.exe")),
        // Debug directory
        Some(std::path::PathBuf::from("target/debug/ip_checker.exe")),
        // Current directory
        Some(std::path::PathBuf::from("ip_checker.exe")),
    ];

    for loc in locations.into_iter().flatten() {
        if loc.exists() {
            return Some(loc);
        }
    }
    None
}

/// Run ip_checker.exe and capture its IP output
fn run_ip_checker(path: &std::path::Path) -> Option<String> {
    use std::process::Command;

    let output = Command::new(path)
        .output()
        .ok()?;

    if !output.status.success() {
        return None;
    }

    let stdout = String::from_utf8_lossy(&output.stdout);

    // Parse output - look for "Your public IP: x.x.x.x"
    for line in stdout.lines() {
        if line.contains("Your public IP:") {
            if let Some(ip) = line.split(':').last() {
                let ip = ip.trim();
                if !ip.is_empty() && ip.chars().all(|c| c.is_ascii_digit() || c == '.') {
                    return Some(ip.to_string());
                }
            }
        }
    }

    None
}
