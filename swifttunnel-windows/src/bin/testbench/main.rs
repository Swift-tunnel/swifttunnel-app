//! SwiftTunnel CLI Testbench
//!
//! A headless CLI tool for testing VPN and split tunnel functionality
//! without requiring a GUI or OpenGL support.

use std::collections::HashSet;
use std::io::{self, Write};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;

use anyhow::Result;
use tokio::runtime::Runtime;

// Import from main crate
use swifttunnel_fps_booster::vpn::connection::VpnConnection;
use swifttunnel_fps_booster::vpn::VpnState;
use swifttunnel_fps_booster::vpn::split_tunnel::{SplitTunnelDriver, SplitTunnelConfig, GamePreset, get_apps_for_preset_set};
use swifttunnel_fps_booster::vpn::servers::DynamicServerList;
use swifttunnel_fps_booster::vpn::wfp::{WfpEngine, setup_wfp_for_split_tunnel};
use swifttunnel_fps_booster::auth::manager::AuthManager;
use swifttunnel_fps_booster::auth::AuthState;

fn main() -> Result<()> {
    // Initialize logging
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info"))
        .format_timestamp_millis()
        .init();

    println!("\n╔════════════════════════════════════════════════════════════╗");
    println!("║          SwiftTunnel CLI Testbench v0.5.16                 ║");
    println!("║          Headless testing for VPN & Split Tunnel           ║");
    println!("╚════════════════════════════════════════════════════════════╝\n");

    // Create tokio runtime
    let rt = Runtime::new()?;

    // Main menu loop
    loop {
        print_menu();

        let choice = read_input("Select option: ");

        match choice.trim() {
            "1" => check_driver_status(),
            "2" => rt.block_on(check_auth_status()),
            "3" => rt.block_on(list_servers()),
            "4" => rt.block_on(test_vpn_connection(&rt)),
            "5" => test_split_tunnel_driver(),
            "6" => show_system_info(),
            "7" => rt.block_on(ping_regions()),
            "8" => test_wfp_setup(),
            "0" | "q" | "quit" | "exit" => {
                println!("\nExiting testbench. Goodbye!");
                break;
            }
            _ => println!("\n⚠ Invalid option. Please try again.\n"),
        }
    }

    Ok(())
}

fn print_menu() {
    println!("┌──────────────────────────────────────┐");
    println!("│            MAIN MENU                 │");
    println!("├──────────────────────────────────────┤");
    println!("│  1. Check Driver Status              │");
    println!("│  2. Check Auth Status                │");
    println!("│  3. List VPN Servers                 │");
    println!("│  4. Test VPN Connection              │");
    println!("│  5. Test Split Tunnel Driver         │");
    println!("│  6. Show System Info                 │");
    println!("│  7. Ping All Regions                 │");
    println!("│  8. Test WFP Setup                   │");
    println!("│  0. Exit                             │");
    println!("└──────────────────────────────────────┘");
}

fn read_input(prompt: &str) -> String {
    print!("{}", prompt);
    io::stdout().flush().unwrap();

    let mut input = String::new();
    io::stdin().read_line(&mut input).unwrap();
    input
}

fn check_driver_status() {
    println!("\n═══ Driver Status ═══\n");

    // Check if driver service exists
    let output = std::process::Command::new("sc")
        .args(["query", "MullvadSplitTunnel"])
        .output();

    match output {
        Ok(out) => {
            let stdout = String::from_utf8_lossy(&out.stdout);
            let stderr = String::from_utf8_lossy(&out.stderr);

            if out.status.success() {
                println!("✅ MullvadSplitTunnel service found:\n");
                println!("{}", stdout);

                // Also get service config
                if let Ok(config_out) = std::process::Command::new("sc")
                    .args(["qc", "MullvadSplitTunnel"])
                    .output()
                {
                    println!("Service Configuration:");
                    println!("{}", String::from_utf8_lossy(&config_out.stdout));
                }
            } else {
                println!("❌ Driver service not found or not accessible");
                println!("Error: {}", stderr);
            }
        }
        Err(e) => {
            println!("❌ Failed to query service: {}", e);
        }
    }

    // Check if driver file exists
    let driver_path = r"C:\Program Files\SwiftTunnel\drivers\mullvad-split-tunnel.sys";
    if std::path::Path::new(driver_path).exists() {
        println!("✅ Driver file exists: {}", driver_path);
    } else {
        println!("❌ Driver file NOT found: {}", driver_path);
    }

    println!();
}

async fn check_auth_status() {
    println!("\n═══ Auth Status ═══\n");

    match AuthManager::new() {
        Ok(auth_manager) => {
            match auth_manager.get_state() {
                AuthState::LoggedIn { user_id, email, .. } => {
                    println!("✅ Logged in");
                    println!("   User ID: {}", user_id);
                    println!("   Email: {}", email);
                }
                AuthState::LoggedOut => {
                    println!("❌ Not logged in");
                }
                AuthState::Loading => {
                    println!("⏳ Loading auth state...");
                }
                AuthState::Error(e) => {
                    println!("❌ Auth error: {}", e);
                }
            }
        }
        Err(e) => {
            println!("❌ Failed to initialize auth manager: {}", e);
        }
    }

    println!();
}

async fn list_servers() {
    println!("\n═══ VPN Servers ═══\n");
    println!("Fetching server list from API...\n");

    let server_list = Arc::new(parking_lot::Mutex::new(DynamicServerList::new_empty()));

    // Fetch servers
    DynamicServerList::fetch(server_list.clone()).await;

    // Wait a moment for fetch to complete
    tokio::time::sleep(Duration::from_secs(2)).await;

    let list = server_list.lock();
    let regions = list.get_gaming_regions();

    if regions.is_empty() {
        println!("❌ No servers found. Check network connection or auth status.");
        if let Some(err) = list.error_message() {
            println!("   Error: {}", err);
        }
    } else {
        println!("Found {} regions:\n", regions.len());
        for region in &regions {
            println!("📍 {} ({})", region.name, region.id);
            println!("   Country: {} | Servers: {}", region.country_code, region.servers.len());
            for server in &region.servers {
                println!("   └─ {}", server);
            }
            println!();
        }
    }
}

async fn test_vpn_connection(rt: &Runtime) {
    println!("\n═══ VPN Connection Test ═══\n");

    // Check auth first
    match AuthManager::new() {
        Ok(auth_manager) => {
            if !matches!(auth_manager.get_state(), AuthState::LoggedIn { .. }) {
                println!("❌ Must be logged in to test VPN connection.");
                println!("   Use the GUI app to log in first, then run this test.");
                return;
            }
        }
        Err(e) => {
            println!("❌ Failed to check auth: {}", e);
            return;
        }
    }

    let region = read_input("Enter region ID (e.g., 'singapore', 'tokyo'): ");
    let region = region.trim();

    if region.is_empty() {
        println!("❌ No region specified.");
        return;
    }

    let server = read_input("Enter server ID (or press Enter for first server): ");
    let server = server.trim();
    let server_id = if server.is_empty() { region.to_string() } else { server.to_string() };

    println!("\nConnecting to {} (server: {})...", region, server_id);

    let running = Arc::new(AtomicBool::new(true));
    let r = running.clone();

    // Handle Ctrl+C
    ctrlc_handler(move || {
        r.store(false, Ordering::SeqCst);
    });

    // Create VPN connection
    let presets = HashSet::from([GamePreset::Roblox]);
    let tunnel_apps = get_apps_for_preset_set(&presets);
    let vpn = VpnConnection::new();

    // Connect
    match vpn.connect(region, &server_id, tunnel_apps).await {
        Ok(_) => {
            println!("✅ VPN connected successfully!");
            println!("\nConnection active. Press Ctrl+C to disconnect...\n");

            // Monitor connection
            while running.load(Ordering::SeqCst) {
                let state = vpn.state();
                match state.status {
                    VpnState::Connected => {
                        print!("\r🟢 Connected | Split Tunnel: {} | Processes: {}   ",
                            if state.split_tunnel_active { "Active" } else { "Inactive" },
                            state.tunneled_processes.len()
                        );
                        io::stdout().flush().unwrap();
                    }
                    VpnState::Disconnected => {
                        println!("\n🔴 Disconnected");
                        break;
                    }
                    _ => {}
                }
                tokio::time::sleep(Duration::from_secs(1)).await;
            }

            println!("\n\nDisconnecting...");
            vpn.disconnect().await;
            println!("✅ Disconnected.");
        }
        Err(e) => {
            println!("❌ Connection failed: {}", e);
        }
    }

    println!();
}

fn test_split_tunnel_driver() {
    println!("\n═══ Split Tunnel Driver Test ═══\n");

    println!("1. Opening driver handle...");
    let mut driver = SplitTunnelDriver::new();

    match driver.open() {
        Ok(_) => {
            println!("   ✅ Driver handle opened");

            println!("\n2. Initializing driver (registering WFP callouts)...");
            match driver.initialize() {
                Ok(_) => {
                    println!("   ✅ Driver initialized");

                    println!("\n3. Configuring split tunnel...");
                    // Get Roblox apps
                    let presets = HashSet::from([GamePreset::Roblox]);
                    let tunnel_apps = get_apps_for_preset_set(&presets);

                    println!("   Tunnel apps: {:?}", tunnel_apps);

                    // Create config
                    let config = SplitTunnelConfig::new(tunnel_apps);

                    match driver.configure(config) {
                        Ok(_) => {
                            println!("   ✅ Split tunnel configured");

                            println!("\n4. Driver state: {:?}", driver.state());

                            println!("\n5. Cleaning up...");
                            driver.close();
                            println!("   ✅ Driver closed");
                        }
                        Err(e) => {
                            println!("   ❌ Configure failed: {}", e);
                            driver.close();
                        }
                    }
                }
                Err(e) => {
                    println!("   ❌ Initialize failed: {}", e);
                    driver.close();
                }
            }
        }
        Err(e) => {
            println!("   ❌ Failed to open driver: {}", e);
            println!("\n   This usually means:");
            println!("   - Driver service is not running (run: sc start MullvadSplitTunnel)");
            println!("   - Not running as Administrator");
        }
    }

    println!();
}

fn show_system_info() {
    println!("\n═══ System Info ═══\n");

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

async fn ping_regions() {
    println!("\n═══ Ping All Regions ═══\n");

    let server_list = Arc::new(parking_lot::Mutex::new(DynamicServerList::new_empty()));
    DynamicServerList::fetch(server_list.clone()).await;
    tokio::time::sleep(Duration::from_secs(2)).await;

    let list = server_list.lock();
    let regions = list.get_gaming_regions();

    if regions.is_empty() {
        println!("❌ No regions available. Check auth/network.");
        return;
    }

    println!("Pinging {} regions...\n", regions.len());

    for region in &regions {
        print!("  {} ({})... ", region.name, region.id);
        io::stdout().flush().unwrap();

        // Get first server IP for ping
        if let Some(_server_id) = region.servers.first() {
            // Try to resolve server endpoint
            // For now just show placeholder
            println!("(ping not implemented in CLI yet)");
        } else {
            println!("no servers");
        }
    }

    println!();
}

fn test_wfp_setup() {
    println!("\n═══ WFP Setup Test ═══\n");

    println!("1. Opening WFP engine...");
    match WfpEngine::open() {
        Ok(mut engine) => {
            println!("   ✅ WFP engine opened");

            println!("\n2. Cleaning up legacy objects...");
            engine.cleanup_legacy_objects();
            println!("   ✅ Cleanup complete");

            println!("\n3. Testing setup_wfp_for_split_tunnel()...");
            // Use a dummy LUID
            match setup_wfp_for_split_tunnel(0) {
                Ok(_) => {
                    println!("   ✅ WFP setup completed successfully");
                }
                Err(e) => {
                    println!("   ❌ WFP setup failed: {}", e);
                }
            }
        }
        Err(e) => {
            println!("   ❌ Failed to open WFP engine: {}", e);
            println!("\n   This usually means:");
            println!("   - Not running as Administrator");
            println!("   - Windows Filtering Platform service issue");
        }
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

fn ctrlc_handler<F: FnOnce() + Send + 'static>(handler: F) {
    let handler = std::sync::Mutex::new(Some(handler));
    ctrlc::set_handler(move || {
        if let Some(h) = handler.lock().unwrap().take() {
            h();
        }
    }).ok();
}
