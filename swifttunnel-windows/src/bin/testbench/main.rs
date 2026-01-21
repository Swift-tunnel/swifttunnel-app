//! SwiftTunnel CLI Testbench
//!
//! A headless CLI tool for testing VPN and split tunnel functionality
//! without requiring a GUI or OpenGL support.

use std::collections::HashSet;
use std::io::{self, Write};

use anyhow::Result;

// Import from main crate - only what we need for driver testing
use swifttunnel_fps_booster::vpn::split_tunnel::{SplitTunnelDriver, GamePreset, get_apps_for_preset_set};
use swifttunnel_fps_booster::vpn::wfp::{WfpEngine, setup_wfp_for_split_tunnel};

fn main() -> Result<()> {
    // Initialize logging
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info"))
        .format_timestamp_millis()
        .init();

    println!("\n╔════════════════════════════════════════════════════════════╗");
    println!("║          SwiftTunnel CLI Testbench v0.5.16                 ║");
    println!("║          Headless testing for VPN & Split Tunnel           ║");
    println!("╚════════════════════════════════════════════════════════════╝\n");

    // Main menu loop
    loop {
        print_menu();

        let choice = read_input("Select option: ");

        match choice.trim() {
            "1" => check_driver_status(),
            "2" => test_split_tunnel_driver(),
            "3" => test_wfp_setup(),
            "4" => test_full_split_tunnel_flow(),
            "5" => show_system_info(),
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
    println!("│  2. Test Split Tunnel Driver         │");
    println!("│  3. Test WFP Setup                   │");
    println!("│  4. Test Full Split Tunnel Flow      │");
    println!("│  5. Show System Info                 │");
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
                    println!("   Driver state: {:?}", driver.state());

                    println!("\n3. Cleaning up...");
                    driver.close();
                    println!("   ✅ Driver closed");
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

fn test_full_split_tunnel_flow() {
    println!("\n═══ Full Split Tunnel Flow Test ═══\n");
    println!("This tests the complete flow: Driver → WFP → Configure\n");

    // Step 1: Open driver
    println!("Step 1: Opening driver handle...");
    let mut driver = SplitTunnelDriver::new();

    match driver.open() {
        Ok(_) => {
            println!("   ✅ Driver handle opened");
        }
        Err(e) => {
            println!("   ❌ Failed to open driver: {}", e);
            return;
        }
    }

    // Step 2: Initialize driver (registers WFP callouts)
    println!("\nStep 2: Initializing driver (registering WFP callouts)...");
    match driver.initialize() {
        Ok(_) => {
            println!("   ✅ Driver initialized - WFP callouts registered");
        }
        Err(e) => {
            println!("   ❌ Initialize failed: {}", e);
            driver.close();
            return;
        }
    }

    // Step 3: Setup WFP filters
    println!("\nStep 3: Setting up WFP for split tunnel...");
    match setup_wfp_for_split_tunnel(0) {
        Ok(wfp_engine) => {
            println!("   ✅ WFP setup complete");
            // Keep wfp_engine alive
            std::mem::forget(wfp_engine);
        }
        Err(e) => {
            println!("   ❌ WFP setup failed: {}", e);
            driver.close();
            return;
        }
    }

    // Step 4: Configure split tunnel with Roblox apps
    println!("\nStep 4: Configuring split tunnel with Roblox apps...");
    let presets = HashSet::from([GamePreset::Roblox]);
    let tunnel_apps = get_apps_for_preset_set(&presets);
    println!("   Tunnel apps: {:?}", tunnel_apps);

    // Need dummy values for IP and LUID since we're not actually connected
    let tunnel_ip = "10.64.0.1".to_string();
    let tunnel_luid: u64 = 0;

    use swifttunnel_fps_booster::vpn::split_tunnel::SplitTunnelConfig;
    let config = SplitTunnelConfig::new(tunnel_apps, tunnel_ip, tunnel_luid);

    match driver.configure(config) {
        Ok(_) => {
            println!("   ✅ Split tunnel configured successfully!");
            println!("\n   Final driver state: {:?}", driver.state());
        }
        Err(e) => {
            println!("   ❌ Configure failed: {}", e);
        }
    }

    // Step 5: Cleanup
    println!("\nStep 5: Cleaning up...");
    driver.close();
    println!("   ✅ Driver closed");

    println!("\n════════════════════════════════════════");
    println!("Full split tunnel flow test complete!");
    println!("════════════════════════════════════════\n");
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
