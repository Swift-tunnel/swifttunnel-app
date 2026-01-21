//! SwiftTunnel CLI Testbench
//!
//! A headless CLI tool for testing VPN and split tunnel functionality
//! without requiring a GUI or user interaction.
//!
//! Usage:
//!   testbench              - Run all tests
//!   testbench driver       - Check driver status only
//!   testbench init         - Test driver initialization
//!   testbench wfp          - Test WFP setup
//!   testbench full         - Test full split tunnel flow
//!   testbench info         - Show system info

use std::collections::HashSet;
use std::env;

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
    println!("║          SwiftTunnel CLI Testbench v0.5.17                 ║");
    println!("║          Headless testing for VPN & Split Tunnel           ║");
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
        "wfp" => {
            test_wfp_setup();
        }
        "full" => {
            test_full_split_tunnel_flow();
        }
        "info" => {
            show_system_info();
        }
        "all" => {
            println!("Running all tests...\n");
            check_driver_status();
            test_split_tunnel_driver();
            test_wfp_setup();
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
    println!("  wfp      Test WFP setup");
    println!("  full     Test full split tunnel flow");
    println!("  info     Show system info");
    println!("  help     Show this help message");
}

fn check_driver_status() {
    println!("═══ Driver Status ═══\n");

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
    println!("═══ Split Tunnel Driver Test ═══\n");

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
                    let _ = driver.close();
                    println!("   ✅ Driver closed");
                }
                Err(e) => {
                    println!("   ❌ Initialize failed: {}", e);
                    let _ = driver.close();
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
    println!("═══ WFP Setup Test ═══\n");

    println!("1. Opening WFP engine...");
    match WfpEngine::open() {
        Ok(engine) => {
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
    println!("═══ Full Split Tunnel Flow Test ═══\n");
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
            let _ = driver.close();
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
            let _ = driver.close();
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
