//! Split Tunnel Integration Test
//!
//! Full end-to-end test of split tunnel functionality:
//! 1. Fetches VPN config from API (or uses local config file)
//! 2. Creates VPN tunnel (Wintun + WireGuard)
//! 3. Sets up WFP (with STRICT error handling - fails if WFP fails)
//! 4. Configures split tunnel for test process
//! 5. Verifies driver state == ENGAGED (4)
//! 6. Runs test process to verify traffic routing
//!
//! Usage with API token:
//!   split_tunnel_integration_test.exe --token ACCESS_TOKEN --region singapore [--test-exe path]
//!
//! Usage with config file:
//!   split_tunnel_integration_test.exe --config config.json [--test-exe path]
//!
//! Requirements:
//!   - Administrator privileges
//!   - wintun.dll in working directory or exe directory
//!   - Mullvad split tunnel driver installed
//!
//! Exit codes:
//!   0 = Success (split tunnel routing verified)
//!   1 = Test failed (prerequisites, WFP, driver, or routing failure)
//!   2 = Usage error

use std::net::Ipv4Addr;
use std::process::Command;
use windows::core::{GUID, PCSTR};
use windows::Win32::Foundation::*;
use windows::Win32::NetworkManagement::WindowsFilteringPlatform::*;
use windows::Win32::Storage::FileSystem::*;
use windows::Win32::System::IO::DeviceIoControl;

const DEVICE_PATH: &str = r"\\.\MULLVADSPLITTUNNEL";
const ST_DEVICE_TYPE: u32 = 0x8000;
const METHOD_NEITHER: u32 = 3;
const METHOD_BUFFERED: u32 = 0;
const FILE_ANY_ACCESS: u32 = 0;

const fn ctl_code(device_type: u32, function: u32, method: u32, access: u32) -> u32 {
    (device_type << 16) | (access << 14) | (function << 2) | method
}

const IOCTL_ST_INITIALIZE: u32 = ctl_code(ST_DEVICE_TYPE, 1, METHOD_NEITHER, FILE_ANY_ACCESS);
const IOCTL_ST_REGISTER_PROCESSES: u32 = ctl_code(ST_DEVICE_TYPE, 3, METHOD_BUFFERED, FILE_ANY_ACCESS);
const IOCTL_ST_REGISTER_IP_ADDRESSES: u32 = ctl_code(ST_DEVICE_TYPE, 4, METHOD_BUFFERED, FILE_ANY_ACCESS);
const IOCTL_ST_SET_CONFIGURATION: u32 = ctl_code(ST_DEVICE_TYPE, 6, METHOD_BUFFERED, FILE_ANY_ACCESS);
#[allow(dead_code)]
const IOCTL_ST_CLEAR_CONFIGURATION: u32 = ctl_code(ST_DEVICE_TYPE, 8, METHOD_NEITHER, FILE_ANY_ACCESS);
const IOCTL_ST_GET_STATE: u32 = ctl_code(ST_DEVICE_TYPE, 9, METHOD_BUFFERED, FILE_ANY_ACCESS);
const IOCTL_ST_RESET: u32 = ctl_code(ST_DEVICE_TYPE, 11, METHOD_NEITHER, FILE_ANY_ACCESS);

/// Driver states
const STATE_NONE: u64 = 0;
const STATE_STARTED: u64 = 1;
const STATE_INITIALIZED: u64 = 2;
const STATE_READY: u64 = 3;
const STATE_ENGAGED: u64 = 4;
#[allow(dead_code)]
const STATE_ZOMBIE: u64 = 5;

/// API endpoint for VPN config
const API_BASE_URL: &str = "https://swifttunnel.net";

#[derive(Debug, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
#[allow(dead_code)]
struct VpnConfig {
    region: String,
    #[serde(rename = "serverEndpoint")]
    endpoint: String,
    server_public_key: String,
    private_key: String,
    assigned_ip: String,
    #[serde(default)]
    dns: Vec<String>,
}

/// Test result
#[derive(Debug)]
enum TestResult {
    Success { baseline_ip: String, vpn_ip: String },
    SplitTunnelNotRouting { baseline_ip: String, vpn_ip: String },
    WfpSetupFailed(String),
    DriverNotEngaged(u64),
    ConfigFetchFailed(String),
    PrerequisiteFailed(String),
    TestExeFailed(String),
}

struct TestConfig {
    access_token: Option<String>,
    region: String,
    config_file: Option<String>,
    test_exe: String,
}

#[tokio::main]
async fn main() {
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info")).init();

    println!("╔══════════════════════════════════════════════════════════════════╗");
    println!("║     SwiftTunnel Split Tunnel Integration Test                    ║");
    println!("║     Debug Mode - STRICT error handling enabled                   ║");
    println!("╚══════════════════════════════════════════════════════════════════╝\n");

    // Parse arguments
    let config = match parse_args() {
        Ok(c) => c,
        Err(e) => {
            eprintln!("ERROR: {}\n", e);
            print_usage();
            std::process::exit(2);
        }
    };

    // Run the test
    let result = run_test(config).await;

    // Print result and exit
    match result {
        TestResult::Success { baseline_ip, vpn_ip } => {
            println!("\n╔══════════════════════════════════════════════════════════════════╗");
            println!("║  ✅ SUCCESS: Split tunnel is routing traffic correctly!          ║");
            println!("╚══════════════════════════════════════════════════════════════════╝");
            println!("\n  Baseline IP: {}", baseline_ip);
            println!("  VPN IP:      {}", vpn_ip);
            println!("\n  Traffic from split tunnel apps is being routed through VPN.");
            std::process::exit(0);
        }
        TestResult::SplitTunnelNotRouting { baseline_ip, vpn_ip } => {
            println!("\n╔══════════════════════════════════════════════════════════════════╗");
            println!("║  ❌ FAIL: Split tunnel NOT routing traffic!                      ║");
            println!("╚══════════════════════════════════════════════════════════════════╝");
            println!("\n  Baseline IP: {}", baseline_ip);
            println!("  VPN IP:      {} (should be different!)", vpn_ip);
            println!("\n  The IP address did not change. Split tunnel is not working.");
            std::process::exit(1);
        }
        TestResult::WfpSetupFailed(e) => {
            println!("\n╔══════════════════════════════════════════════════════════════════╗");
            println!("║  ❌ FAIL: WFP setup failed (FATAL)                               ║");
            println!("╚══════════════════════════════════════════════════════════════════╝");
            println!("\n  Error: {}", e);
            println!("\n  WFP (Windows Filtering Platform) is required for split tunneling.");
            println!("  The Mullvad driver cannot route traffic without WFP filters.");
            std::process::exit(1);
        }
        TestResult::DriverNotEngaged(state) => {
            println!("\n╔══════════════════════════════════════════════════════════════════╗");
            println!("║  ❌ FAIL: Driver not in ENGAGED state                            ║");
            println!("╚══════════════════════════════════════════════════════════════════╝");
            println!("\n  Expected state: 4 (ENGAGED)");
            println!("  Actual state:   {} ({})", state, state_name(state));
            println!("\n  The driver must be in ENGAGED state to route traffic.");
            println!("  Check the diagnostic logs above for the exact failure point.");
            std::process::exit(1);
        }
        TestResult::ConfigFetchFailed(e) => {
            println!("\n╔══════════════════════════════════════════════════════════════════╗");
            println!("║  ❌ FAIL: Could not fetch VPN config                             ║");
            println!("╚══════════════════════════════════════════════════════════════════╝");
            println!("\n  Error: {}", e);
            std::process::exit(1);
        }
        TestResult::PrerequisiteFailed(e) => {
            println!("\n╔══════════════════════════════════════════════════════════════════╗");
            println!("║  ❌ FAIL: Prerequisites not met                                  ║");
            println!("╚══════════════════════════════════════════════════════════════════╝");
            println!("\n  Error: {}", e);
            std::process::exit(1);
        }
        TestResult::TestExeFailed(e) => {
            println!("\n╔══════════════════════════════════════════════════════════════════╗");
            println!("║  ❌ FAIL: Test executable failed                                 ║");
            println!("╚══════════════════════════════════════════════════════════════════╝");
            println!("\n  Error: {}", e);
            std::process::exit(1);
        }
    }
}

fn parse_args() -> Result<TestConfig, String> {
    let args: Vec<String> = std::env::args().collect();
    let mut access_token = None;
    let mut region = "singapore".to_string();
    let mut config_file = None;
    let mut test_exe = None;

    let mut i = 1;
    while i < args.len() {
        match args[i].as_str() {
            "--token" | "-t" => {
                i += 1;
                if i >= args.len() {
                    return Err("--token requires a value".to_string());
                }
                access_token = Some(args[i].clone());
            }
            "--region" | "-r" => {
                i += 1;
                if i >= args.len() {
                    return Err("--region requires a value".to_string());
                }
                region = args[i].clone();
            }
            "--config" | "-c" => {
                i += 1;
                if i >= args.len() {
                    return Err("--config requires a value".to_string());
                }
                config_file = Some(args[i].clone());
            }
            "--test-exe" | "-e" => {
                i += 1;
                if i >= args.len() {
                    return Err("--test-exe requires a value".to_string());
                }
                test_exe = Some(args[i].clone());
            }
            "--help" | "-h" => {
                print_usage();
                std::process::exit(0);
            }
            other => {
                // Backwards compat: first positional arg is config file
                if config_file.is_none() && !other.starts_with('-') {
                    config_file = Some(other.to_string());
                } else {
                    return Err(format!("Unknown argument: {}", other));
                }
            }
        }
        i += 1;
    }

    if access_token.is_none() && config_file.is_none() {
        return Err("Either --token or --config is required".to_string());
    }

    // Default test exe to ip_checker.exe
    let test_exe = test_exe.unwrap_or_else(|| {
        std::env::current_exe()
            .map(|p| p.parent().unwrap().join("ip_checker.exe").to_string_lossy().to_string())
            .unwrap_or_else(|_| "ip_checker.exe".to_string())
    });

    Ok(TestConfig {
        access_token,
        region,
        config_file,
        test_exe,
    })
}

fn print_usage() {
    eprintln!("Usage:");
    eprintln!("  With API token:");
    eprintln!("    split_tunnel_integration_test.exe --token ACCESS_TOKEN --region REGION");
    eprintln!("");
    eprintln!("  With config file:");
    eprintln!("    split_tunnel_integration_test.exe --config config.json");
    eprintln!("");
    eprintln!("Options:");
    eprintln!("  --token, -t TOKEN    Supabase access token for API auth");
    eprintln!("  --region, -r REGION  VPN region (default: singapore)");
    eprintln!("  --config, -c FILE    VPN config JSON file (alternative to --token)");
    eprintln!("  --test-exe, -e PATH  Test executable (default: ip_checker.exe)");
    eprintln!("  --help, -h           Show this help");
    eprintln!("");
    eprintln!("Examples:");
    eprintln!("  split_tunnel_integration_test.exe --token eyJhbG... --region singapore");
    eprintln!("  split_tunnel_integration_test.exe --config vpn_config.json");
}

async fn run_test(config: TestConfig) -> TestResult {
    // ═══════════════════════════════════════════════════════════════════════
    // STEP 1: Check prerequisites
    // ═══════════════════════════════════════════════════════════════════════
    println!("[1/8] Checking prerequisites...");

    if !is_admin() {
        return TestResult::PrerequisiteFailed("Administrator privileges required!".to_string());
    }
    println!("    ✓ Running as Administrator");

    let wintun_path = match find_wintun_dll() {
        Some(p) => {
            println!("    ✓ Found wintun.dll: {}", p.display());
            p
        }
        None => {
            return TestResult::PrerequisiteFailed(
                "wintun.dll not found! Place it next to the executable.".to_string()
            );
        }
    };

    if !check_split_tunnel_driver() {
        return TestResult::PrerequisiteFailed(
            "Split tunnel driver not available! Run: sc start MullvadSplitTunnel".to_string()
        );
    }
    println!("    ✓ Split tunnel driver available");

    if !std::path::Path::new(&config.test_exe).exists() {
        return TestResult::PrerequisiteFailed(format!(
            "Test executable not found: {}\nBuild it with: cargo build --bin ip_checker --release",
            config.test_exe
        ));
    }
    println!("    ✓ Test executable found: {}", config.test_exe);

    // ═══════════════════════════════════════════════════════════════════════
    // STEP 2: Load/fetch VPN config
    // ═══════════════════════════════════════════════════════════════════════
    println!("\n[2/8] Getting VPN configuration...");

    let vpn_config = if let Some(token) = &config.access_token {
        println!("    Fetching from API (region: {})...", config.region);
        match fetch_vpn_config(token, &config.region).await {
            Ok(c) => {
                println!("    ✓ Config received from API");
                c
            }
            Err(e) => {
                return TestResult::ConfigFetchFailed(e);
            }
        }
    } else if let Some(path) = &config.config_file {
        println!("    Loading from file: {}", path);
        match load_config(path) {
            Ok(c) => {
                println!("    ✓ Config loaded from file");
                c
            }
            Err(e) => {
                return TestResult::ConfigFetchFailed(e);
            }
        }
    } else {
        return TestResult::ConfigFetchFailed("No config source specified".to_string());
    };

    println!("    Region:      {}", vpn_config.region);
    println!("    Endpoint:    {}", vpn_config.endpoint);
    println!("    Assigned IP: {}", vpn_config.assigned_ip);

    // ═══════════════════════════════════════════════════════════════════════
    // STEP 3: Get baseline IP (without VPN)
    // ═══════════════════════════════════════════════════════════════════════
    println!("\n[3/8] Getting baseline public IP (without VPN)...");

    let baseline_ip = match run_test_exe(&config.test_exe) {
        Ok(ip) => {
            println!("    ✓ Baseline IP: {}", ip);
            ip
        }
        Err(e) => {
            println!("    ⚠ Could not get baseline IP: {}", e);
            println!("    Continuing anyway (will skip comparison)...");
            String::new()
        }
    };

    // ═══════════════════════════════════════════════════════════════════════
    // STEP 4: Create Wintun adapter
    // ═══════════════════════════════════════════════════════════════════════
    println!("\n[4/8] Creating VPN tunnel...");

    let wintun = match unsafe { wintun::load_from_path(&wintun_path) } {
        Ok(w) => w,
        Err(e) => {
            return TestResult::PrerequisiteFailed(format!("Failed to load wintun.dll: {:?}", e));
        }
    };
    println!("    ✓ Wintun loaded");

    let adapter = match wintun::Adapter::create(&wintun, "SwiftTunnel", "SwiftTunnel", None) {
        Ok(a) => a,
        Err(e) => {
            return TestResult::PrerequisiteFailed(format!("Failed to create adapter: {:?}", e));
        }
    };
    println!("    ✓ Wintun adapter created");

    // Get LUID for split tunnel
    let luid = adapter.get_luid();
    let interface_luid = unsafe { std::mem::transmute::<_, u64>(luid) };
    println!("    Interface LUID: {} (0x{:016X})", interface_luid, interface_luid);

    // Parse and set IP
    let assigned_ip: Ipv4Addr = vpn_config.assigned_ip.split('/').next()
        .unwrap_or(&vpn_config.assigned_ip)
        .parse()
        .expect("Invalid assigned IP");

    if let Err(e) = adapter.set_address(assigned_ip) {
        return TestResult::PrerequisiteFailed(format!("Failed to set IP address: {:?}", e));
    }
    println!("    ✓ IP address set: {}", assigned_ip);

    // Start session
    let _session = match adapter.start_session(0x400000) {
        Ok(s) => s,
        Err(e) => {
            return TestResult::PrerequisiteFailed(format!("Failed to start session: {:?}", e));
        }
    };
    println!("    ✓ Adapter session started");

    // ═══════════════════════════════════════════════════════════════════════
    // STEP 5: Setup WFP (STRICT - fail if WFP fails!)
    // NOTE: The driver's INITIALIZE creates its own WFP callouts. We only need
    // to ensure the provider/sublayer exist for the callouts to attach to.
    // ═══════════════════════════════════════════════════════════════════════
    println!("\n[5/8] Setting up WFP for split tunneling (STRICT MODE)...");
    println!("    ⚠ WFP failure is FATAL - the driver cannot route without WFP");

    let _wfp_engine = match setup_wfp_strict(interface_luid) {
        Ok(engine) => {
            println!("    ✓ WFP setup complete");
            engine
        }
        Err(e) => {
            return TestResult::WfpSetupFailed(e);
        }
    };

    // ═══════════════════════════════════════════════════════════════════════
    // STEP 6: Configure split tunnel driver
    // ═══════════════════════════════════════════════════════════════════════
    println!("\n[6/8] Configuring split tunnel driver...");

    let driver_handle = match open_split_tunnel_driver() {
        Ok(h) => h,
        Err(e) => {
            return TestResult::PrerequisiteFailed(format!("Failed to open driver: {}", e));
        }
    };
    println!("    ✓ Driver handle opened");

    // Check initial state
    let initial_state = get_driver_state(driver_handle).unwrap_or(0);
    println!("    Initial state: {} ({})", initial_state, state_name(initial_state));

    // ALWAYS reset driver to clear stale WFP callouts from previous sessions
    // This is CRITICAL: without reset, INITIALIZE fails with ALREADY_EXISTS
    // if there are leftover callouts from a previous app crash or test run
    println!("    Resetting driver to clear stale callouts (twice for good measure)...");
    let _ = send_ioctl_neither(driver_handle, IOCTL_ST_RESET);
    std::thread::sleep(std::time::Duration::from_millis(500));
    let _ = send_ioctl_neither(driver_handle, IOCTL_ST_RESET);
    std::thread::sleep(std::time::Duration::from_millis(500));
    if let Some(state) = get_driver_state(driver_handle) {
        println!("    State after reset: {} ({})", state, state_name(state));
    }

    // DEBUG: Also try CLEAR_CONFIGURATION to ensure clean slate
    println!("    Sending CLEAR_CONFIGURATION...");
    let _ = send_ioctl_neither(driver_handle, IOCTL_ST_CLEAR_CONFIGURATION);
    std::thread::sleep(std::time::Duration::from_millis(200));

    // Initialize driver (transitions from STARTED -> INITIALIZED)
    println!("    Sending INITIALIZE...");
    if let Err(e) = send_ioctl_neither(driver_handle, IOCTL_ST_INITIALIZE) {
        // FWP_E_ALREADY_EXISTS is OK if callouts already exist
        if !e.contains("0x80320009") {
            cleanup_driver(driver_handle);
            return TestResult::DriverNotEngaged(get_driver_state(driver_handle).unwrap_or(0));
        }
        println!("    Note: Callouts already exist (continuing)");
    }

    let post_init_state = get_driver_state(driver_handle).unwrap_or(0);
    println!("    State after INITIALIZE: {} ({})", post_init_state, state_name(post_init_state));

    if post_init_state < STATE_INITIALIZED {
        cleanup_driver(driver_handle);
        return TestResult::DriverNotEngaged(post_init_state);
    }

    // Register process tree (transitions from INITIALIZED -> READY)
    println!("    Sending REGISTER_PROCESSES...");
    let proc_data = build_process_tree();
    println!("    Process tree size: {} bytes", proc_data.len());
    if let Err(e) = send_ioctl(driver_handle, IOCTL_ST_REGISTER_PROCESSES, &proc_data) {
        println!("    ERROR: REGISTER_PROCESSES failed: {}", e);
        cleanup_driver(driver_handle);
        return TestResult::DriverNotEngaged(get_driver_state(driver_handle).unwrap_or(0));
    }

    let post_proc_state = get_driver_state(driver_handle).unwrap_or(0);
    println!("    State after REGISTER_PROCESSES: {} ({})", post_proc_state, state_name(post_proc_state));

    // Register IP addresses (part of READY state)
    println!("    Sending REGISTER_IP_ADDRESSES...");
    let ip_data = build_ip_addresses(interface_luid, assigned_ip);
    println!("    IP data size: {} bytes, LUID: 0x{:016X}, IP: {}", ip_data.len(), interface_luid, assigned_ip);
    if let Err(e) = send_ioctl(driver_handle, IOCTL_ST_REGISTER_IP_ADDRESSES, &ip_data) {
        println!("    ERROR: REGISTER_IP_ADDRESSES failed: {}", e);
        cleanup_driver(driver_handle);
        return TestResult::DriverNotEngaged(get_driver_state(driver_handle).unwrap_or(0));
    }

    let post_ip_state = get_driver_state(driver_handle).unwrap_or(0);
    println!("    State after REGISTER_IP_ADDRESSES: {} ({})", post_ip_state, state_name(post_ip_state));

    // Set configuration (transitions from READY -> ENGAGED)
    println!("    Sending SET_CONFIGURATION...");
    let config_data = build_configuration(&config.test_exe);
    let device_path = to_device_path(&config.test_exe).unwrap_or_else(|_| config.test_exe.clone());
    println!("    Config size: {} bytes", config_data.len());
    println!("    Target app: {}", device_path);

    if let Err(e) = send_ioctl(driver_handle, IOCTL_ST_SET_CONFIGURATION, &config_data) {
        println!("    ERROR: SET_CONFIGURATION failed: {}", e);
        println!("");
        println!("    This likely means the WFP sublayer doesn't exist or has wrong GUIDs.");
        println!("    The driver creates WFP filters during SET_CONFIGURATION, and");
        println!("    needs the sublayer to attach them to.");
        cleanup_driver(driver_handle);
        return TestResult::DriverNotEngaged(get_driver_state(driver_handle).unwrap_or(0));
    }

    // ═══════════════════════════════════════════════════════════════════════
    // STEP 7: Verify driver state == ENGAGED (CRITICAL CHECK)
    // ═══════════════════════════════════════════════════════════════════════
    println!("\n[7/8] Verifying driver state (CRITICAL)...");

    let final_state = get_driver_state(driver_handle).unwrap_or(0);
    println!("    Final state: {} ({})", final_state, state_name(final_state));

    if final_state != STATE_ENGAGED {
        println!("    ❌ CRITICAL: Driver is NOT in ENGAGED state!");
        println!("       Expected: {} (ENGAGED)", STATE_ENGAGED);
        println!("       Actual:   {} ({})", final_state, state_name(final_state));
        cleanup_driver(driver_handle);
        return TestResult::DriverNotEngaged(final_state);
    }

    println!("    ✓ Driver is ENGAGED - ready to route traffic");

    // ═══════════════════════════════════════════════════════════════════════
    // STEP 8: Test traffic routing
    // ═══════════════════════════════════════════════════════════════════════
    println!("\n[8/8] Testing traffic routing through split tunnel...");

    // Small delay to let filters settle
    std::thread::sleep(std::time::Duration::from_millis(500));

    let vpn_ip = match run_test_exe(&config.test_exe) {
        Ok(ip) => {
            println!("    IP through split tunnel: {}", ip);
            ip
        }
        Err(e) => {
            cleanup_driver(driver_handle);
            return TestResult::TestExeFailed(e);
        }
    };

    // Cleanup
    cleanup_driver(driver_handle);

    // Compare IPs
    if baseline_ip.is_empty() {
        // Can't compare, but we got an IP back
        return TestResult::Success {
            baseline_ip: "(not measured)".to_string(),
            vpn_ip,
        };
    }

    if vpn_ip != baseline_ip {
        TestResult::Success { baseline_ip, vpn_ip }
    } else {
        TestResult::SplitTunnelNotRouting { baseline_ip, vpn_ip }
    }
}

/// Fetch VPN config from API
async fn fetch_vpn_config(access_token: &str, region: &str) -> Result<VpnConfig, String> {
    let client = reqwest::Client::new();
    let url = format!("{}/api/vpn/generate-config", API_BASE_URL);

    let response = client
        .post(&url)
        .header("Authorization", format!("Bearer {}", access_token))
        .json(&serde_json::json!({ "region": region }))
        .send()
        .await
        .map_err(|e| format!("HTTP request failed: {}", e))?;

    if !response.status().is_success() {
        let status = response.status();
        let body = response.text().await.unwrap_or_default();
        return Err(format!("API returned {}: {}", status, body));
    }

    response
        .json::<VpnConfig>()
        .await
        .map_err(|e| format!("Failed to parse response: {}", e))
}

fn load_config(path: &str) -> Result<VpnConfig, String> {
    let data = std::fs::read_to_string(path)
        .map_err(|e| format!("Failed to read config: {}", e))?;
    serde_json::from_str(&data)
        .map_err(|e| format!("Failed to parse config: {}", e))
}

fn is_admin() -> bool {
    unsafe {
        use windows::Win32::Security::{GetTokenInformation, TokenElevation, TOKEN_ELEVATION, TOKEN_QUERY};
        use windows::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};

        let mut token_handle = HANDLE::default();
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
        result.is_ok() && elevation.TokenIsElevated != 0
    }
}

fn find_wintun_dll() -> Option<std::path::PathBuf> {
    // Check next to executable
    if let Ok(exe_path) = std::env::current_exe() {
        if let Some(exe_dir) = exe_path.parent() {
            let dll_path = exe_dir.join("wintun.dll");
            if dll_path.exists() {
                return Some(dll_path);
            }
        }
    }
    // Check current directory
    if let Ok(cwd) = std::env::current_dir() {
        let dll_path = cwd.join("wintun.dll");
        if dll_path.exists() {
            return Some(dll_path);
        }
    }
    // Check dist directory (for development)
    if let Ok(cwd) = std::env::current_dir() {
        let dll_path = cwd.join("dist").join("wintun.dll");
        if dll_path.exists() {
            return Some(dll_path);
        }
    }
    None
}

fn check_split_tunnel_driver() -> bool {
    unsafe {
        let path = std::ffi::CString::new(DEVICE_PATH).unwrap();
        let handle = CreateFileA(
            PCSTR(path.as_ptr() as *const u8),
            GENERIC_READ.0 | GENERIC_WRITE.0,
            FILE_SHARE_READ | FILE_SHARE_WRITE,
            None,
            OPEN_EXISTING,
            FILE_ATTRIBUTE_NORMAL,
            None,
        );
        match handle {
            Ok(h) => {
                let _ = CloseHandle(h);
                true
            }
            Err(_) => false,
        }
    }
}

fn run_test_exe(path: &str) -> Result<String, String> {
    let output = Command::new(path)
        .output()
        .map_err(|e| format!("Failed to run {}: {}", path, e))?;

    if !output.status.success() {
        return Err(format!(
            "Test exe exited with code: {:?}\nstdout: {}\nstderr: {}",
            output.status.code(),
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        ));
    }

    let stdout = String::from_utf8_lossy(&output.stdout);

    // Parse IP from output
    for line in stdout.lines() {
        if line.contains("Your public IP:") {
            if let Some(ip) = line.split(':').last() {
                return Ok(ip.trim().to_string());
            }
        }
        // Also try bare IP
        let trimmed = line.trim();
        if trimmed.split('.').count() == 4 && trimmed.chars().all(|c| c.is_ascii_digit() || c == '.') {
            return Ok(trimmed.to_string());
        }
    }

    Err(format!("Could not find IP in output: {}", stdout))
}

fn open_split_tunnel_driver() -> Result<HANDLE, String> {
    unsafe {
        let path = std::ffi::CString::new(DEVICE_PATH).unwrap();
        CreateFileA(
            PCSTR(path.as_ptr() as *const u8),
            GENERIC_READ.0 | GENERIC_WRITE.0,
            FILE_SHARE_READ | FILE_SHARE_WRITE,
            None,
            OPEN_EXISTING,
            FILE_ATTRIBUTE_NORMAL,
            None,
        ).map_err(|e| format!("Failed to open driver: {}", e))
    }
}

fn send_ioctl_neither(handle: HANDLE, ioctl_code: u32) -> Result<(), String> {
    let mut bytes_returned: u32 = 0;
    unsafe {
        DeviceIoControl(handle, ioctl_code, None, 0, None, 0, Some(&mut bytes_returned), None)
            .map_err(|e| format!("IOCTL 0x{:08X} failed: {}", ioctl_code, e))
    }
}

fn send_ioctl(handle: HANDLE, ioctl_code: u32, input: &[u8]) -> Result<Vec<u8>, String> {
    let mut output = vec![0u8; 4096];
    let mut bytes_returned: u32 = 0;
    unsafe {
        DeviceIoControl(
            handle,
            ioctl_code,
            Some(input.as_ptr() as *const std::ffi::c_void),
            input.len() as u32,
            Some(output.as_mut_ptr() as *mut std::ffi::c_void),
            output.len() as u32,
            Some(&mut bytes_returned),
            None,
        ).map_err(|e| format!("IOCTL 0x{:08X} failed: {}", ioctl_code, e))?;
    }
    output.truncate(bytes_returned as usize);
    Ok(output)
}

fn get_driver_state(handle: HANDLE) -> Option<u64> {
    let mut buf = [0u8; 64];
    let mut bytes_returned: u32 = 0;
    unsafe {
        if DeviceIoControl(
            handle,
            IOCTL_ST_GET_STATE,
            None, 0,
            Some(buf.as_mut_ptr() as *mut std::ffi::c_void),
            buf.len() as u32,
            Some(&mut bytes_returned),
            None,
        ).is_ok() && bytes_returned >= 8 {
            Some(u64::from_le_bytes([buf[0], buf[1], buf[2], buf[3], buf[4], buf[5], buf[6], buf[7]]))
        } else {
            None
        }
    }
}

fn state_name(state: u64) -> &'static str {
    match state {
        STATE_NONE => "NONE",
        STATE_STARTED => "STARTED",
        STATE_INITIALIZED => "INITIALIZED",
        STATE_READY => "READY",
        STATE_ENGAGED => "ENGAGED",
        STATE_ZOMBIE => "ZOMBIE",
        _ => "UNKNOWN",
    }
}

fn cleanup_driver(handle: HANDLE) {
    let _ = send_ioctl_neither(handle, IOCTL_ST_RESET);
    unsafe { let _ = CloseHandle(handle); }
}

/// Build process tree with System process placeholder
fn build_process_tree() -> Vec<u8> {
    let system_wide: Vec<u16> = "System".encode_utf16().collect();
    let string_bytes = system_wide.len() * 2;
    let total_size = 16 + 32 + string_bytes; // header + 1 entry + strings

    let mut data = Vec::with_capacity(total_size);

    // Header
    data.extend_from_slice(&1u64.to_le_bytes()); // num_entries
    data.extend_from_slice(&(total_size as u64).to_le_bytes()); // total_length

    // Entry (32 bytes)
    data.extend_from_slice(&4u64.to_le_bytes()); // pid = 4 (System)
    data.extend_from_slice(&0u64.to_le_bytes()); // parent_pid = 0
    data.extend_from_slice(&0u64.to_le_bytes()); // image_name_offset = 0 (relative)
    data.extend_from_slice(&(string_bytes as u16).to_le_bytes()); // image_name_size
    data.extend_from_slice(&[0u8; 6]); // padding

    // Strings
    for w in &system_wide {
        data.extend_from_slice(&w.to_le_bytes());
    }

    data
}

/// Build ST_IP_ADDRESSES struct (40 bytes)
fn build_ip_addresses(interface_luid: u64, ipv4: Ipv4Addr) -> Vec<u8> {
    let mut data = Vec::with_capacity(40);

    data.extend_from_slice(&interface_luid.to_le_bytes()); // interface_luid (8)
    data.extend_from_slice(&ipv4.octets()); // tunnel_ipv4 (4)
    data.extend_from_slice(&[0u8; 16]); // tunnel_ipv6 (16)
    data.push(1); // has_ipv4
    data.push(0); // has_ipv6
    data.extend_from_slice(&[0u8; 10]); // padding

    data
}

/// Build configuration for the test executable
fn build_configuration(exe_path: &str) -> Vec<u8> {
    // Convert to device path
    let device_path = to_device_path(exe_path).unwrap_or_else(|_| exe_path.to_string());
    let wide: Vec<u16> = device_path.encode_utf16().collect();
    let string_bytes = wide.len() * 2;

    let total_size = 16 + 32 + string_bytes; // header + 1 entry + strings
    let mut data = Vec::with_capacity(total_size);

    // Header
    data.extend_from_slice(&1u64.to_le_bytes()); // num_entries
    data.extend_from_slice(&(total_size as u64).to_le_bytes()); // total_length

    // ConfigurationEntry (32 bytes)
    data.extend_from_slice(&0u64.to_le_bytes()); // protocol (unused)
    data.extend_from_slice(&0u64.to_le_bytes()); // padding
    data.extend_from_slice(&0u64.to_le_bytes()); // image_name_offset = 0 (relative)
    data.extend_from_slice(&(string_bytes as u16).to_le_bytes()); // image_name_size
    data.extend_from_slice(&[0u8; 6]); // padding

    // Strings
    for w in &wide {
        data.extend_from_slice(&w.to_le_bytes());
    }

    data
}

fn to_device_path(path: &str) -> Result<String, String> {
    use windows::Win32::Storage::FileSystem::QueryDosDeviceW;
    use windows::core::PCWSTR;

    if path.len() < 2 || path.chars().nth(1) != Some(':') {
        if path.starts_with(r"\Device\") {
            return Ok(path.to_string());
        }
        return Err("Invalid path format".to_string());
    }

    let drive = &path[0..2];
    let rest = &path[2..];

    let drive_wide: Vec<u16> = drive.encode_utf16().chain(std::iter::once(0)).collect();
    let mut device_name = vec![0u16; 260];

    unsafe {
        let len = QueryDosDeviceW(PCWSTR(drive_wide.as_ptr()), Some(&mut device_name));
        if len == 0 {
            return Ok(format!(r"\Device\HarddiskVolume1{}", rest));
        }
        let actual_len = device_name.iter().position(|&c| c == 0).unwrap_or(device_name.len());
        let device_str = String::from_utf16_lossy(&device_name[..actual_len]);
        Ok(format!("{}{}", device_str, rest))
    }
}

// ============================================================================
// WFP (Windows Filtering Platform) - STRICT MODE
// ============================================================================

/// Mullvad Split Tunnel WFP Provider GUID
static ST_FW_PROVIDER_KEY: GUID = GUID::from_values(
    0xE2C114EE,
    0xF32A,
    0x4264,
    [0xA6, 0xCB, 0x3F, 0xA7, 0x99, 0x63, 0x56, 0xD9],
);

/// Mullvad Split Tunnel WFP Sublayer GUID (WinFW Baseline Sublayer)
static ST_FW_WINFW_BASELINE_SUBLAYER_KEY: GUID = GUID::from_values(
    0xC78056FF,
    0x2BC1,
    0x4211,
    [0xAA, 0xDD, 0x7F, 0x35, 0x8D, 0xEF, 0x20, 0x2D],
);

/// Mullvad Split Tunnel WFP DNS Sublayer GUID
static ST_FW_WINFW_DNS_SUBLAYER_KEY: GUID = GUID::from_values(
    0x60090787,
    0xCCA1,
    0x4937,
    [0xAA, 0xCE, 0x51, 0x25, 0x6E, 0xF4, 0x81, 0xF3],
);

/// Legacy SwiftTunnel VPN Provider GUID (from old code, has PERSISTENT flag)
/// Must be cleaned up to prevent driver INITIALIZE failures
static LEGACY_ST_PROVIDER_KEY: GUID = GUID::from_values(
    0x5f7b3a1e,
    0x9d4c,
    0x4b2a,
    [0x8e, 0x6f, 0x1a, 0x2b, 0x3c, 0x4d, 0x5e, 0x6f],
);

/// Legacy SwiftTunnel Split Tunnel Sublayer GUID (from old code, has PERSISTENT flag)
/// Must be cleaned up to prevent driver INITIALIZE failures
static LEGACY_ST_SUBLAYER_KEY: GUID = GUID::from_values(
    0x6a8c4b2f,
    0xae5d,
    0x5c3b,
    [0x9f, 0x70, 0x2b, 0x3c, 0x4d, 0x5e, 0x6f, 0x70],
);

/// RPC authentication constant
const RPC_C_AUTHN_WINNT: u32 = 10;

/// WFP Engine wrapper
struct WfpEngineHandle {
    handle: HANDLE,
}

impl Drop for WfpEngineHandle {
    fn drop(&mut self) {
        if !self.handle.is_invalid() {
            unsafe {
                let _ = FwpmEngineClose0(self.handle);
            }
        }
    }
}

/// Setup WFP with STRICT error handling
/// Returns Err if WFP setup fails (split tunnel will not work without it)
fn setup_wfp_strict(interface_luid: u64) -> Result<WfpEngineHandle, String> {
    println!("    Opening WFP engine...");

    let mut handle = HANDLE::default();
    let result = unsafe {
        FwpmEngineOpen0(
            None,
            RPC_C_AUTHN_WINNT,
            None,
            None,
            &mut handle,
        )
    };

    if result != 0 {
        return Err(format!("Failed to open WFP engine: 0x{:08X}", result));
    }
    println!("    ✓ WFP engine opened");

    // CRITICAL: Clean up any stale WFP objects from previous sessions
    // This prevents ALREADY_EXISTS errors when driver tries to create callouts
    println!("    Cleaning up stale WFP objects...");
    cleanup_wfp_objects(handle);

    // Create provider (or verify it exists)
    let provider_name: Vec<u16> = "Mullvad Split Tunnel".encode_utf16().chain(std::iter::once(0)).collect();
    let provider_desc: Vec<u16> = "Mullvad Split Tunnel WFP provider".encode_utf16().chain(std::iter::once(0)).collect();

    let provider = FWPM_PROVIDER0 {
        providerKey: ST_FW_PROVIDER_KEY,
        displayData: FWPM_DISPLAY_DATA0 {
            name: windows::core::PWSTR(provider_name.as_ptr() as *mut u16),
            description: windows::core::PWSTR(provider_desc.as_ptr() as *mut u16),
        },
        flags: 0, // Non-persistent
        providerData: FWP_BYTE_BLOB::default(),
        serviceName: windows::core::PWSTR::null(),
    };

    let result = unsafe { FwpmProviderAdd0(handle, &provider, None) };
    if result != 0 && result != FWP_E_ALREADY_EXISTS.0 as u32 {
        unsafe { let _ = FwpmEngineClose0(handle); }
        return Err(format!("Failed to add WFP provider: 0x{:08X}", result));
    }
    println!("    ✓ WFP provider registered (GUID: {:?})", ST_FW_PROVIDER_KEY);

    // Create baseline sublayer (REQUIRED for split tunnel filters)
    let sublayer_name: Vec<u16> = "WinFW Baseline Sublayer".encode_utf16().chain(std::iter::once(0)).collect();
    let sublayer_desc: Vec<u16> = "Mullvad split tunnel WFP sublayer".encode_utf16().chain(std::iter::once(0)).collect();

    let sublayer = FWPM_SUBLAYER0 {
        subLayerKey: ST_FW_WINFW_BASELINE_SUBLAYER_KEY,
        displayData: FWPM_DISPLAY_DATA0 {
            name: windows::core::PWSTR(sublayer_name.as_ptr() as *mut u16),
            description: windows::core::PWSTR(sublayer_desc.as_ptr() as *mut u16),
        },
        flags: 0, // Non-persistent
        providerKey: std::ptr::null_mut(),
        providerData: FWP_BYTE_BLOB::default(),
        weight: 0x8000,
    };

    let result = unsafe { FwpmSubLayerAdd0(handle, &sublayer, None) };
    if result != 0 && result != FWP_E_ALREADY_EXISTS.0 as u32 {
        unsafe { let _ = FwpmEngineClose0(handle); }
        return Err(format!(
            "Failed to add WFP baseline sublayer: 0x{:08X}\nThe driver needs this sublayer to create filters.",
            result
        ));
    }
    println!("    ✓ WFP baseline sublayer created (GUID: {:?})", ST_FW_WINFW_BASELINE_SUBLAYER_KEY);

    // Create DNS sublayer (for DNS filtering)
    let dns_sublayer_name: Vec<u16> = "WinFW DNS Sublayer".encode_utf16().chain(std::iter::once(0)).collect();
    let dns_sublayer_desc: Vec<u16> = "Mullvad DNS traffic sublayer".encode_utf16().chain(std::iter::once(0)).collect();

    let dns_sublayer = FWPM_SUBLAYER0 {
        subLayerKey: ST_FW_WINFW_DNS_SUBLAYER_KEY,
        displayData: FWPM_DISPLAY_DATA0 {
            name: windows::core::PWSTR(dns_sublayer_name.as_ptr() as *mut u16),
            description: windows::core::PWSTR(dns_sublayer_desc.as_ptr() as *mut u16),
        },
        flags: 0,
        providerKey: std::ptr::null_mut(),
        providerData: FWP_BYTE_BLOB::default(),
        weight: 0x9000,
    };

    let result = unsafe { FwpmSubLayerAdd0(handle, &dns_sublayer, None) };
    if result != 0 && result != FWP_E_ALREADY_EXISTS.0 as u32 {
        println!("    ⚠ DNS sublayer not created (0x{:08X}) - DNS filtering may not work", result);
    } else {
        println!("    ✓ WFP DNS sublayer created");
    }

    println!("    Interface LUID for filters: {} (0x{:016X})", interface_luid, interface_luid);

    Ok(WfpEngineHandle { handle })
}

/// Clean up stale WFP objects from previous sessions
/// This is critical to prevent ALREADY_EXISTS errors when the driver initializes
fn cleanup_wfp_objects(handle: HANDLE) {
    // Delete sublayers first (this will also delete associated filters)
    let result = unsafe {
        FwpmSubLayerDeleteByKey0(handle, &ST_FW_WINFW_BASELINE_SUBLAYER_KEY)
    };
    if result == 0 {
        println!("    Deleted stale baseline sublayer (Mullvad)");
    }

    let result = unsafe {
        FwpmSubLayerDeleteByKey0(handle, &ST_FW_WINFW_DNS_SUBLAYER_KEY)
    };
    if result == 0 {
        println!("    Deleted stale DNS sublayer (Mullvad)");
    }

    // Delete provider
    let result = unsafe {
        FwpmProviderDeleteByKey0(handle, &ST_FW_PROVIDER_KEY)
    };
    if result == 0 {
        println!("    Deleted stale provider (Mullvad)");
    }

    // Clean up LEGACY SwiftTunnel WFP objects (from old code with PERSISTENT flags)
    // These must be removed or driver INITIALIZE will fail with ALREADY_EXISTS
    let result = unsafe {
        FwpmSubLayerDeleteByKey0(handle, &LEGACY_ST_SUBLAYER_KEY)
    };
    if result == 0 {
        println!("    Deleted legacy SwiftTunnel sublayer (PERSISTENT)");
    }

    let result = unsafe {
        FwpmProviderDeleteByKey0(handle, &LEGACY_ST_PROVIDER_KEY)
    };
    if result == 0 {
        println!("    Deleted legacy SwiftTunnel provider (PERSISTENT)");
    }
}
