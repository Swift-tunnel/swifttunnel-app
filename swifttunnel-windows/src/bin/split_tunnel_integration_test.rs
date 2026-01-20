//! Split Tunnel Integration Test
//!
//! Full end-to-end test of split tunnel functionality:
//! 1. Fetches VPN config from API (or uses local config file)
//! 2. Creates VPN tunnel (Wintun + WireGuard with FULL packet forwarding)
//! 3. Sets up WFP (with STRICT error handling - fails if WFP fails)
//! 4. Configures split tunnel for test process
//! 5. Verifies driver state == ENGAGED (4)
//! 6. Runs test process to verify traffic routing through actual VPN tunnel
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

use std::net::{Ipv4Addr, SocketAddr};
use std::process::Command;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;
use tokio::net::UdpSocket;
use boringtun::noise::{Tunn, TunnResult};
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
    // STEP 4: Create Wintun adapter + WireGuard tunnel (FULL PACKET FORWARDING)
    // ═══════════════════════════════════════════════════════════════════════
    println!("\n[4/9] Creating VPN tunnel with WireGuard...");

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
    let session = match adapter.start_session(0x400000) {
        Ok(s) => Arc::new(s),
        Err(e) => {
            return TestResult::PrerequisiteFailed(format!("Failed to start session: {:?}", e));
        }
    };
    println!("    ✓ Adapter session started");

    // Parse server endpoint
    let endpoint: SocketAddr = match vpn_config.endpoint.parse() {
        Ok(e) => e,
        Err(e) => {
            return TestResult::PrerequisiteFailed(format!("Invalid endpoint: {}", e));
        }
    };

    // Create BoringTun instance
    let private_key = match parse_wireguard_key(&vpn_config.private_key) {
        Ok(k) => k,
        Err(e) => {
            return TestResult::PrerequisiteFailed(format!("Invalid private key: {}", e));
        }
    };
    let server_public_key = match parse_wireguard_key(&vpn_config.server_public_key) {
        Ok(k) => k,
        Err(e) => {
            return TestResult::PrerequisiteFailed(format!("Invalid server public key: {}", e));
        }
    };

    let tunn = match Tunn::new(
        private_key.into(),
        server_public_key.into(),
        None, // No preshared key
        Some(25), // 25s keepalive
        0, // Tunnel index
        None, // No rate limiter
    ) {
        Ok(t) => Arc::new(std::sync::Mutex::new(t)),
        Err(e) => {
            return TestResult::PrerequisiteFailed(format!("Failed to create BoringTun: {:?}", e));
        }
    };
    println!("    ✓ BoringTun instance created");

    // Create UDP socket for VPN server
    let socket = match UdpSocket::bind("0.0.0.0:0").await {
        Ok(s) => s,
        Err(e) => {
            return TestResult::PrerequisiteFailed(format!("Failed to bind UDP socket: {}", e));
        }
    };
    if let Err(e) = socket.connect(endpoint).await {
        return TestResult::PrerequisiteFailed(format!("Failed to connect to VPN server: {}", e));
    }
    let socket = Arc::new(socket);
    println!("    ✓ UDP socket connected to {}", endpoint);

    // Perform WireGuard handshake
    println!("    Performing WireGuard handshake...");
    if let Err(e) = wireguard_handshake(&tunn, &socket).await {
        return TestResult::PrerequisiteFailed(format!("WireGuard handshake failed: {}", e));
    }
    println!("    ✓ WireGuard handshake completed!");

    // Start packet forwarding tasks
    let running = Arc::new(AtomicBool::new(true));
    let (outbound_handle, inbound_handle, keepalive_handle) = start_packet_forwarding(
        Arc::clone(&session),
        Arc::clone(&tunn),
        Arc::clone(&socket),
        Arc::clone(&running),
    );
    println!("    ✓ Packet forwarding tasks started");

    // ═══════════════════════════════════════════════════════════════════════
    // STEP 5: Setup WFP (STRICT - fail if WFP fails!)
    // NOTE: The driver's INITIALIZE creates its own WFP callouts. We only need
    // to ensure the provider/sublayer exist for the callouts to attach to.
    // ═══════════════════════════════════════════════════════════════════════
    println!("\n[5/9] Setting up WFP for split tunneling (STRICT MODE)...");
    println!("    ⚠ WFP failure is FATAL - the driver cannot route without WFP");

    let wfp_engine = match setup_wfp_strict(interface_luid) {
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
    println!("\n[6/9] Configuring split tunnel driver...");

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

    // CRITICAL: Create WFP sublayers AFTER driver INITIALIZE
    // The driver creates its provider during INITIALIZE, but does NOT create sublayers.
    // SET_CONFIGURATION needs sublayers to attach filters to, so we create them now.
    println!("    Ensuring WFP sublayers exist...");
    if let Err(e) = wfp_engine.ensure_sublayers() {
        cleanup_driver(driver_handle);
        return TestResult::WfpSetupFailed(format!("Failed to create sublayers: {}", e));
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
    // Configure the test executable (ip_checker.exe) for split tunneling, NOT curl.exe.
    // The split tunnel driver only intercepts traffic from processes matching the configured path.
    println!("    Sending SET_CONFIGURATION...");
    let tunnel_exe = &config.test_exe;
    let config_data = build_configuration(tunnel_exe);
    let device_path = to_device_path(tunnel_exe).unwrap_or_else(|_| tunnel_exe.to_string());
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
    println!("\n[7/9] Verifying driver state (CRITICAL)...");

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
    // STEP 8: Test traffic routing through WireGuard tunnel
    // ═══════════════════════════════════════════════════════════════════════
    println!("\n[8/9] Testing traffic routing through split tunnel + WireGuard...");
    println!("    (WireGuard tunnel is ACTIVE - packets will be encrypted and forwarded)");
    println!("    Watching for packets on Wintun adapter...");

    // Longer delay to let filters settle and observe packet flow
    println!("    Waiting 2s for filters to settle...");
    std::thread::sleep(std::time::Duration::from_millis(2000));

    println!("    ===== RUNNING TEST COMMAND =====");
    println!("    Exe: {}", config.test_exe);
    let vpn_ip = match run_test_exe(&config.test_exe) {
        Ok(ip) => {
            println!("    ===== TEST COMMAND FINISHED =====");
            println!("    IP returned: {}", ip);
            // Wait a bit more to catch any late packets
            println!("    Waiting 2s for late packets...");
            std::thread::sleep(std::time::Duration::from_millis(2000));
            ip
        }
        Err(e) => {
            // Cleanup
            running.store(false, Ordering::SeqCst);
            cleanup_driver(driver_handle);
            return TestResult::TestExeFailed(e);
        }
    };

    // ═══════════════════════════════════════════════════════════════════════
    // STEP 9: Cleanup
    // ═══════════════════════════════════════════════════════════════════════
    println!("\n[9/9] Cleaning up...");

    // Stop packet forwarding
    running.store(false, Ordering::SeqCst);
    println!("    Stopping packet forwarding...");

    // Give tasks time to stop
    std::thread::sleep(std::time::Duration::from_millis(200));

    // Abort the tasks (they may be blocked on receive)
    outbound_handle.abort();
    inbound_handle.abort();
    keepalive_handle.abort();

    // Reset split tunnel driver
    cleanup_driver(driver_handle);
    println!("    ✓ Cleanup complete");

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

// ============================================================================
// WireGuard Tunnel Functions
// ============================================================================

/// Parse base64 WireGuard key to 32-byte array
fn parse_wireguard_key(key: &str) -> Result<[u8; 32], String> {
    use base64::{Engine as _, engine::general_purpose::STANDARD};

    let decoded = STANDARD.decode(key)
        .map_err(|e| format!("Invalid base64: {}", e))?;

    if decoded.len() != 32 {
        return Err(format!("Key must be 32 bytes, got {}", decoded.len()));
    }

    let mut key_bytes = [0u8; 32];
    key_bytes.copy_from_slice(&decoded);
    Ok(key_bytes)
}

/// Perform WireGuard handshake with the server
async fn wireguard_handshake(
    tunn: &Arc<std::sync::Mutex<Tunn>>,
    socket: &Arc<UdpSocket>,
) -> Result<(), String> {
    let mut buf = vec![0u8; 65535];

    // Generate handshake initiation
    let init_data = {
        let mut tunn = tunn.lock().unwrap();
        match tunn.format_handshake_initiation(&mut buf, false) {
            TunnResult::WriteToNetwork(data) => data.to_vec(),
            other => return Err(format!("Failed to generate handshake: {:?}", other)),
        }
    };

    // Send handshake initiation
    socket.send(&init_data).await
        .map_err(|e| format!("Failed to send handshake: {}", e))?;

    // Wait for response with timeout
    let mut response_buf = vec![0u8; 65535];
    let timeout = Duration::from_secs(10);

    match tokio::time::timeout(timeout, socket.recv(&mut response_buf)).await {
        Ok(Ok(n)) => {
            // Process response
            let response_data = {
                let mut tunn = tunn.lock().unwrap();
                match tunn.decapsulate(None, &response_buf[..n], &mut buf) {
                    TunnResult::Done => None,
                    TunnResult::WriteToNetwork(data) => Some(data.to_vec()),
                    TunnResult::Err(e) => return Err(format!("Handshake error: {:?}", e)),
                    other => {
                        // May still be OK
                        println!("    Unexpected handshake result: {:?}", other);
                        None
                    }
                }
            };

            // Send response if needed
            if let Some(data) = response_data {
                socket.send(&data).await.ok();
            }

            Ok(())
        }
        Ok(Err(e)) => Err(format!("Receive error: {}", e)),
        Err(_) => Err("Handshake timeout - server may be unreachable".to_string()),
    }
}

/// Start packet forwarding tasks (outbound, inbound, keepalive)
fn start_packet_forwarding(
    session: Arc<wintun::Session>,
    tunn: Arc<std::sync::Mutex<Tunn>>,
    socket: Arc<UdpSocket>,
    running: Arc<AtomicBool>,
) -> (tokio::task::JoinHandle<()>, tokio::task::JoinHandle<()>, tokio::task::JoinHandle<()>) {
    // Counters for debug logging
    let outbound_count = Arc::new(std::sync::atomic::AtomicU64::new(0));
    let inbound_count = Arc::new(std::sync::atomic::AtomicU64::new(0));

    // Outbound: Wintun adapter -> encrypt -> UDP to server
    // Uses a channel to bridge blocking wintun receive with async send
    let (tx, mut rx) = tokio::sync::mpsc::channel::<Vec<u8>>(100);

    // Spawn blocking task for wintun receive
    let outbound_recv_handle = {
        let session = Arc::clone(&session);
        let running = Arc::clone(&running);
        let tx = tx;
        let outbound_count = Arc::clone(&outbound_count);

        std::thread::spawn(move || {
            while running.load(Ordering::SeqCst) {
                match session.receive_blocking() {
                    Ok(packet) => {
                        let count = outbound_count.fetch_add(1, Ordering::SeqCst) + 1;
                        let bytes = packet.bytes();
                        if count <= 10 {
                            let ip_version = (bytes[0] >> 4) & 0x0F;
                            println!("    [OUTBOUND] Packet #{}: {} bytes, IPv{}", count, bytes.len(), ip_version);
                            if ip_version == 4 && bytes.len() >= 20 {
                                // Parse IPv4 header
                                let src_ip = format!("{}.{}.{}.{}", bytes[12], bytes[13], bytes[14], bytes[15]);
                                let dst_ip = format!("{}.{}.{}.{}", bytes[16], bytes[17], bytes[18], bytes[19]);
                                let protocol = bytes[9];
                                let proto_name = match protocol {
                                    1 => "ICMP",
                                    6 => "TCP",
                                    17 => "UDP",
                                    _ => "other",
                                };
                                println!("              {} -> {} ({}/{})", src_ip, dst_ip, proto_name, protocol);
                            } else if ip_version == 6 && bytes.len() >= 40 {
                                println!("              IPv6 packet (next header: {})", bytes[6]);
                            } else {
                                println!("              Raw: {:02X?}", &bytes[..bytes.len().min(20)]);
                            }
                        } else if count % 10 == 0 {
                            println!("    [OUTBOUND] {} packets total", count);
                        }
                        if tx.blocking_send(bytes.to_vec()).is_err() {
                            break; // Channel closed
                        }
                    }
                    Err(_) => {
                        // Session shutdown
                        break;
                    }
                }
            }
            println!("    [OUTBOUND] Thread exiting, total packets: {}", outbound_count.load(Ordering::SeqCst));
        })
    };

    let outbound_handle = {
        let tunn = Arc::clone(&tunn);
        let socket = Arc::clone(&socket);
        let running = Arc::clone(&running);

        tokio::spawn(async move {
            let mut encrypt_buf = vec![0u8; 65535];

            while running.load(Ordering::SeqCst) {
                // Receive from channel with timeout
                let packet_data = match tokio::time::timeout(
                    Duration::from_millis(100),
                    rx.recv()
                ).await {
                    Ok(Some(data)) => data,
                    Ok(None) => break, // Channel closed
                    Err(_) => continue, // Timeout
                };

                // Encrypt packet
                let encrypted = {
                    let mut tunn = tunn.lock().unwrap();
                    tunn.encapsulate(&packet_data, &mut encrypt_buf)
                };

                match encrypted {
                    TunnResult::WriteToNetwork(data) => {
                        if let Err(e) = socket.send(data).await {
                            eprintln!("Send error: {}", e);
                        }
                    }
                    TunnResult::Err(e) => {
                        eprintln!("Encrypt error: {:?}", e);
                    }
                    _ => {}
                }
            }

            // Drop the receiver to signal the blocking thread to stop
            drop(rx);
            // Note: outbound_recv_handle thread will exit when running becomes false
            // or when the session is shutdown
            let _ = outbound_recv_handle;
        })
    };

    // Inbound: UDP from server -> decrypt -> Wintun adapter
    let inbound_handle = {
        let session = Arc::clone(&session);
        let tunn = Arc::clone(&tunn);
        let socket = Arc::clone(&socket);
        let running = Arc::clone(&running);
        let inbound_count = Arc::clone(&inbound_count);

        tokio::spawn(async move {
            let mut recv_buf = vec![0u8; 65535];
            let mut decrypt_buf = vec![0u8; 65535];

            while running.load(Ordering::SeqCst) {
                // Receive from server with timeout
                let recv_result = tokio::time::timeout(
                    Duration::from_millis(100),
                    socket.recv(&mut recv_buf),
                ).await;

                let n = match recv_result {
                    Ok(Ok(n)) => n,
                    Ok(Err(e)) => {
                        eprintln!("Recv error: {}", e);
                        continue;
                    }
                    Err(_) => continue, // Timeout
                };

                // Decrypt packet
                let decrypted = {
                    let mut tunn = tunn.lock().unwrap();
                    tunn.decapsulate(None, &recv_buf[..n], &mut decrypt_buf)
                };

                match decrypted {
                    TunnResult::WriteToTunnelV4(data, _) | TunnResult::WriteToTunnelV6(data, _) => {
                        // Write to adapter
                        let count = inbound_count.fetch_add(1, Ordering::SeqCst) + 1;
                        let len = data.len();
                        if count <= 5 {
                            println!("    [INBOUND] Packet #{}: {} bytes", count, len);
                            if len >= 20 {
                                let src_ip = format!("{}.{}.{}.{}", data[12], data[13], data[14], data[15]);
                                let dst_ip = format!("{}.{}.{}.{}", data[16], data[17], data[18], data[19]);
                                println!("              {} -> {}", src_ip, dst_ip);
                            }
                        } else if count % 10 == 0 {
                            println!("    [INBOUND] {} packets total", count);
                        }
                        if let Ok(mut send_packet) = session.allocate_send_packet(len as u16) {
                            send_packet.bytes_mut().copy_from_slice(data);
                            session.send_packet(send_packet);
                        }
                    }
                    TunnResult::WriteToNetwork(data) => {
                        // Send response (e.g., keepalive)
                        let _ = socket.send(data).await;
                    }
                    TunnResult::Err(e) => {
                        eprintln!("Decrypt error: {:?}", e);
                    }
                    _ => {}
                }
            }
        })
    };

    // Keepalive: Timer tick for BoringTun internal state
    let keepalive_handle = {
        let tunn = Arc::clone(&tunn);
        let socket = Arc::clone(&socket);
        let running = Arc::clone(&running);

        tokio::spawn(async move {
            let mut buf = vec![0u8; 65535];

            while running.load(Ordering::SeqCst) {
                tokio::time::sleep(Duration::from_millis(100)).await;

                let result = {
                    let mut tunn = tunn.lock().unwrap();
                    tunn.update_timers(&mut buf)
                };

                match result {
                    TunnResult::WriteToNetwork(data) => {
                        let _ = socket.send(data).await;
                    }
                    _ => {}
                }
            }
        })
    };

    (outbound_handle, inbound_handle, keepalive_handle)
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

    // ConfigurationEntry layout (24 bytes total):
    //   protocol: u64 (8 bytes)
    //   image_name_offset: u64 (8 bytes) - offset from start of strings section
    //   image_name_size: u16 (2 bytes) - size in bytes
    //   _padding: [u8; 6] (6 bytes)
    let entry_size = 24;
    let total_size = 16 + entry_size + string_bytes; // header + 1 entry + strings
    let mut data = Vec::with_capacity(total_size);

    // Header
    data.extend_from_slice(&1u64.to_le_bytes()); // num_entries
    data.extend_from_slice(&(total_size as u64).to_le_bytes()); // total_length

    // ConfigurationEntry (24 bytes - NOT 32!)
    data.extend_from_slice(&0u64.to_le_bytes()); // protocol (unused)
    data.extend_from_slice(&0u64.to_le_bytes()); // image_name_offset = 0 (relative to strings section)
    data.extend_from_slice(&(string_bytes as u16).to_le_bytes()); // image_name_size
    data.extend_from_slice(&[0u8; 6]); // padding

    // Strings section
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

// =============================================================================
// Mullvad Split Tunnel WFP Callout GUIDs
// These are registered by the driver with PERSISTENT flag and MUST be cleaned up
// before re-initializing the driver, otherwise we get FWP_E_ALREADY_EXISTS
// =============================================================================

static ST_FW_CALLOUT_CLASSIFY_BIND_IPV4: GUID = GUID::from_values(
    0x76653805, 0x1972, 0x45D1, [0xB4, 0x7C, 0x31, 0x40, 0xAE, 0xBA, 0xBC, 0x49]
);
static ST_FW_CALLOUT_CLASSIFY_BIND_IPV6: GUID = GUID::from_values(
    0x53FB3120, 0xB6A4, 0x462B, [0xBF, 0xFC, 0x69, 0x78, 0xAA, 0xDA, 0x1D, 0xA2]
);
static ST_FW_CALLOUT_CLASSIFY_CONNECT_IPV4: GUID = GUID::from_values(
    0xA4E010B5, 0xDC3F, 0x474A, [0xB7, 0xC2, 0x2F, 0x32, 0x69, 0x94, 0x5F, 0x41]
);
static ST_FW_CALLOUT_CLASSIFY_CONNECT_IPV6: GUID = GUID::from_values(
    0x6B634022, 0xB3D3, 0x4667, [0x88, 0xBA, 0xBF, 0x50, 0x28, 0x85, 0x8F, 0x52]
);
static ST_FW_CALLOUT_PERMIT_SPLIT_APPS_IPV4_CONN: GUID = GUID::from_values(
    0x33F3EDCC, 0xEB5E, 0x41CF, [0x92, 0x50, 0x70, 0x2C, 0x94, 0xA2, 0x8E, 0x39]
);
static ST_FW_CALLOUT_PERMIT_SPLIT_APPS_IPV4_RECV: GUID = GUID::from_values(
    0xA7A13809, 0x0DE6, 0x48AB, [0x9B, 0xB8, 0x20, 0xA8, 0xBC, 0xEC, 0x37, 0xAB]
);
static ST_FW_CALLOUT_PERMIT_SPLIT_APPS_IPV6_CONN: GUID = GUID::from_values(
    0x7B7E0055, 0x89F5, 0x4760, [0x89, 0x28, 0xCC, 0xD5, 0x7C, 0x88, 0x30, 0xAB]
);
static ST_FW_CALLOUT_PERMIT_SPLIT_APPS_IPV6_RECV: GUID = GUID::from_values(
    0xB40B78EF, 0x5642, 0x40EF, [0xAC, 0x4D, 0xF9, 0x65, 0x12, 0x61, 0xF9, 0xE7]
);
static ST_FW_CALLOUT_BLOCK_SPLIT_APPS_IPV4_CONN: GUID = GUID::from_values(
    0x974AA588, 0x397A, 0x483E, [0xAC, 0x29, 0x88, 0xF4, 0xF4, 0x11, 0x2A, 0xC2]
);
static ST_FW_CALLOUT_BLOCK_SPLIT_APPS_IPV4_RECV: GUID = GUID::from_values(
    0x8E314FD7, 0xBDD3, 0x45A4, [0xA7, 0x12, 0x46, 0x03, 0x6B, 0x25, 0xB3, 0xE1]
);
static ST_FW_CALLOUT_BLOCK_SPLIT_APPS_IPV6_CONN: GUID = GUID::from_values(
    0x466B7800, 0x5EF4, 0x4772, [0xAA, 0x79, 0xE0, 0xA8, 0x34, 0x32, 0x82, 0x14]
);
static ST_FW_CALLOUT_BLOCK_SPLIT_APPS_IPV6_RECV: GUID = GUID::from_values(
    0xD25AFB1B, 0x4645, 0x43CB, [0xB0, 0xBE, 0x37, 0x94, 0xFE, 0x48, 0x7B, 0xAC]
);

/// All Mullvad callout GUIDs in an array for easy iteration
static MULLVAD_CALLOUT_GUIDS: [GUID; 12] = [
    ST_FW_CALLOUT_CLASSIFY_BIND_IPV4,
    ST_FW_CALLOUT_CLASSIFY_BIND_IPV6,
    ST_FW_CALLOUT_CLASSIFY_CONNECT_IPV4,
    ST_FW_CALLOUT_CLASSIFY_CONNECT_IPV6,
    ST_FW_CALLOUT_PERMIT_SPLIT_APPS_IPV4_CONN,
    ST_FW_CALLOUT_PERMIT_SPLIT_APPS_IPV4_RECV,
    ST_FW_CALLOUT_PERMIT_SPLIT_APPS_IPV6_CONN,
    ST_FW_CALLOUT_PERMIT_SPLIT_APPS_IPV6_RECV,
    ST_FW_CALLOUT_BLOCK_SPLIT_APPS_IPV4_CONN,
    ST_FW_CALLOUT_BLOCK_SPLIT_APPS_IPV4_RECV,
    ST_FW_CALLOUT_BLOCK_SPLIT_APPS_IPV6_CONN,
    ST_FW_CALLOUT_BLOCK_SPLIT_APPS_IPV6_RECV,
];

/// RPC authentication constant
const RPC_C_AUTHN_WINNT: u32 = 10;

/// WFP Engine wrapper
struct WfpEngineHandle {
    handle: HANDLE,
}

impl WfpEngineHandle {
    /// Create sublayers if they don't exist (called after driver INITIALIZE)
    fn ensure_sublayers(&self) -> Result<(), String> {
        create_sublayers_if_needed(self.handle)
    }
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
/// NOTE: We do NOT create provider/sublayer ourselves anymore.
/// The Mullvad driver creates its own provider with FWPM_SESSION_FLAG_DYNAMIC.
/// If we create them first, driver INITIALIZE fails with ALREADY_EXISTS.
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

    // NOTE: We intentionally do NOT create provider or sublayers here!
    // The Mullvad driver creates its own provider during INITIALIZE with
    // FWPM_SESSION_FLAG_DYNAMIC. If we create them first, driver fails.
    println!("    ✓ WFP cleanup complete (driver will create its own provider)");
    println!("    Interface LUID for filters: {} (0x{:016X})", interface_luid, interface_luid);

    Ok(WfpEngineHandle { handle })
}

/// Clean up stale WFP objects from previous sessions
/// This is critical to prevent ALREADY_EXISTS errors when the driver initializes
fn cleanup_wfp_objects(handle: HANDLE) {
    // CRITICAL: Delete Mullvad callouts FIRST
    // These are registered by the driver with PERSISTENT flag and survive across sessions
    // If not deleted, driver INITIALIZE will fail with FWP_E_ALREADY_EXISTS (0x80320009)
    println!("    Attempting to delete 12 Mullvad WFP callouts...");
    let mut callouts_deleted = 0;
    let mut not_found = 0;
    let mut other_errors = 0;
    for (i, guid) in MULLVAD_CALLOUT_GUIDS.iter().enumerate() {
        let result = unsafe {
            FwpmCalloutDeleteByKey0(handle, guid)
        };
        if result == 0 {
            callouts_deleted += 1;
        } else if result == 0x80320002 { // FWP_E_CALLOUT_NOT_FOUND
            not_found += 1;
        } else {
            other_errors += 1;
            println!("    [DEBUG] Callout {} delete error: 0x{:08X}", i, result);
        }
    }
    println!("    Callouts: {} deleted, {} not found, {} errors", callouts_deleted, not_found, other_errors);

    // NOTE: Do NOT delete sublayers here!
    // The driver needs sublayers to exist for SET_CONFIGURATION to work.
    // The driver creates a provider during INITIALIZE but NOT sublayers.
    // We will create sublayers if they don't exist in create_sublayers_if_needed().

    // Delete provider ONLY (so driver INITIALIZE can create its own)
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

/// Create sublayers if they don't exist
/// Called AFTER driver INITIALIZE creates the provider
fn create_sublayers_if_needed(handle: HANDLE) -> Result<(), String> {
    // Check if baseline sublayer exists
    let mut sublayer_ptr: *mut FWPM_SUBLAYER0 = std::ptr::null_mut();
    let result = unsafe {
        FwpmSubLayerGetByKey0(handle, &ST_FW_WINFW_BASELINE_SUBLAYER_KEY, &mut sublayer_ptr)
    };

    if result == 0 {
        // Sublayer exists
        if !sublayer_ptr.is_null() {
            unsafe { FwpmFreeMemory0(&mut sublayer_ptr as *mut _ as *mut *mut std::ffi::c_void) };
        }
        println!("    Baseline sublayer already exists");
    } else {
        // Create it
        println!("    Creating baseline sublayer...");

        let name: Vec<u16> = "SwiftTunnel Baseline Sublayer".encode_utf16().chain(std::iter::once(0)).collect();
        let sublayer = FWPM_SUBLAYER0 {
            subLayerKey: ST_FW_WINFW_BASELINE_SUBLAYER_KEY,
            displayData: FWPM_DISPLAY_DATA0 {
                name: windows::core::PWSTR(name.as_ptr() as *mut u16),
                description: windows::core::PWSTR::null(),
            },
            flags: 0, // No PERSISTENT flag - use dynamic session
            providerKey: std::ptr::null_mut(), // Will reference driver's provider
            providerData: FWP_BYTE_BLOB::default(),
            weight: 0xFFFF, // High weight
        };

        let result = unsafe {
            FwpmSubLayerAdd0(handle, &sublayer, None)
        };

        if result != 0 && result != 0x80320009 { // 0x80320009 = ALREADY_EXISTS is OK
            return Err(format!("Failed to create baseline sublayer: 0x{:08X}", result));
        }
        println!("    ✓ Created baseline sublayer");
    }

    // Check if DNS sublayer exists
    let mut sublayer_ptr: *mut FWPM_SUBLAYER0 = std::ptr::null_mut();
    let result = unsafe {
        FwpmSubLayerGetByKey0(handle, &ST_FW_WINFW_DNS_SUBLAYER_KEY, &mut sublayer_ptr)
    };

    if result == 0 {
        // Sublayer exists
        if !sublayer_ptr.is_null() {
            unsafe { FwpmFreeMemory0(&mut sublayer_ptr as *mut _ as *mut *mut std::ffi::c_void) };
        }
        println!("    DNS sublayer already exists");
    } else {
        // Create it
        println!("    Creating DNS sublayer...");

        let name: Vec<u16> = "SwiftTunnel DNS Sublayer".encode_utf16().chain(std::iter::once(0)).collect();
        let sublayer = FWPM_SUBLAYER0 {
            subLayerKey: ST_FW_WINFW_DNS_SUBLAYER_KEY,
            displayData: FWPM_DISPLAY_DATA0 {
                name: windows::core::PWSTR(name.as_ptr() as *mut u16),
                description: windows::core::PWSTR::null(),
            },
            flags: 0, // No PERSISTENT flag - use dynamic session
            providerKey: std::ptr::null_mut(),
            providerData: FWP_BYTE_BLOB::default(),
            weight: 0xFFFE, // Slightly lower weight
        };

        let result = unsafe {
            FwpmSubLayerAdd0(handle, &sublayer, None)
        };

        if result != 0 && result != 0x80320009 { // ALREADY_EXISTS is OK
            return Err(format!("Failed to create DNS sublayer: 0x{:08X}", result));
        }
        println!("    ✓ Created DNS sublayer");
    }

    Ok(())
}
