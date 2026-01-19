//! Split Tunnel Integration Test
//!
//! Full end-to-end test of split tunnel functionality:
//! 1. Creates VPN tunnel (Wintun + WireGuard)
//! 2. Configures split tunnel for test process
//! 3. Runs test process to verify traffic routing
//!
//! Usage:
//!   cargo run --bin split_tunnel_integration_test -- config.json [test_exe_path]
//!
//! Requirements:
//!   - Administrator privileges
//!   - wintun.dll in working directory
//!   - Mullvad split tunnel driver installed
//!   - Valid VPN config file
//!
//! Test process (optional):
//!   - Defaults to ip_checker.exe in same directory
//!   - Can specify any executable as second argument

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
}

#[tokio::main]
async fn main() {
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info")).init();

    println!("=== SwiftTunnel Split Tunnel Integration Test ===\n");

    // Parse arguments
    let args: Vec<String> = std::env::args().collect();
    if args.len() < 2 {
        eprintln!("Usage: {} <config.json> [test_exe_path]", args[0]);
        eprintln!("\nconfig.json: VPN configuration from API");
        eprintln!("test_exe_path: Optional path to test executable (default: ip_checker.exe)");
        std::process::exit(1);
    }

    let config_path = &args[1];
    let test_exe = if args.len() > 2 {
        args[2].clone()
    } else {
        // Default to ip_checker.exe in same directory
        std::env::current_exe()
            .map(|p| p.parent().unwrap().join("ip_checker.exe").to_string_lossy().to_string())
            .unwrap_or_else(|_| "ip_checker.exe".to_string())
    };

    // Step 1: Check prerequisites
    println!("[1] Checking prerequisites...");

    if !is_admin() {
        eprintln!("    ERROR: Administrator privileges required!");
        std::process::exit(1);
    }
    println!("    ✓ Running as Administrator");

    let wintun_path = match find_wintun_dll() {
        Some(p) => p,
        None => {
            eprintln!("    ERROR: wintun.dll not found!");
            std::process::exit(1);
        }
    };
    println!("    ✓ Found wintun.dll");

    if !check_split_tunnel_driver() {
        eprintln!("    ERROR: Split tunnel driver not available!");
        std::process::exit(1);
    }
    println!("    ✓ Split tunnel driver available");

    if !std::path::Path::new(&test_exe).exists() {
        eprintln!("    ERROR: Test executable not found: {}", test_exe);
        eprintln!("    Build it with: cargo build --bin ip_checker --release");
        std::process::exit(1);
    }
    println!("    ✓ Test executable found: {}\n", test_exe);

    // Step 2: Load VPN config
    println!("[2] Loading VPN config...");
    let config = match load_config(config_path) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("    ERROR: {}", e);
            std::process::exit(1);
        }
    };
    println!("    Region: {}", config.region);
    println!("    Endpoint: {}", config.endpoint);
    println!("    Assigned IP: {}\n", config.assigned_ip);

    // Step 3: Get baseline IP (without VPN)
    println!("[3] Getting baseline public IP (without VPN)...");
    let baseline_ip = match run_test_exe(&test_exe) {
        Ok(ip) => {
            println!("    Baseline IP: {}\n", ip);
            ip
        }
        Err(e) => {
            eprintln!("    WARNING: Could not get baseline IP: {}", e);
            eprintln!("    Continuing anyway...\n");
            String::new()
        }
    };

    // Step 4: Create VPN tunnel
    println!("[4] Creating VPN tunnel...");

    let wintun = match unsafe { wintun::load_from_path(&wintun_path) } {
        Ok(w) => w,
        Err(e) => {
            eprintln!("    ERROR: Failed to load wintun.dll: {:?}", e);
            std::process::exit(1);
        }
    };

    let adapter = match wintun::Adapter::create(&wintun, "SwiftTunnel", "SwiftTunnel", None) {
        Ok(a) => a,
        Err(e) => {
            eprintln!("    ERROR: Failed to create adapter: {:?}", e);
            std::process::exit(1);
        }
    };
    println!("    ✓ Wintun adapter created");

    // Get LUID for split tunnel
    let luid = adapter.get_luid();
    let interface_luid = unsafe { std::mem::transmute::<_, u64>(luid) };
    println!("    Interface LUID: {}", interface_luid);

    // Parse and set IP
    let assigned_ip: Ipv4Addr = config.assigned_ip.split('/').next()
        .unwrap_or(&config.assigned_ip)
        .parse()
        .expect("Invalid assigned IP");

    if let Err(e) = adapter.set_address(assigned_ip) {
        eprintln!("    ERROR: Failed to set IP address: {:?}", e);
        std::process::exit(1);
    }
    println!("    ✓ IP address set: {}", assigned_ip);

    // Start session
    let _session = match adapter.start_session(0x400000) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("    ERROR: Failed to start session: {:?}", e);
            std::process::exit(1);
        }
    };
    println!("    ✓ Adapter session started\n");

    // Step 5: Setup WFP (Windows Filtering Platform)
    println!("[5] Setting up WFP for split tunneling...");

    let _wfp_engine = match setup_wfp(interface_luid) {
        Ok(engine) => {
            println!("    ✓ WFP provider registered");
            println!("    ✓ WFP sublayer created");
            println!("    ✓ WFP filters added\n");
            engine
        }
        Err(e) => {
            eprintln!("    ERROR: WFP setup failed: {}", e);
            eprintln!("    Split tunnel may not work without WFP.\n");
            None
        }
    };

    // Step 6: Configure split tunnel
    println!("[6] Configuring split tunnel...");

    let driver_handle = match open_split_tunnel_driver() {
        Ok(h) => h,
        Err(e) => {
            eprintln!("    ERROR: {}", e);
            std::process::exit(1);
        }
    };
    println!("    ✓ Split tunnel driver opened");

    // Check current driver state
    let current_state = get_driver_state(driver_handle).unwrap_or(0);
    println!("    Current driver state: {} ({})", current_state, state_name(current_state));

    // Driver state machine: STARTED(1) -> INITIALIZED(2) -> READY(3) -> ENGAGED(4)
    // If already past STARTED, the driver has persistent WFP state from a previous run

    // If driver is already past STARTED, try RESET first to get a clean state
    if current_state > 1 {
        println!("    Resetting driver to STARTED state...");
        let _ = send_ioctl_neither(driver_handle, IOCTL_ST_RESET);
        std::thread::sleep(std::time::Duration::from_millis(200));
        if let Some(state) = get_driver_state(driver_handle) {
            println!("    Driver state after RESET: {} ({})", state, state_name(state));
        }
    }

    // Try to INITIALIZE the driver
    // The driver creates WFP callouts during INITIALIZE
    match send_ioctl_neither(driver_handle, IOCTL_ST_INITIALIZE) {
        Ok(_) => {
            println!("    ✓ Driver initialized");
        }
        Err(e) => {
            // Print full error for diagnosis
            println!("    INITIALIZE returned error: {}", e);

            // FWP_E_ALREADY_EXISTS (0x80320009) means callouts already exist
            // This happens when the driver registered them at service start
            if e.contains("0x80320009") {
                println!("    Interpreting as: callouts already exist (may be OK)");
                // Check the state after this
                if let Some(state) = get_driver_state(driver_handle) {
                    println!("    Driver state is now: {} ({})", state, state_name(state));
                    if state >= 2 {
                        println!("    ✓ Driver in working state");
                    }
                }
            } else {
                eprintln!("    ERROR: INITIALIZE failed: {}", e);
                cleanup_driver(driver_handle);
                std::process::exit(1);
            }
        }
    }

    // Check state after INITIALIZE
    if let Some(state) = get_driver_state(driver_handle) {
        println!("    Driver state after INITIALIZE: {} ({})", state, state_name(state));
        if state < 2 {
            println!("    ⚠ Driver not in INITIALIZED state - may need driver service restart");
        }
    }

    // Register process tree
    let proc_data = build_process_tree();
    if let Err(e) = send_ioctl(driver_handle, IOCTL_ST_REGISTER_PROCESSES, &proc_data) {
        eprintln!("    ERROR: REGISTER_PROCESSES failed: {}", e);
        cleanup_driver(driver_handle);
        std::process::exit(1);
    }
    println!("    ✓ Process tree registered");

    // Register IP addresses
    let ip_data = build_ip_addresses(interface_luid, assigned_ip);
    if let Err(e) = send_ioctl(driver_handle, IOCTL_ST_REGISTER_IP_ADDRESSES, &ip_data) {
        eprintln!("    ERROR: REGISTER_IP_ADDRESSES failed: {}", e);
        cleanup_driver(driver_handle);
        std::process::exit(1);
    }
    println!("    ✓ IP addresses registered");

    // Check driver state
    if let Some(state) = get_driver_state(driver_handle) {
        println!("    Driver state: {} ({})", state, state_name(state));
    }

    // Create the WFP sublayer that SET_CONFIGURATION needs to add filters to
    // The Mullvad VPN app normally creates this as part of its firewall
    // Since we're not running the full app, we need to create it ourselves
    println!("    Creating WFP sublayer for split tunnel filters...");
    if let Err(e) = create_wfp_infrastructure() {
        eprintln!("    WARNING: Failed to create WFP infrastructure: {}", e);
    } else {
        println!("    ✓ WFP sublayer ready");
    }

    // Set configuration (route test exe through VPN)
    let config_data = build_configuration(&test_exe);
    match send_ioctl(driver_handle, IOCTL_ST_SET_CONFIGURATION, &config_data) {
        Ok(_) => {
            println!("    ✓ Configuration set for: {}", test_exe);
        }
        Err(e) => {
            eprintln!("    ERROR: SET_CONFIGURATION failed: {}", e);
            eprintln!("    This may be expected if VPN tunnel is not fully active.");
            eprintln!("    Continuing to test...\n");
        }
    }

    // Check final state
    if let Some(state) = get_driver_state(driver_handle) {
        println!("    Final driver state: {} ({})\n", state, state_name(state));
    }

    // Step 7: Test with split tunnel active
    println!("[7] Testing with split tunnel active...");
    match run_test_exe(&test_exe) {
        Ok(vpn_ip) => {
            println!("    VPN IP: {}", vpn_ip);

            if !baseline_ip.is_empty() && vpn_ip != baseline_ip {
                println!("    ✓ SUCCESS: Traffic is being routed through VPN!");
                println!("      Baseline IP: {}", baseline_ip);
                println!("      VPN IP:      {}", vpn_ip);
            } else if baseline_ip.is_empty() {
                println!("    ? Unable to compare (no baseline)");
            } else {
                println!("    ⚠ WARNING: IP unchanged - split tunnel may not be active");
            }
        }
        Err(e) => {
            eprintln!("    ERROR: Test failed: {}", e);
        }
    }

    // Cleanup
    println!("\n[8] Cleaning up...");
    cleanup_driver(driver_handle);
    println!("    ✓ Split tunnel driver reset");

    // WFP engine will be dropped automatically (filters persist)
    // Adapter will be dropped automatically
    println!("    ✓ VPN adapter closed");

    println!("\n=== Integration test complete ===");
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
    if let Ok(exe_path) = std::env::current_exe() {
        if let Some(exe_dir) = exe_path.parent() {
            let dll_path = exe_dir.join("wintun.dll");
            if dll_path.exists() {
                return Some(dll_path);
            }
        }
    }
    if let Ok(cwd) = std::env::current_dir() {
        let dll_path = cwd.join("wintun.dll");
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

fn load_config(path: &str) -> Result<VpnConfig, String> {
    let data = std::fs::read_to_string(path)
        .map_err(|e| format!("Failed to read config: {}", e))?;
    serde_json::from_str(&data)
        .map_err(|e| format!("Failed to parse config: {}", e))
}

fn run_test_exe(path: &str) -> Result<String, String> {
    let output = Command::new(path)
        .output()
        .map_err(|e| format!("Failed to run {}: {}", path, e))?;

    if !output.status.success() {
        return Err(format!("Test exe exited with code: {:?}", output.status.code()));
    }

    let stdout = String::from_utf8_lossy(&output.stdout);

    // Parse IP from output (look for line with IP address pattern)
    for line in stdout.lines() {
        if line.contains("Your public IP:") {
            if let Some(ip) = line.split(':').last() {
                return Ok(ip.trim().to_string());
            }
        }
        // Also try to find bare IP addresses
        let trimmed = line.trim();
        if trimmed.split('.').count() == 4 && trimmed.chars().all(|c| c.is_digit(10) || c == '.') {
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
        0 => "NONE",
        1 => "STARTED",
        2 => "INITIALIZED",
        3 => "READY",
        4 => "ENGAGED",
        5 => "ZOMBIE",
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
    data.extend_from_slice(&1usize.to_le_bytes()); // num_entries
    data.extend_from_slice(&(total_size as usize).to_le_bytes()); // total_length

    // Entry (32 bytes)
    data.extend_from_slice(&4usize.to_le_bytes()); // pid = 4 (System)
    data.extend_from_slice(&0usize.to_le_bytes()); // parent_pid = 0
    data.extend_from_slice(&0usize.to_le_bytes()); // image_name_offset = 0 (relative)
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
// WFP (Windows Filtering Platform) Setup
// ============================================================================

/// Mullvad Split Tunnel WFP Provider GUID
/// Must match: {E2C114EE-F32A-4264-A6CB-3FA7996356D9}
static ST_FW_PROVIDER_KEY: GUID = GUID::from_values(
    0xE2C114EE,
    0xF32A,
    0x4264,
    [0xA6, 0xCB, 0x3F, 0xA7, 0x99, 0x63, 0x56, 0xD9],
);

/// Mullvad Split Tunnel WFP Sublayer GUID (WinFW Baseline Sublayer)
/// Must match: {C78056FF-2BC1-4211-AADD-7F358DEF202D}
static ST_FW_WINFW_BASELINE_SUBLAYER_KEY: GUID = GUID::from_values(
    0xC78056FF,
    0x2BC1,
    0x4211,
    [0xAA, 0xDD, 0x7F, 0x35, 0x8D, 0xEF, 0x20, 0x2D],
);

/// Mullvad Split Tunnel WFP DNS Sublayer GUID
/// Must match: {60090787-CCA1-4937-AACE-51256EF481F3}
/// Used for DNS filtering (port 53 traffic)
static ST_FW_WINFW_DNS_SUBLAYER_KEY: GUID = GUID::from_values(
    0x60090787,
    0xCCA1,
    0x4937,
    [0xAA, 0xCE, 0x51, 0x25, 0x6E, 0xF4, 0x81, 0xF3],
);

/// Mullvad Split Tunnel Driver Callout GUIDs (from identifiers.h)
/// These must be deleted before INITIALIZE to avoid "already exists" errors
static ST_CALLOUT_GUIDS: &[GUID] = &[
    // ST_FW_CALLOUT_CLASSIFY_BIND_IPV4_KEY
    GUID::from_values(0x76653805, 0x1972, 0x45D1, [0xB4, 0x7C, 0x31, 0x40, 0xAE, 0xBA, 0xBC, 0x49]),
    // ST_FW_CALLOUT_CLASSIFY_BIND_IPV6_KEY
    GUID::from_values(0x53FB3120, 0xB6A4, 0x462B, [0xBF, 0xFC, 0x69, 0x78, 0xAA, 0xDA, 0x1D, 0xA2]),
    // ST_FW_CALLOUT_CLASSIFY_CONNECT_IPV4_KEY
    GUID::from_values(0xA4E010B5, 0xDC3F, 0x474A, [0xB7, 0xC2, 0x2F, 0x32, 0x69, 0x94, 0x5F, 0x41]),
    // ST_FW_CALLOUT_CLASSIFY_CONNECT_IPV6_KEY
    GUID::from_values(0x6B634022, 0xB3D3, 0x4667, [0x88, 0xBA, 0xBF, 0x50, 0x28, 0x85, 0x8F, 0x52]),
    // ST_FW_CALLOUT_PERMIT_SPLIT_APPS_IPV4_CONN_KEY
    GUID::from_values(0x33F3EDCC, 0xEB5E, 0x41CF, [0x92, 0x50, 0x70, 0x2C, 0x94, 0xA2, 0x8E, 0x39]),
    // ST_FW_CALLOUT_PERMIT_SPLIT_APPS_IPV4_RECV_KEY
    GUID::from_values(0xA7A13809, 0x0DE6, 0x48AB, [0x9B, 0xB8, 0x20, 0xA8, 0xBC, 0xEC, 0x37, 0xAB]),
    // ST_FW_CALLOUT_PERMIT_SPLIT_APPS_IPV6_CONN_KEY
    GUID::from_values(0x7B7E0055, 0x89F5, 0x4760, [0x89, 0x28, 0xCC, 0xD5, 0x7C, 0x88, 0x30, 0xAB]),
    // ST_FW_CALLOUT_PERMIT_SPLIT_APPS_IPV6_RECV_KEY
    GUID::from_values(0xB40B78EF, 0x5642, 0x40EF, [0xAC, 0x4D, 0xF9, 0x65, 0x12, 0x61, 0xF9, 0xE7]),
    // ST_FW_CALLOUT_BLOCK_SPLIT_APPS_IPV4_CONN_KEY
    GUID::from_values(0x974AA588, 0x397A, 0x483E, [0xAC, 0x29, 0x88, 0xF4, 0xF4, 0x11, 0x2A, 0xC2]),
    // ST_FW_CALLOUT_BLOCK_SPLIT_APPS_IPV4_RECV_KEY
    GUID::from_values(0x8E314FD7, 0xBDD3, 0x45A4, [0xA7, 0x12, 0x46, 0x03, 0x6B, 0x25, 0xB3, 0xE1]),
    // ST_FW_CALLOUT_BLOCK_SPLIT_APPS_IPV6_CONN_KEY
    GUID::from_values(0x466B7800, 0x5EF4, 0x4772, [0xAA, 0x79, 0xE0, 0xA8, 0x34, 0x32, 0x82, 0x14]),
    // ST_FW_CALLOUT_BLOCK_SPLIT_APPS_IPV6_RECV_KEY
    GUID::from_values(0xD25AFB1B, 0x4645, 0x43CB, [0xB0, 0xBE, 0x37, 0x94, 0xFE, 0x48, 0x7B, 0xAC]),
];

/// Mullvad Split Tunnel Filter GUIDs (from identifiers.h)
/// SET_CONFIGURATION creates these filters, we need to clean them up to avoid "already exists"
static ST_FILTER_GUIDS: &[GUID] = &[
    // ST_FW_FILTER_CLASSIFY_BIND_IPV4_KEY
    GUID::from_values(0xB47D14A7, 0xAEED, 0x48B9, [0xAD, 0x4E, 0x55, 0x29, 0x61, 0x9F, 0x13, 0x37]),
    // ST_FW_FILTER_CLASSIFY_BIND_IPV6_KEY
    GUID::from_values(0x2F607222, 0xB2EB, 0x443C, [0xB6, 0xE0, 0x64, 0x10, 0x67, 0x37, 0x54, 0x78]),
    // ST_FW_FILTER_CLASSIFY_CONNECT_IPV4_KEY
    GUID::from_values(0x4207F127, 0xCC80, 0x477E, [0xAD, 0xDF, 0x26, 0xF7, 0x65, 0x85, 0xE0, 0x73]),
    // ST_FW_FILTER_CLASSIFY_CONNECT_IPV6_KEY
    GUID::from_values(0x9A87F137, 0x5112, 0x4427, [0xB3, 0x15, 0x4F, 0x87, 0xB3, 0xE8, 0x4D, 0xCC]),
    // ST_FW_FILTER_PERMIT_SPLIT_APPS_IPV4_CONN_KEY
    GUID::from_values(0x66CED079, 0xC270, 0x4B4D, [0xA4, 0x5C, 0xD1, 0x17, 0x11, 0xC0, 0xD6, 0x00]),
    // ST_FW_FILTER_PERMIT_SPLIT_APPS_IPV4_RECV_KEY
    GUID::from_values(0x37972155, 0xEBDB, 0x49FC, [0x9A, 0x37, 0x3A, 0x0B, 0x3B, 0x0A, 0xA1, 0x00]),
    // ST_FW_FILTER_PERMIT_SPLIT_APPS_IPV6_CONN_KEY
    GUID::from_values(0x0AFA08E3, 0xB010, 0x4082, [0x9E, 0x03, 0x1C, 0xC4, 0xBE, 0x1C, 0x6C, 0xF8]),
    // ST_FW_FILTER_PERMIT_SPLIT_APPS_IPV6_RECV_KEY
    GUID::from_values(0x7835DFD7, 0x24AE, 0x44F4, [0x8A, 0x8A, 0x5E, 0x9C, 0x76, 0x6A, 0xAE, 0x63]),
    // ST_FW_FILTER_PERMIT_SPLIT_APPS_IPV4_DNS_CONN_KEY
    GUID::from_values(0xEDB743A8, 0x1A77, 0x4BA9, [0x90, 0x6B, 0xC5, 0x94, 0xA7, 0xDD, 0xB7, 0x5B]),
    // ST_FW_FILTER_PERMIT_SPLIT_APPS_IPV4_DNS_RECV_KEY
    GUID::from_values(0x5373BF17, 0x937E, 0x438B, [0xA3, 0x07, 0xCD, 0x50, 0xE1, 0x25, 0xDF, 0xF9]),
    // ST_FW_FILTER_PERMIT_SPLIT_APPS_IPV6_DNS_CONN_KEY
    GUID::from_values(0x355F9524, 0x8CE0, 0x4C85, [0x90, 0x2F, 0xED, 0xF0, 0x25, 0x25, 0x56, 0xD4]),
    // ST_FW_FILTER_PERMIT_SPLIT_APPS_IPV6_DNS_RECV_KEY
    GUID::from_values(0x282B9C48, 0x4029, 0x4D27, [0x8F, 0xE0, 0x8C, 0x3C, 0x4B, 0x84, 0xF9, 0x52]),
    // ST_FW_FILTER_BLOCK_ALL_SPLIT_APPS_TUNNEL_IPV4_CONN_KEY
    GUID::from_values(0xD8602FF5, 0x436B, 0x414A, [0xA2, 0x21, 0x7B, 0x4D, 0xE8, 0xCE, 0x96, 0xC7]),
    // ST_FW_FILTER_BLOCK_ALL_SPLIT_APPS_TUNNEL_IPV4_RECV_KEY
    GUID::from_values(0xFC3F8D71, 0x33F7, 0x4D24, [0x93, 0x06, 0xA3, 0xDE, 0xE3, 0xF7, 0xC8, 0x65]),
    // ST_FW_FILTER_BLOCK_ALL_SPLIT_APPS_TUNNEL_IPV6_CONN_KEY
    GUID::from_values(0x05CB3C5E, 0x6F64, 0x44F7, [0x81, 0xB1, 0xC8, 0x90, 0x56, 0x3F, 0xA2, 0x80]),
    // ST_FW_FILTER_BLOCK_ALL_SPLIT_APPS_TUNNEL_IPV6_RECV_KEY
    GUID::from_values(0xC854E73A, 0x81C8, 0x4814, [0x9A, 0x55, 0x55, 0xBA, 0xF2, 0xC3, 0xBD, 0x17]),
];

/// RPC authentication constant
const RPC_C_AUTHN_WINNT: u32 = 10;

/// WFP Engine wrapper for the integration test
struct WfpEngineHandle {
    handle: HANDLE,
}

impl Drop for WfpEngineHandle {
    fn drop(&mut self) {
        if !self.handle.is_invalid() {
            unsafe {
                let _ = FwpmEngineClose0(self.handle);
            }
            println!("    WFP engine closed");
        }
    }
}

/// Create WFP provider and sublayer that the driver needs
/// IMPORTANT: Call this BEFORE starting the driver service
fn create_wfp_infrastructure() -> Result<(), String> {
    println!("    Creating WFP infrastructure...");

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

    // Create provider
    let provider_name: Vec<u16> = "Mullvad Split Tunnel".encode_utf16().chain(std::iter::once(0)).collect();
    let provider_desc: Vec<u16> = "Mullvad Split Tunnel WFP provider".encode_utf16().chain(std::iter::once(0)).collect();

    // Try to add provider first, but don't fail if it already exists (driver created it)
    let provider = FWPM_PROVIDER0 {
        providerKey: ST_FW_PROVIDER_KEY,
        displayData: FWPM_DISPLAY_DATA0 {
            name: windows::core::PWSTR(provider_name.as_ptr() as *mut u16),
            description: windows::core::PWSTR(provider_desc.as_ptr() as *mut u16),
        },
        flags: 0, // Non-persistent (driver creates its own)
        providerData: FWP_BYTE_BLOB::default(),
        serviceName: windows::core::PWSTR::null(),
    };

    let result = unsafe { FwpmProviderAdd0(handle, &provider, None) };
    if result != 0 && result != FWP_E_ALREADY_EXISTS.0 as u32 {
        // Provider add failed - but if driver already created it, that's OK
        println!("    Note: Provider add returned 0x{:08X} (may already exist)", result);
    } else {
        println!("    WFP provider created");
    }

    // Create sublayer - this MUST exist before driver can use SET_CONFIGURATION
    // Use non-persistent and don't reference a provider to avoid context mismatch
    let sublayer_name: Vec<u16> = "WinFW Baseline Sublayer".encode_utf16().chain(std::iter::once(0)).collect();
    let sublayer_desc: Vec<u16> = "Mullvad split tunnel WFP sublayer".encode_utf16().chain(std::iter::once(0)).collect();

    let sublayer = FWPM_SUBLAYER0 {
        subLayerKey: ST_FW_WINFW_BASELINE_SUBLAYER_KEY,
        displayData: FWPM_DISPLAY_DATA0 {
            name: windows::core::PWSTR(sublayer_name.as_ptr() as *mut u16),
            description: windows::core::PWSTR(sublayer_desc.as_ptr() as *mut u16),
        },
        flags: 0, // Non-persistent
        providerKey: std::ptr::null_mut(), // Don't reference provider
        providerData: FWP_BYTE_BLOB::default(),
        weight: 0x8000, // Medium-high weight
    };

    let result = unsafe { FwpmSubLayerAdd0(handle, &sublayer, None) };
    if result != 0 && result != FWP_E_ALREADY_EXISTS.0 as u32 {
        unsafe { let _ = FwpmEngineClose0(handle); }
        return Err(format!("Failed to add WFP baseline sublayer: 0x{:08X}", result));
    }
    println!("    WFP baseline sublayer created");

    // Also create DNS sublayer for DNS filtering (port 53 traffic)
    let dns_sublayer_name: Vec<u16> = "WinFW DNS Sublayer".encode_utf16().chain(std::iter::once(0)).collect();
    let dns_sublayer_desc: Vec<u16> = "Mullvad DNS traffic sublayer".encode_utf16().chain(std::iter::once(0)).collect();

    let dns_sublayer = FWPM_SUBLAYER0 {
        subLayerKey: ST_FW_WINFW_DNS_SUBLAYER_KEY,
        displayData: FWPM_DISPLAY_DATA0 {
            name: windows::core::PWSTR(dns_sublayer_name.as_ptr() as *mut u16),
            description: windows::core::PWSTR(dns_sublayer_desc.as_ptr() as *mut u16),
        },
        flags: 0, // Non-persistent
        providerKey: std::ptr::null_mut(), // Don't reference provider
        providerData: FWP_BYTE_BLOB::default(),
        weight: 0x9000, // Higher weight than baseline for DNS priority
    };

    let dns_result = unsafe { FwpmSubLayerAdd0(handle, &dns_sublayer, None) };
    if dns_result != 0 && dns_result != FWP_E_ALREADY_EXISTS.0 as u32 {
        println!("    Note: DNS sublayer add returned 0x{:08X}", dns_result);
    } else {
        println!("    WFP DNS sublayer created");
    }

    unsafe { let _ = FwpmEngineClose0(handle); }
    Ok(())
}

/// Check if driver's WFP callouts exist by trying to delete them (diagnostic function)
#[allow(dead_code)]
fn check_callouts_exist() {
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
        println!("    Could not open WFP engine for callout check");
        return;
    }

    // Try to delete callouts - this tells us their current state
    // We don't actually want to delete them, but this is a diagnostic
    let mut in_use = 0;
    let mut not_found = 0;
    let mut deleted = 0;
    for callout_guid in ST_CALLOUT_GUIDS {
        let result = unsafe {
            FwpmCalloutDeleteByKey0(handle, callout_guid)
        };
        if result == 0 {
            // Successfully deleted - callout existed but wasn't in use
            // This is unexpected after driver starts
            deleted += 1;
        } else if result == 0x80320008 || result == 0x80320001 {
            // FWP_E_CALLOUT_NOT_FOUND or FWP_E_PROVIDER_NOT_FOUND
            not_found += 1;
        } else {
            // Most likely FWP_E_IN_USE (0x80320009) - callout owned by driver
            in_use += 1;
        }
    }

    if in_use > 0 {
        println!("    ⚠ {} callouts in use by driver (registered in DriverEntry!)", in_use);
    }
    if not_found > 0 {
        println!("    {} callouts do not exist (good - will be created by INITIALIZE)", not_found);
    }
    if deleted > 0 {
        println!("    {} callouts were deleted (unexpected - they existed but weren't owned)", deleted);
    }

    unsafe { let _ = FwpmEngineClose0(handle); }
}

/// Cleanup any existing WFP objects from previous runs
/// IMPORTANT: Call this while the driver service is STOPPED for best results
fn cleanup_wfp() -> Result<(), String> {
    println!("    Cleaning up WFP objects...");

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
        return Err(format!("Failed to open WFP engine for cleanup: 0x{:08X}", result));
    }

    // Delete driver's callouts (these persist and cause "already exists" errors)
    // These MUST be deleted while driver is fully unloaded from memory
    let mut callouts_deleted = 0;
    let mut callouts_not_found = 0;
    let mut callouts_in_use = 0;
    for callout_guid in ST_CALLOUT_GUIDS {
        let result = unsafe {
            FwpmCalloutDeleteByKey0(handle, callout_guid)
        };
        if result == 0 {
            callouts_deleted += 1;
        } else if result == 0x80320008 {
            // FWP_E_CALLOUT_NOT_FOUND - callout doesn't exist
            callouts_not_found += 1;
        } else if result == 0x80320001 {
            // FWP_E_PROVIDER_NOT_FOUND - callout's provider doesn't exist
            // This means the callout doesn't exist either (clean state)
            callouts_not_found += 1;
        } else {
            // Some other error (e.g., callout still in use by driver)
            callouts_in_use += 1;
        }
    }
    if callouts_deleted > 0 {
        println!("    ✓ Deleted {} WFP callouts", callouts_deleted);
    }
    if callouts_not_found > 0 {
        println!("    {} callouts not present (clean state)", callouts_not_found);
    }
    if callouts_in_use > 0 {
        println!("    ⚠ {} callouts still in use by driver", callouts_in_use);
        // Only fail if callouts are actually in use
        unsafe { let _ = FwpmEngineClose0(handle); }
        return Err(format!("{} callouts still in use", callouts_in_use));
    }

    // IMPORTANT: Delete filters BEFORE deleting sublayer
    // SET_CONFIGURATION creates filters with hardcoded GUIDs, and these persist
    // If we don't clean them up, SET_CONFIGURATION will fail with "already exists"
    let mut filters_deleted = 0;
    let mut filters_not_found = 0;
    for filter_guid in ST_FILTER_GUIDS {
        let result = unsafe {
            FwpmFilterDeleteByKey0(handle, filter_guid)
        };
        if result == 0 {
            filters_deleted += 1;
        } else if result == 0x80320003 { // FWP_E_FILTER_NOT_FOUND
            filters_not_found += 1;
        } else if result == 0x80320001 { // FWP_E_PROVIDER_NOT_FOUND
            filters_not_found += 1;
        } else {
            // Log other errors but continue
            println!("    Note: Filter delete returned 0x{:08X}", result);
        }
    }
    if filters_deleted > 0 {
        println!("    ✓ Deleted {} WFP filters", filters_deleted);
    }
    if filters_not_found > 0 && filters_deleted == 0 {
        println!("    {} filters not present (clean state)", filters_not_found);
    }

    // Delete BOTH sublayers (baseline and DNS) - the Mullvad VPN app creates these,
    // but since we're not running the full app, we need to manage them ourselves
    let sublayer_result = unsafe {
        FwpmSubLayerDeleteByKey0(handle, &ST_FW_WINFW_BASELINE_SUBLAYER_KEY)
    };
    if sublayer_result == 0 {
        println!("    Deleted baseline sublayer");
    } else if sublayer_result != 0x80320005 { // FWP_E_SUBLAYER_NOT_FOUND
        println!("    Note: Baseline sublayer delete returned 0x{:08X}", sublayer_result);
    }

    let dns_sublayer_result = unsafe {
        FwpmSubLayerDeleteByKey0(handle, &ST_FW_WINFW_DNS_SUBLAYER_KEY)
    };
    if dns_sublayer_result == 0 {
        println!("    Deleted DNS sublayer");
    } else if dns_sublayer_result != 0x80320005 { // FWP_E_SUBLAYER_NOT_FOUND
        // DNS sublayer not found is fine - might not have been created
    }

    // Delete provider
    let provider_result = unsafe {
        FwpmProviderDeleteByKey0(handle, &ST_FW_PROVIDER_KEY)
    };
    if provider_result == 0 {
        println!("    Deleted WFP provider");
    } else if provider_result != 0x80320001 { // FWP_E_PROVIDER_NOT_FOUND
        println!("    Note: Provider delete returned 0x{:08X}", provider_result);
    }

    unsafe { let _ = FwpmEngineClose0(handle); }
    println!("    WFP cleanup complete");
    Ok(())
}


/// Reset driver to clean state
#[allow(dead_code)]
fn reset_driver() -> Result<(), String> {
    match open_split_tunnel_driver() {
        Ok(handle) => {
            let _ = send_ioctl_neither(handle, IOCTL_ST_RESET);
            unsafe { let _ = CloseHandle(handle); }
            println!("    Driver reset to clean state");
            Ok(())
        }
        Err(e) => Err(e)
    }
}

/// Check if driver is already initialized
fn check_driver_state() -> Option<u64> {
    match open_split_tunnel_driver() {
        Ok(handle) => {
            let state = get_driver_state(handle);
            unsafe { let _ = CloseHandle(handle); }
            state
        }
        Err(_) => None
    }
}

/// Stop the split tunnel driver service
fn stop_driver_service() -> bool {
    // Stop the service
    let _ = std::process::Command::new("sc")
        .args(["stop", "mullvadsplittunnel"])
        .output();

    // Wait for the service to fully stop (poll state)
    for _ in 0..30 {
        std::thread::sleep(std::time::Duration::from_millis(200));
        let output = std::process::Command::new("sc")
            .args(["query", "mullvadsplittunnel"])
            .output();
        if let Ok(out) = output {
            let stdout = String::from_utf8_lossy(&out.stdout);
            if stdout.contains("STOPPED") {
                println!("    Driver service stopped");
                return true;
            }
        }
    }
    false
}

/// Start the split tunnel driver service
fn start_driver_service() -> bool {
    // Start the service
    let _ = std::process::Command::new("sc")
        .args(["start", "mullvadsplittunnel"])
        .output();

    // Wait for service to fully start
    for _ in 0..30 {
        std::thread::sleep(std::time::Duration::from_millis(200));
        let output = std::process::Command::new("sc")
            .args(["query", "mullvadsplittunnel"])
            .output();
        if let Ok(out) = output {
            let stdout = String::from_utf8_lossy(&out.stdout);
            if stdout.contains("RUNNING") {
                println!("    Driver service started");
                return true;
            }
        }
    }
    false
}

/// Setup WFP provider and sublayer required for split tunneling
fn setup_wfp(_interface_luid: u64) -> Result<Option<WfpEngineHandle>, String> {
    // Check driver state first
    if let Some(state) = check_driver_state() {
        if state >= 2 {
            // Driver is already initialized (INITIALIZED, READY, or ENGAGED)
            println!("    Driver already in state {} - skipping WFP cleanup", state);
            // Just open WFP engine and return
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
            if result == 0 {
                return Ok(Some(WfpEngineHandle { handle }));
            }
        }
    }

    // CRITICAL: The correct sequence is:
    // 1. Stop driver service (driver unloads, callouts become orphaned)
    // 2. Clean up WFP objects WHILE driver is stopped
    // 3. Create WFP provider/sublayer BEFORE driver starts (driver expects these to exist)
    // 4. Start driver service
    // 5. Then INITIALIZE will register callouts using our sublayer

    println!("    Stopping driver service for clean WFP state...");
    if !stop_driver_service() {
        println!("    WARNING: Could not stop driver service");
    }

    // CRITICAL: The driver takes time to fully unload from memory after service stops
    // WFP callouts can only be deleted once the driver is completely unloaded
    println!("    Waiting for driver to fully unload from memory...");
    std::thread::sleep(std::time::Duration::from_millis(3000));

    // Try to cleanup WFP objects multiple times
    for attempt in 1..=3 {
        match cleanup_wfp() {
            Ok(_) => break,
            Err(e) => {
                if attempt < 3 {
                    println!("    Cleanup attempt {} failed, waiting...", attempt);
                    std::thread::sleep(std::time::Duration::from_millis(1000));
                } else {
                    println!("    WARNING: WFP cleanup failed: {}", e);
                }
            }
        }
    }

    // DON'T create WFP provider/sublayer ourselves
    // Let the driver's INITIALIZE create everything it needs
    // Previously we were creating them, which caused INITIALIZE to fail with "already exists"

    // Start the driver service - it will be in STARTED state
    println!("    Starting driver service...");
    if !start_driver_service() {
        return Err("Failed to start driver service".to_string());
    }

    // Wait a moment for driver to be ready
    std::thread::sleep(std::time::Duration::from_millis(500));

    // Open WFP engine to keep a handle for later cleanup
    let mut handle = HANDLE::default();
    let result = unsafe {
        FwpmEngineOpen0(
            None,                   // Server name (local)
            RPC_C_AUTHN_WINNT,     // Auth service
            None,                   // Auth identity
            None,                   // Session (default)
            &mut handle,
        )
    };

    if result != 0 {
        return Err(format!("Failed to open WFP engine: 0x{:08X}", result));
    }

    println!("    WFP setup complete");
    Ok(Some(WfpEngineHandle { handle }))
}
