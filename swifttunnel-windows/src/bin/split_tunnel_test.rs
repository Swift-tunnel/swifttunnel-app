//! Split Tunnel Driver Test Binary
//!
//! Run with: cargo run --bin split_tunnel_test
//!
//! Tests the Mullvad split tunnel driver integration.
//! Requires: Administrator privileges, driver installed

use windows::core::PCSTR;
use windows::Win32::Foundation::*;
use windows::Win32::Storage::FileSystem::*;
use windows::Win32::System::IO::DeviceIoControl;
use std::net::Ipv4Addr;

/// Driver device path (Mullvad split tunnel driver)
const DEVICE_PATH: &str = r"\\.\MULLVADSPLITTUNNEL";

/// Mullvad split tunnel device type
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
const IOCTL_ST_GET_STATE: u32 = ctl_code(ST_DEVICE_TYPE, 9, METHOD_BUFFERED, FILE_ANY_ACCESS);
const IOCTL_ST_RESET: u32 = ctl_code(ST_DEVICE_TYPE, 11, METHOD_NEITHER, FILE_ANY_ACCESS);

fn get_state_name(state: u32) -> &'static str {
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

fn get_driver_state(handle: HANDLE) -> Option<u32> {
    // Try larger buffer - driver might return more than just the state
    let mut state_buf = [0u8; 64];
    let mut bytes_returned: u32 = 0;
    let result = unsafe {
        DeviceIoControl(
            handle,
            IOCTL_ST_GET_STATE,
            None,
            0,
            Some(state_buf.as_mut_ptr() as *mut std::ffi::c_void),
            state_buf.len() as u32,
            Some(&mut bytes_returned),
            None,
        )
    };

    if let Err(e) = result {
        eprintln!("    GET_STATE failed: {}", e);
        return None;
    }

    println!("    GET_STATE returned {} bytes: {:02X?}", bytes_returned, &state_buf[..bytes_returned as usize]);

    if bytes_returned < 4 {
        return None;
    }

    // State is typically the first 4 bytes
    Some(u32::from_le_bytes([state_buf[0], state_buf[1], state_buf[2], state_buf[3]]))
}

fn print_state(handle: HANDLE, label: &str) {
    print!("    {}: ", label);
    match get_driver_state(handle) {
        Some(state) => println!("{} ({})", state, get_state_name(state)),
        None => println!("failed to query"),
    }
}

fn main() {
    println!("=== SwiftTunnel Split Tunnel Driver Test ===\n");

    // Print IOCTL codes for debugging
    println!("IOCTL codes:");
    println!("  INITIALIZE:         0x{:08X}", IOCTL_ST_INITIALIZE);
    println!("  REGISTER_PROCESSES: 0x{:08X}", IOCTL_ST_REGISTER_PROCESSES);
    println!("  REGISTER_IP_ADDRS:  0x{:08X}", IOCTL_ST_REGISTER_IP_ADDRESSES);
    println!("  SET_CONFIGURATION:  0x{:08X}", IOCTL_ST_SET_CONFIGURATION);
    println!("  GET_STATE:          0x{:08X}", IOCTL_ST_GET_STATE);
    println!("  RESET:              0x{:08X}", IOCTL_ST_RESET);
    println!();

    // Step 1: Open driver
    println!("[1] Opening Mullvad split tunnel driver...");

    let handle = unsafe {
        let path = std::ffi::CString::new(DEVICE_PATH).unwrap();
        CreateFileA(
            PCSTR(path.as_ptr() as *const u8),
            GENERIC_READ.0 | GENERIC_WRITE.0,
            FILE_SHARE_READ | FILE_SHARE_WRITE,
            None,
            OPEN_EXISTING,
            FILE_ATTRIBUTE_NORMAL,
            None,
        )
    };

    let handle = match handle {
        Ok(h) => {
            println!("    Driver opened successfully\n");
            h
        }
        Err(e) => {
            eprintln!("    Failed: {}", e);
            eprintln!("    Run: sc start MullvadSplitTunnel");
            std::process::exit(1);
        }
    };

    // Check initial state
    print_state(handle, "Initial state");
    println!();

    // Step 2: Reset first (Mullvad does this before initializing)
    println!("[2] Resetting driver...");
    if send_ioctl_neither(handle, IOCTL_ST_RESET) {
        println!("    Reset successful");
    } else {
        println!("    Reset failed (may be OK if driver was already reset)");
    }
    print_state(handle, "After reset");
    println!();

    // Step 3: Initialize driver
    println!("[3] Initializing driver...");
    if send_ioctl_neither(handle, IOCTL_ST_INITIALIZE) {
        println!("    Initialize successful");
    } else {
        eprintln!("    Initialize failed");
    }
    print_state(handle, "After initialize");
    println!();

    // Step 4: Register processes (process tree with PIDs)
    // ProcessRegistryHeader = { num_entries: usize, total_length: usize }
    // ProcessRegistryEntry = { pid: usize, parent_pid: usize, image_name_offset: usize, image_name_size: u16 }
    // Entry might be 26 bytes (no explicit padding) or 32 bytes (with padding)
    println!("[4] Registering process tree...");

    // Try multiple entry sizes to find what works
    for entry_size in [26usize, 32usize] {
        println!("  Trying entry size: {} bytes", entry_size);

        let system_path = r"\SystemRoot\System32\ntoskrnl.exe";
        let system_wide: Vec<u16> = system_path.encode_utf16().collect();
        let system_bytes = system_wide.len() * 2;

        let header_size: usize = 16;
        let total_size = header_size + entry_size + system_bytes;

        let mut proc_tree: Vec<u8> = Vec::with_capacity(total_size);

        // Header
        proc_tree.extend_from_slice(&1usize.to_le_bytes()); // num_entries = 1
        proc_tree.extend_from_slice(&(total_size as usize).to_le_bytes()); // total_length

        // Entry for System process (PID 4, parent PID 0)
        // Try offset from buffer start
        let string_offset = header_size + entry_size;
        proc_tree.extend_from_slice(&4usize.to_le_bytes()); // pid = 4 (System)
        proc_tree.extend_from_slice(&0usize.to_le_bytes()); // parent_pid = 0
        proc_tree.extend_from_slice(&(string_offset as usize).to_le_bytes()); // image_name_offset
        proc_tree.extend_from_slice(&(system_bytes as u16).to_le_bytes()); // image_name_size

        // Add padding if entry_size is 32
        if entry_size == 32 {
            proc_tree.extend_from_slice(&[0u8; 6]); // padding
        }

        // String buffer (UTF-16LE)
        for w in &system_wide {
            proc_tree.extend_from_slice(&w.to_le_bytes());
        }

        println!("    Size: {} bytes, Header: {:02X?}", proc_tree.len(), &proc_tree[..16]);

        if send_ioctl_buffered(handle, IOCTL_ST_REGISTER_PROCESSES, &proc_tree) {
            println!("    SUCCESS with entry size {}", entry_size);
            break;
        } else {
            println!("    Failed with entry size {}", entry_size);
        }

        // Also try with offset relative to string section (offset = 0)
        let mut proc_tree2: Vec<u8> = Vec::with_capacity(total_size);
        proc_tree2.extend_from_slice(&1usize.to_le_bytes());
        proc_tree2.extend_from_slice(&(total_size as usize).to_le_bytes());
        proc_tree2.extend_from_slice(&4usize.to_le_bytes());
        proc_tree2.extend_from_slice(&0usize.to_le_bytes());
        proc_tree2.extend_from_slice(&0usize.to_le_bytes()); // offset = 0 (relative to string section)
        proc_tree2.extend_from_slice(&(system_bytes as u16).to_le_bytes());
        if entry_size == 32 {
            proc_tree2.extend_from_slice(&[0u8; 6]);
        }
        for w in &system_wide {
            proc_tree2.extend_from_slice(&w.to_le_bytes());
        }

        if send_ioctl_buffered(handle, IOCTL_ST_REGISTER_PROCESSES, &proc_tree2) {
            println!("    SUCCESS with relative offset");
            break;
        }
    }

    // Try empty tree as last resort
    println!("  Trying empty process tree...");
    let empty_tree: [u8; 16] = [
        0, 0, 0, 0, 0, 0, 0, 0,  // num_entries = 0
        16, 0, 0, 0, 0, 0, 0, 0, // total_length = 16
    ];
    if send_ioctl_buffered(handle, IOCTL_ST_REGISTER_PROCESSES, &empty_tree) {
        println!("    Empty tree: SUCCESS");
    }

    print_state(handle, "After register process tree");
    println!();

    // Step 5: Register IP addresses
    println!("[5] Registering IP addresses...");

    // Format: ST_IP_ADDRESSES
    // - TunnelIpv4: IN_ADDR (4 bytes)
    // - InternetIpv4: IN_ADDR (4 bytes)
    // - TunnelIpv6: IN6_ADDR (16 bytes)
    // - InternetIpv6: IN6_ADDR (16 bytes)
    // Total: 40 bytes

    let tunnel_ipv4: Ipv4Addr = "10.0.0.77".parse().unwrap();
    let internet_ipv4: Ipv4Addr = "51.79.128.68".parse().unwrap();

    let mut ip_data: Vec<u8> = Vec::with_capacity(40);
    ip_data.extend_from_slice(&tunnel_ipv4.octets()); // TunnelIpv4
    ip_data.extend_from_slice(&internet_ipv4.octets()); // InternetIpv4
    ip_data.extend_from_slice(&[0u8; 16]); // TunnelIpv6 (zeroed)
    ip_data.extend_from_slice(&[0u8; 16]); // InternetIpv6 (zeroed)

    println!("    Tunnel IPv4:   {}", tunnel_ipv4);
    println!("    Internet IPv4: {}", internet_ipv4);
    println!("    Data ({} bytes): {:02X?}", ip_data.len(), &ip_data);

    if send_ioctl_buffered(handle, IOCTL_ST_REGISTER_IP_ADDRESSES, &ip_data) {
        println!("    IP registration successful");
    } else {
        eprintln!("    IP registration failed");
    }
    print_state(handle, "After register IPs");
    println!();

    // Step 6: Set configuration (add notepad.exe to split tunnel list)
    println!("[6] Setting split tunnel configuration...");

    // Use device path format for process images
    let test_app = r"\Device\HarddiskVolume3\Windows\System32\notepad.exe";
    let app_wide: Vec<u16> = test_app.encode_utf16().collect();
    let app_bytes = app_wide.len() * 2;

    // Try different formats for configuration entry
    let header_size: usize = 16;

    // First try: relative offset with 16-byte entry
    println!("  6a. Trying relative offset, 16-byte entry...");
    let entry_size: usize = 16;
    let total_size = header_size + entry_size + app_bytes;
    let mut config_data: Vec<u8> = Vec::with_capacity(total_size);
    config_data.extend_from_slice(&1usize.to_le_bytes()); // NumEntries
    config_data.extend_from_slice(&(total_size as usize).to_le_bytes()); // TotalLength
    config_data.extend_from_slice(&0usize.to_le_bytes()); // name_offset = 0 (relative)
    config_data.extend_from_slice(&(app_bytes as u16).to_le_bytes()); // name_length
    config_data.extend_from_slice(&[0u8; 6]); // Padding
    for w in &app_wide {
        config_data.extend_from_slice(&w.to_le_bytes());
    }
    println!("    Size: {} bytes", config_data.len());

    if send_ioctl_buffered(handle, IOCTL_ST_SET_CONFIGURATION, &config_data) {
        println!("    Configuration set with relative offset!");
    } else {
        // Second try: absolute offset with 16-byte entry
        println!("  6b. Trying absolute offset, 16-byte entry...");
        let mut config_data2: Vec<u8> = Vec::with_capacity(total_size);
        config_data2.extend_from_slice(&1usize.to_le_bytes());
        config_data2.extend_from_slice(&(total_size as usize).to_le_bytes());
        config_data2.extend_from_slice(&((header_size + entry_size) as usize).to_le_bytes()); // absolute offset
        config_data2.extend_from_slice(&(app_bytes as u16).to_le_bytes());
        config_data2.extend_from_slice(&[0u8; 6]);
        for w in &app_wide {
            config_data2.extend_from_slice(&w.to_le_bytes());
        }

        if send_ioctl_buffered(handle, IOCTL_ST_SET_CONFIGURATION, &config_data2) {
            println!("    Configuration set with absolute offset!");
        } else {
            // Third try: 10-byte entry (no padding)
            println!("  6c. Trying 10-byte entry (no padding)...");
            let entry_size = 10;
            let total_size = header_size + entry_size + app_bytes;
            let mut config_data3: Vec<u8> = Vec::with_capacity(total_size);
            config_data3.extend_from_slice(&1usize.to_le_bytes());
            config_data3.extend_from_slice(&(total_size as usize).to_le_bytes());
            config_data3.extend_from_slice(&0usize.to_le_bytes()); // relative offset
            config_data3.extend_from_slice(&(app_bytes as u16).to_le_bytes());
            // No padding
            for w in &app_wide {
                config_data3.extend_from_slice(&w.to_le_bytes());
            }

            if send_ioctl_buffered(handle, IOCTL_ST_SET_CONFIGURATION, &config_data3) {
                println!("    Configuration set with 10-byte entry!");
            } else {
                println!("    All configuration attempts failed");
            }
        }
    }

    println!("    App: {}", test_app);

    if send_ioctl_buffered(handle, IOCTL_ST_SET_CONFIGURATION, &config_data) {
        println!("    Configuration set successfully!");
    } else {
        eprintln!("    Configuration failed");
    }
    print_state(handle, "After set config");
    println!();

    // Final state check
    println!("[7] Final state check...");
    if let Some(state) = get_driver_state(handle) {
        println!("    State: {} ({})", state, get_state_name(state));
        if state == 4 {
            println!("\n    SUCCESS! Driver is ENGAGED and ready for split tunneling!");
        } else {
            println!("\n    Driver is not fully engaged (expected state 4, got {})", state);
        }
    }
    println!();

    // Cleanup
    println!("[8] Cleaning up...");
    let _ = send_ioctl_neither(handle, IOCTL_ST_RESET);
    unsafe {
        let _ = CloseHandle(handle);
    }
    println!("    Done\n");

    println!("=== Test Complete ===");
}

fn send_ioctl_neither(handle: HANDLE, ioctl_code: u32) -> bool {
    let mut bytes_returned: u32 = 0;
    let result = unsafe {
        DeviceIoControl(
            handle,
            ioctl_code,
            None,
            0,
            None,
            0,
            Some(&mut bytes_returned),
            None,
        )
    };
    if let Err(e) = result {
        eprintln!("    IOCTL 0x{:08X} error: {}", ioctl_code, e);
        return false;
    }
    true
}

fn build_process_list(paths: &[&str]) -> Vec<u8> {
    let header_size: usize = 16;
    let entry_size: usize = 16;

    // Convert paths to UTF-16
    let wide_paths: Vec<Vec<u16>> = paths.iter()
        .map(|p| p.encode_utf16().collect())
        .collect();

    let strings_size: usize = wide_paths.iter().map(|p| p.len() * 2).sum();
    let total_size = header_size + entry_size * paths.len() + strings_size;

    let mut data: Vec<u8> = Vec::with_capacity(total_size);

    // Header
    data.extend_from_slice(&(paths.len() as u64).to_le_bytes()); // NumEntries
    data.extend_from_slice(&(total_size as u64).to_le_bytes()); // TotalLength

    // Entries
    let mut string_offset = header_size + entry_size * paths.len();
    for wide_path in &wide_paths {
        let path_bytes = wide_path.len() * 2;
        data.extend_from_slice(&(string_offset as u64).to_le_bytes()); // ImageNameOffset
        data.extend_from_slice(&(path_bytes as u16).to_le_bytes()); // ImageNameLength
        data.extend_from_slice(&[0u8; 6]); // Reserved
        string_offset += path_bytes;
    }

    // String buffer
    for wide_path in &wide_paths {
        for w in wide_path {
            data.extend_from_slice(&w.to_le_bytes());
        }
    }

    data
}

fn send_ioctl_buffered(handle: HANDLE, ioctl_code: u32, input: &[u8]) -> bool {
    let mut bytes_returned: u32 = 0;
    // Some drivers expect output buffer even if no output is returned
    let mut output_buf = [0u8; 64];

    let result = unsafe {
        DeviceIoControl(
            handle,
            ioctl_code,
            Some(input.as_ptr() as *const std::ffi::c_void),
            input.len() as u32,
            Some(output_buf.as_mut_ptr() as *mut std::ffi::c_void),
            output_buf.len() as u32,
            Some(&mut bytes_returned),
            None,
        )
    };
    if let Err(e) = result {
        eprintln!("    IOCTL 0x{:08X} error: {}", ioctl_code, e);
        return false;
    }
    if bytes_returned > 0 {
        println!("    IOCTL returned {} bytes: {:02X?}", bytes_returned, &output_buf[..bytes_returned as usize]);
    }
    true
}
