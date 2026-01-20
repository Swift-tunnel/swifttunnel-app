//! Simple driver initialization test
//! Tests if the Mullvad split tunnel driver initializes correctly

use std::ffi::OsStr;
use std::os::windows::ffi::OsStrExt;
use std::ptr;
use windows::Win32::Foundation::*;
use windows::Win32::Storage::FileSystem::*;
use windows::Win32::System::IO::DeviceIoControl;

// IOCTL codes from Mullvad driver
const ST_DEVICE_TYPE: u32 = 0x8000;  // Custom device type used by Mullvad driver
const METHOD_BUFFERED: u32 = 0;
const METHOD_NEITHER: u32 = 3;
const FILE_ANY_ACCESS: u32 = 0;

macro_rules! ctl_code {
    ($device_type:expr, $function:expr, $method:expr, $access:expr) => {
        (($device_type) << 16) | (($access) << 14) | (($function) << 2) | ($method)
    };
}

const IOCTL_ST_INITIALIZE: u32 = ctl_code!(ST_DEVICE_TYPE, 1, METHOD_NEITHER, FILE_ANY_ACCESS);
const IOCTL_ST_GET_STATE: u32 = ctl_code!(ST_DEVICE_TYPE, 9, METHOD_BUFFERED, FILE_ANY_ACCESS);
const IOCTL_ST_RESET: u32 = ctl_code!(ST_DEVICE_TYPE, 11, METHOD_NEITHER, FILE_ANY_ACCESS);

const DRIVER_DEVICE_PATH: &str = "\\\\.\\MULLVADSPLITTUNNEL";

fn main() {
    println!("╔════════════════════════════════════════╗");
    println!("║  Mullvad Split Tunnel Driver Test      ║");
    println!("╚════════════════════════════════════════╝\n");

    // Convert path to wide string
    let path_wide: Vec<u16> = OsStr::new(DRIVER_DEVICE_PATH)
        .encode_wide()
        .chain(std::iter::once(0))
        .collect();

    // Open driver
    println!("1. Opening driver at {}...", DRIVER_DEVICE_PATH);
    let handle = unsafe {
        CreateFileW(
            windows::core::PCWSTR(path_wide.as_ptr()),
            FILE_GENERIC_READ.0 | FILE_GENERIC_WRITE.0,
            FILE_SHARE_MODE(0),
            None,
            OPEN_EXISTING,
            FILE_ATTRIBUTE_NORMAL,
            HANDLE::default(),
        )
    };

    let handle = match handle {
        Ok(h) => {
            println!("   ✓ Driver opened successfully");
            h
        }
        Err(e) => {
            println!("   ✗ Failed to open driver: {:?}", e);
            println!("\n   Make sure the mullvad-split-tunnel.sys driver is installed and started.");
            println!("   Run: sc query mullvadsplittunnel");
            return;
        }
    };

    // Get initial state
    println!("\n2. Getting initial driver state...");
    match get_driver_state(handle) {
        Some(state) => println!("   State: {} ({})", state, state_name(state)),
        None => println!("   ✗ Failed to get state"),
    }

    // Send RESET
    println!("\n3. Sending RESET command...");
    if send_ioctl(handle, IOCTL_ST_RESET) {
        println!("   ✓ RESET sent");
    } else {
        println!("   ✗ RESET failed");
    }

    std::thread::sleep(std::time::Duration::from_millis(500));

    // Get state after RESET
    println!("\n4. Getting state after RESET...");
    match get_driver_state(handle) {
        Some(state) => println!("   State: {} ({})", state, state_name(state)),
        None => println!("   ✗ Failed to get state"),
    }

    // Send INITIALIZE
    println!("\n5. Sending INITIALIZE command...");
    if send_ioctl(handle, IOCTL_ST_INITIALIZE) {
        println!("   ✓ INITIALIZE sent");
    } else {
        println!("   Note: INITIALIZE may have returned error (callouts already exist)");
    }

    std::thread::sleep(std::time::Duration::from_millis(500));

    // Get final state
    println!("\n6. Getting final driver state...");
    match get_driver_state(handle) {
        Some(state) => {
            println!("   State: {} ({})", state, state_name(state));
            if state >= 2 {
                println!("\n   ✓ SUCCESS: Driver initialized properly!");
            } else {
                println!("\n   ✗ FAILURE: Driver did not advance past STARTED state");
                println!("     This is the root cause of split tunnel not working.");
            }
        }
        None => println!("   ✗ Failed to get state"),
    }

    // Close handle
    unsafe { let _ = CloseHandle(handle); }
    println!("\nTest complete.");
}

fn get_driver_state(handle: HANDLE) -> Option<u32> {
    let mut state: u32 = 0;
    let mut bytes_returned: u32 = 0;

    let result = unsafe {
        DeviceIoControl(
            handle,
            IOCTL_ST_GET_STATE,
            None,
            0,
            Some(&mut state as *mut u32 as *mut _),
            std::mem::size_of::<u32>() as u32,
            Some(&mut bytes_returned),
            None,
        )
    };

    match result {
        Ok(_) => {
            if bytes_returned == 4 {
                Some(state)
            } else {
                println!("   (unexpected bytes_returned: {})", bytes_returned);
                None
            }
        }
        Err(e) => {
            println!("   (error: {:?})", e);
            None
        }
    }
}

fn send_ioctl(handle: HANDLE, ioctl: u32) -> bool {
    let mut bytes_returned: u32 = 0;

    let result = unsafe {
        DeviceIoControl(
            handle,
            ioctl,
            None,
            0,
            None,
            0,
            Some(&mut bytes_returned),
            None,
        )
    };

    match result {
        Ok(_) => true,
        Err(e) => {
            println!("   (error: {:?})", e);
            false
        }
    }
}

fn state_name(state: u32) -> &'static str {
    match state {
        0 => "NONE",
        1 => "STARTED",
        2 => "INITIALIZED",
        3 => "READY",
        4 => "ENGAGED",
        _ => "UNKNOWN",
    }
}
