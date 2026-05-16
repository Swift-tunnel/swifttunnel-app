//! WFP (Windows Filtering Platform) temporary block filters
//!
//! This module provides instant packet blocking for newly detected game processes.
//! When ETW detects a game process starting, we IMMEDIATELY add a WFP block filter
//! for that process's full image path. This holds all packets from that process
//! while we set up the split tunnel. Once ready, we remove the block filter and
//! packets flow correctly through the VPN.
//!
//! This eliminates the race condition where packets could bypass the VPN before
//! the UDP table reflects the socket binding (0.5-2ms gap).

use std::collections::HashMap;
use std::ffi::c_void;
use std::sync::Mutex;
use windows::Win32::Foundation::HANDLE;
use windows::Win32::NetworkManagement::WindowsFilteringPlatform::*;
use windows::Win32::System::Rpc::RPC_C_AUTHN_WINNT;
use windows::core::{GUID, PCWSTR, PWSTR};

/// GUID for our sublayer (random, unique to SwiftTunnel)
const SWIFTTUNNEL_SUBLAYER_GUID: GUID = GUID::from_u128(0x8a9b3c4d_5e6f_7a8b_9c0d_1e2f3a4b5c6d);
const FWP_E_ALREADY_EXISTS_CODE: u32 = 0x8032_0009;
const FWP_E_FILTER_NOT_FOUND_CODE: u32 = 0x8032_0003;
const FWP_E_SUBLAYER_NOT_FOUND_CODE: u32 = 0x8032_0007;
const FILTER_ENUM_BATCH_SIZE: u32 = 128;

/// Global WFP engine handle and active filters
static WFP_STATE: Mutex<Option<WfpBlockState>> = Mutex::new(None);

struct WfpBlockState {
    engine_handle: HANDLE,
    /// Map of image path (lowercase) -> filter ID for active block filters
    active_filters: HashMap<String, u64>,
    /// Counter for generating unique filter GUIDs
    filter_counter: u32,
}

// Safety: HANDLE is a raw pointer but WFP engine handles are thread-safe.
// We protect access with a Mutex and only use the handle for WFP operations.
unsafe impl Send for WfpBlockState {}

unsafe fn open_wfp_engine(session: Option<*const FWPM_SESSION0>) -> Result<HANDLE, String> {
    let mut engine_handle = HANDLE::default();
    let result = unsafe {
        FwpmEngineOpen0(
            None,              // serverName (local)
            RPC_C_AUTHN_WINNT, // authnService
            None,              // authIdentity
            session,
            &mut engine_handle,
        )
    };

    if result != 0 {
        return Err(format!("FwpmEngineOpen0 failed: 0x{:08x}", result));
    }

    Ok(engine_handle)
}

fn free_wfp_memory<T>(ptr: *mut T) {
    if ptr.is_null() {
        return;
    }

    unsafe {
        let mut raw = ptr as *mut c_void;
        FwpmFreeMemory0(&mut raw);
    }
}

fn collect_filters_in_swifttunnel_sublayer(engine_handle: HANDLE) -> Result<Vec<u64>, String> {
    let mut enum_handle = HANDLE::default();
    unsafe {
        let result = FwpmFilterCreateEnumHandle0(engine_handle, None, &mut enum_handle);
        if result != 0 {
            return Err(format!(
                "FwpmFilterCreateEnumHandle0 failed: 0x{:08x}",
                result
            ));
        }
    }

    let mut filter_ids = Vec::new();
    let mut enum_error: Option<String> = None;

    loop {
        let mut entries: *mut *mut FWPM_FILTER0 = std::ptr::null_mut();
        let mut returned = 0u32;
        let result = unsafe {
            FwpmFilterEnum0(
                engine_handle,
                enum_handle,
                FILTER_ENUM_BATCH_SIZE,
                &mut entries,
                &mut returned,
            )
        };

        if result != 0 {
            enum_error = Some(format!("FwpmFilterEnum0 failed: 0x{:08x}", result));
            free_wfp_memory(entries);
            break;
        }

        if returned == 0 {
            free_wfp_memory(entries);
            break;
        }

        unsafe {
            for idx in 0..returned as usize {
                let filter = *entries.add(idx);
                if !filter.is_null() && (*filter).subLayerKey == SWIFTTUNNEL_SUBLAYER_GUID {
                    filter_ids.push((*filter).filterId);
                }
            }
        }

        free_wfp_memory(entries);

        if returned < FILTER_ENUM_BATCH_SIZE {
            break;
        }
    }

    unsafe {
        let destroy_result = FwpmFilterDestroyEnumHandle0(engine_handle, enum_handle);
        if destroy_result != 0 {
            log::warn!(
                "FwpmFilterDestroyEnumHandle0 failed during cleanup: 0x{:08x}",
                destroy_result
            );
        }
    }

    if let Some(error) = enum_error {
        Err(error)
    } else {
        Ok(filter_ids)
    }
}

fn delete_filters_in_swifttunnel_sublayer(engine_handle: HANDLE) -> Result<usize, String> {
    let filter_ids = collect_filters_in_swifttunnel_sublayer(engine_handle)?;
    let mut deleted = 0usize;

    for filter_id in filter_ids {
        let result = unsafe { FwpmFilterDeleteById0(engine_handle, filter_id) };
        if result == 0 {
            deleted += 1;
        } else if result != FWP_E_FILTER_NOT_FOUND_CODE {
            log::warn!(
                "Failed to delete stale SwiftTunnel WFP filter {}: 0x{:08x}",
                filter_id,
                result
            );
        }
    }

    Ok(deleted)
}

fn cleanup_stale_result() -> Result<usize, String> {
    unsafe {
        let engine_handle = open_wfp_engine(None)?;
        let deleted = delete_filters_in_swifttunnel_sublayer(engine_handle);

        if deleted.is_ok() {
            let sublayer_result =
                FwpmSubLayerDeleteByKey0(engine_handle, &SWIFTTUNNEL_SUBLAYER_GUID);
            if sublayer_result != 0 && sublayer_result != FWP_E_SUBLAYER_NOT_FOUND_CODE {
                log::warn!(
                    "Failed to delete SwiftTunnel WFP sublayer during stale cleanup: 0x{:08x}",
                    sublayer_result
                );
            }
        }

        let close_result = FwpmEngineClose0(engine_handle);
        if close_result != 0 {
            log::warn!(
                "FwpmEngineClose0 failed during stale cleanup: 0x{:08x}",
                close_result
            );
        }

        deleted
    }
}

/// Stateless cleanup for filters left by older non-dynamic WFP sessions.
///
/// New sessions are dynamic, so Windows removes their filters if the app is
/// killed. This remains as migration/recovery for users who already have a
/// stale "SwiftTunnel Process Block" filter from an older build.
pub fn cleanup_stale() {
    match cleanup_stale_result() {
        Ok(deleted) if deleted > 0 => {
            log::info!("Removed {} stale SwiftTunnel WFP block filter(s)", deleted);
        }
        Ok(_) => {}
        Err(e) => log::warn!("Failed to clean stale SwiftTunnel WFP filters: {}", e),
    }
}

/// Initialize WFP engine for temporary block filters
pub fn init() -> Result<(), String> {
    {
        let state = WFP_STATE
            .lock()
            .map_err(|e| format!("Lock failed: {}", e))?;

        if state.is_some() {
            return Ok(()); // Already initialized
        }
    }

    cleanup_stale();

    let mut state = WFP_STATE
        .lock()
        .map_err(|e| format!("Lock failed: {}", e))?;

    if state.is_some() {
        return Ok(());
    }

    unsafe {
        // Dynamic sessions make WFP remove our temporary filters if the app is
        // killed before `cleanup()` runs.
        let session_name: Vec<u16> = "SwiftTunnel WFP Blocks\0".encode_utf16().collect();
        let session_desc: Vec<u16> = "Temporary process holds for split tunnel setup\0"
            .encode_utf16()
            .collect();
        let session = FWPM_SESSION0 {
            displayData: FWPM_DISPLAY_DATA0 {
                name: PWSTR::from_raw(session_name.as_ptr() as *mut u16),
                description: PWSTR::from_raw(session_desc.as_ptr() as *mut u16),
            },
            flags: FWPM_SESSION_FLAG_DYNAMIC,
            ..Default::default()
        };
        let engine_handle = open_wfp_engine(Some(&session as *const _))?;

        // Create wide strings for display data. Keep these alive for the call.
        let name: Vec<u16> = "SwiftTunnel Temporary Blocks\0".encode_utf16().collect();
        let desc: Vec<u16> = "Holds game packets during split tunnel setup\0"
            .encode_utf16()
            .collect();

        // Add our sublayer (if it doesn't exist)
        let sublayer = FWPM_SUBLAYER0 {
            subLayerKey: SWIFTTUNNEL_SUBLAYER_GUID,
            displayData: FWPM_DISPLAY_DATA0 {
                name: PWSTR::from_raw(name.as_ptr() as *mut u16),
                description: PWSTR::from_raw(desc.as_ptr() as *mut u16),
            },
            weight: 0xFFFF, // High weight so our blocks take priority
            ..Default::default()
        };

        let add_result = FwpmSubLayerAdd0(engine_handle, &sublayer, None);
        // Ignore "already exists" error (0x80320009)
        if add_result != 0 && add_result != FWP_E_ALREADY_EXISTS_CODE {
            let _ = FwpmEngineClose0(engine_handle);
            return Err(format!("FwpmSubLayerAdd0 failed: 0x{:08x}", add_result));
        }

        *state = Some(WfpBlockState {
            engine_handle,
            active_filters: HashMap::new(),
            filter_counter: 0,
        });

        log::info!("WFP block filter engine initialized");
        Ok(())
    }
}

/// Build a mapping of volume device paths to drive letters using QueryDosDevice
///
/// Returns a HashMap like:
///   r"\Device\HarddiskVolume3" -> 'C'
///   r"\Device\HarddiskVolume4" -> 'D'
fn build_drive_mapping() -> HashMap<String, char> {
    use windows::Win32::Storage::FileSystem::QueryDosDeviceW;

    let mut mapping = HashMap::new();

    // Check all possible drive letters A-Z
    for drive_char in 'A'..='Z' {
        // Create drive string like "C:"
        let drive_name: Vec<u16> = format!("{}:", drive_char)
            .encode_utf16()
            .chain(std::iter::once(0))
            .collect();

        // Buffer to receive device path
        let mut buffer = [0u16; 512];

        unsafe {
            let len = QueryDosDeviceW(PCWSTR::from_raw(drive_name.as_ptr()), Some(&mut buffer));

            if len > 0 {
                // QueryDosDevice returns null-separated strings, take the first one
                let device_path = String::from_utf16_lossy(&buffer[..len as usize])
                    .split('\0')
                    .next()
                    .unwrap_or("")
                    .to_string();

                if !device_path.is_empty() {
                    mapping.insert(device_path, drive_char);
                }
            }
        }
    }

    mapping
}

/// Convert NT path to DOS path for WFP
/// NT paths look like: \Device\HarddiskVolume3\Users\...
/// WFP needs DOS paths: C:\Users\...
///
/// Uses QueryDosDevice to properly map volume devices to drive letters,
/// supporting drives other than C: (e.g., Roblox installed on D:)
fn nt_to_dos_path(nt_path: &str) -> Option<String> {
    if nt_path.starts_with(r"\Device\HarddiskVolume") || nt_path.starts_with(r"\Device\Mup") {
        // Build the volume → drive letter mapping
        let drive_map = build_drive_mapping();

        // Find the matching volume device
        for (device_path, drive_letter) in &drive_map {
            if nt_path.starts_with(device_path) {
                // Extract the path after the device prefix
                let rest = nt_path.strip_prefix(device_path)?;
                // rest starts with '\' like \Users\...
                return Some(format!("{}:{}", drive_letter, rest));
            }
        }

        // Fallback: try to parse the volume number directly
        // This handles cases where QueryDosDevice might not return expected results
        if let Some(rest) = nt_path.strip_prefix(r"\Device\HarddiskVolume") {
            if let Some((num_str, path)) = rest.split_once('\\') {
                if let Ok(vol_num) = num_str.parse::<u32>() {
                    // Search for this volume number in our mapping
                    for (device_path, drive_letter) in &drive_map {
                        if device_path.contains(&format!("HarddiskVolume{}", vol_num)) {
                            return Some(format!("{}:\\{}", drive_letter, path));
                        }
                    }
                    // Don't guess C:\ — games on D:\ would silently get a
                    // mismatched WFP block filter. The caller already handles
                    // None by falling back to speculative tunneling.
                    log::warn!(
                        "nt_to_dos_path: Could not map volume {} to drive letter, returning None",
                        vol_num
                    );
                }
            }
        }

        None
    } else if nt_path.starts_with(r"\??\") {
        // Already a DOS-style path with \??\ prefix
        Some(nt_path.strip_prefix(r"\??\")?.to_string())
    } else if nt_path.chars().nth(1) == Some(':') {
        // Already a DOS path like C:\Users\...
        Some(nt_path.to_string())
    } else {
        None
    }
}

/// Add a temporary block filter for a process by its full image path
/// This immediately blocks ALL outbound connections from this process
///
/// The image_path should be the full NT path from ETW, e.g.:
/// \Device\HarddiskVolume3\Users\test\AppData\Local\Roblox\...\RobloxPlayerBeta.exe
pub fn block_process_by_path(image_path: &str) -> Result<(), String> {
    if image_path.is_empty() {
        return Err("Empty image path".to_string());
    }

    let mut state_guard = WFP_STATE
        .lock()
        .map_err(|e| format!("Lock failed: {}", e))?;
    let state = state_guard.as_mut().ok_or("WFP not initialized")?;

    let key = image_path.to_lowercase();

    // Check if already blocked
    if state.active_filters.contains_key(&key) {
        log::debug!("Path {} already blocked", image_path);
        return Ok(());
    }

    // Convert NT path to DOS path for WFP
    let dos_path = nt_to_dos_path(image_path)
        .ok_or_else(|| format!("Could not convert NT path to DOS path: {}", image_path))?;

    log::info!("WFP blocking process: {} (DOS: {})", image_path, dos_path);

    unsafe {
        // Get the WFP app ID blob for this path
        let dos_path_wide: Vec<u16> = dos_path.encode_utf16().chain(std::iter::once(0)).collect();
        let mut app_id: *mut FWP_BYTE_BLOB = std::ptr::null_mut();

        let result =
            FwpmGetAppIdFromFileName0(PCWSTR::from_raw(dos_path_wide.as_ptr()), &mut app_id);

        if result != 0 {
            return Err(format!(
                "FwpmGetAppIdFromFileName0 failed for '{}': 0x{:08x}",
                dos_path, result
            ));
        }

        if app_id.is_null() {
            return Err("FwpmGetAppIdFromFileName0 returned null app_id".to_string());
        }

        // Create the filter condition matching this app
        let condition = FWPM_FILTER_CONDITION0 {
            fieldKey: FWPM_CONDITION_ALE_APP_ID,
            matchType: FWP_MATCH_EQUAL,
            conditionValue: FWP_CONDITION_VALUE0 {
                r#type: FWP_BYTE_BLOB_TYPE,
                Anonymous: FWP_CONDITION_VALUE0_0 { byteBlob: app_id },
            },
        };

        // Generate unique filter GUID
        state.filter_counter += 1;
        let filter_guid = GUID::from_u128(
            0x1234_5678_9abc_def0_1234_5678_0000_0000u128 | (state.filter_counter as u128),
        );

        // Create wide strings for display data
        let filter_name: Vec<u16> = "SwiftTunnel Process Block\0".encode_utf16().collect();
        let filter_desc: Vec<u16> = "Temporary block during split tunnel setup\0"
            .encode_utf16()
            .collect();

        // Create the block filter at ALE_AUTH_CONNECT layer
        // This blocks ALL new outbound connections from this process
        let filter = FWPM_FILTER0 {
            filterKey: filter_guid,
            displayData: FWPM_DISPLAY_DATA0 {
                name: PWSTR::from_raw(filter_name.as_ptr() as *mut u16),
                description: PWSTR::from_raw(filter_desc.as_ptr() as *mut u16),
            },
            layerKey: FWPM_LAYER_ALE_AUTH_CONNECT_V4,
            subLayerKey: SWIFTTUNNEL_SUBLAYER_GUID,
            weight: FWP_VALUE0 {
                r#type: FWP_UINT8,
                Anonymous: FWP_VALUE0_0 { uint8: 15 }, // High weight
            },
            action: FWPM_ACTION0 {
                r#type: FWP_ACTION_BLOCK,
                Anonymous: FWPM_ACTION0_0 {
                    filterType: GUID::zeroed(),
                },
            },
            numFilterConditions: 1,
            filterCondition: &condition as *const _ as *mut _,
            ..Default::default()
        };

        let mut filter_id: u64 = 0;
        let add_result = FwpmFilterAdd0(state.engine_handle, &filter, None, Some(&mut filter_id));

        // Free the app ID blob
        free_wfp_memory(app_id);

        if add_result != 0 {
            return Err(format!("FwpmFilterAdd0 failed: 0x{:08x}", add_result));
        }

        state.active_filters.insert(key, filter_id);
        log::info!(
            "WFP block filter added for {} (filter_id={})",
            image_path,
            filter_id
        );

        Ok(())
    }
}

/// Remove the block filter for a process
pub fn unblock_process_by_path(image_path: &str) -> Result<(), String> {
    let mut state_guard = WFP_STATE
        .lock()
        .map_err(|e| format!("Lock failed: {}", e))?;
    let state = state_guard.as_mut().ok_or("WFP not initialized")?;

    let key = image_path.to_lowercase();

    if let Some(filter_id) = state.active_filters.remove(&key) {
        unsafe {
            let result = FwpmFilterDeleteById0(state.engine_handle, filter_id);
            if result != 0 {
                log::warn!(
                    "Failed to remove block filter for '{}': 0x{:08x}",
                    image_path,
                    result
                );
            } else {
                log::info!(
                    "WFP block filter removed for {} (filter_id={})",
                    image_path,
                    filter_id
                );
            }
        }
    }

    Ok(())
}

/// Cleanup all WFP state
pub fn cleanup() {
    if let Ok(mut state_guard) = WFP_STATE.lock() {
        if let Some(state) = state_guard.take() {
            unsafe {
                // Remove all active filters
                for (path, filter_id) in state.active_filters {
                    let result = FwpmFilterDeleteById0(state.engine_handle, filter_id);
                    if result == 0 || result == FWP_E_FILTER_NOT_FOUND_CODE {
                        log::debug!("Cleanup: removed block filter for '{}'", path);
                    } else {
                        log::warn!(
                            "Cleanup: failed to remove block filter for '{}': 0x{:08x}",
                            path,
                            result
                        );
                    }
                }

                // Remove our sublayer
                let sublayer_result =
                    FwpmSubLayerDeleteByKey0(state.engine_handle, &SWIFTTUNNEL_SUBLAYER_GUID);
                if sublayer_result != 0 && sublayer_result != FWP_E_SUBLAYER_NOT_FOUND_CODE {
                    log::warn!(
                        "Cleanup: failed to remove WFP sublayer: 0x{:08x}",
                        sublayer_result
                    );
                }

                // Close engine
                let _ = FwpmEngineClose0(state.engine_handle);
                log::info!("WFP block filter engine closed");
            }
        }
    }
}

/// Check if WFP blocking is initialized
pub fn is_initialized() -> bool {
    WFP_STATE.lock().map(|s| s.is_some()).unwrap_or(false)
}
