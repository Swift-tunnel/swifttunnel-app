//! Windows Filtering Platform (WFP) Integration
//!
//! Creates WFP provider, sublayer, and filters required for split tunneling.
//! The Mullvad split tunnel driver requires WFP sublayers to exist before
//! it can create its filtering rules.
//!
//! WFP operates at kernel level with negligible performance overhead.

use super::{VpnError, VpnResult};
use std::ptr;
use windows::core::GUID;
use windows::Win32::Foundation::*;
use windows::Win32::NetworkManagement::WindowsFilteringPlatform::*;
use windows::Win32::System::Services::*;

/// Ensure the Base Filtering Engine (BFE) service is running
/// BFE is required for WFP operations - without it, FwpmEngineOpen0 fails with 0x6D9
pub fn ensure_bfe_running() -> VpnResult<()> {
    log::info!("Checking Base Filtering Engine (BFE) service status...");

    unsafe {
        // Open Service Control Manager
        let scm = OpenSCManagerW(None, None, SC_MANAGER_CONNECT);
        if scm.is_err() {
            let err = GetLastError();
            log::warn!("Could not open SCM: {:?}", err);
            return Ok(()); // Continue anyway, WFP open will give better error
        }
        let scm = scm.unwrap();

        // Open BFE service
        let service = OpenServiceW(scm, windows::core::w!("BFE"), SERVICE_QUERY_STATUS | SERVICE_START);
        if service.is_err() {
            let _ = CloseServiceHandle(scm);
            let err = GetLastError();
            log::warn!("Could not open BFE service: {:?}", err);
            return Ok(()); // Continue anyway
        }
        let service = service.unwrap();

        // Query service status
        let mut status: SERVICE_STATUS = std::mem::zeroed();
        if QueryServiceStatus(service, &mut status).is_ok() {
            if status.dwCurrentState == SERVICE_RUNNING {
                log::info!("BFE service is already running");
                let _ = CloseServiceHandle(service);
                let _ = CloseServiceHandle(scm);
                return Ok(());
            }

            log::warn!("BFE service is not running (state: {}), attempting to start...", status.dwCurrentState.0);

            // Try to start the service
            if StartServiceW(service, None).is_ok() {
                log::info!("BFE service start initiated");

                // Wait for service to start (up to 10 seconds)
                for i in 0..20 {
                    std::thread::sleep(std::time::Duration::from_millis(500));
                    if QueryServiceStatus(service, &mut status).is_ok() {
                        if status.dwCurrentState == SERVICE_RUNNING {
                            log::info!("BFE service started successfully after {}ms", (i + 1) * 500);
                            break;
                        }
                        if status.dwCurrentState == SERVICE_STOPPED {
                            log::error!("BFE service failed to start");
                            break;
                        }
                    }
                }
            } else {
                let err = GetLastError();
                // ERROR_SERVICE_ALREADY_RUNNING (1056) is OK
                if err.0 == 1056 {
                    log::info!("BFE service is already running");
                } else {
                    log::error!("Failed to start BFE service: {:?}", err);
                }
            }
        }

        let _ = CloseServiceHandle(service);
        let _ = CloseServiceHandle(scm);
    }

    Ok(())
}

/// Mullvad Split Tunnel WFP Provider GUID
/// Must match the GUID expected by the Mullvad split tunnel driver
/// Source: {E2C114EE-F32A-4264-A6CB-3FA7996356D9}
static ST_FW_PROVIDER_KEY: GUID = GUID::from_values(
    0xE2C114EE,
    0xF32A,
    0x4264,
    [0xA6, 0xCB, 0x3F, 0xA7, 0x99, 0x63, 0x56, 0xD9],
);

/// Mullvad Split Tunnel WFP Sublayer GUID (WinFW Baseline Sublayer)
/// Must match the GUID expected by the Mullvad split tunnel driver
/// Source: {C78056FF-2BC1-4211-AADD-7F358DEF202D}
static ST_FW_WINFW_BASELINE_SUBLAYER_KEY: GUID = GUID::from_values(
    0xC78056FF,
    0x2BC1,
    0x4211,
    [0xAA, 0xDD, 0x7F, 0x35, 0x8D, 0xEF, 0x20, 0x2D],
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
// These are registered by the driver with PERSISTENT flag and must be cleaned up
// before re-initializing the driver, otherwise we get FWP_E_ALREADY_EXISTS
// =============================================================================

/// ST_FW_CALLOUT_CLASSIFY_BIND_IPV4_KEY
static ST_FW_CALLOUT_CLASSIFY_BIND_IPV4: GUID = GUID::from_values(
    0x76653805, 0x1972, 0x45D1, [0xB4, 0x7C, 0x31, 0x40, 0xAE, 0xBA, 0xBC, 0x49]
);

/// ST_FW_CALLOUT_CLASSIFY_BIND_IPV6_KEY
static ST_FW_CALLOUT_CLASSIFY_BIND_IPV6: GUID = GUID::from_values(
    0x53FB3120, 0xB6A4, 0x462B, [0xBF, 0xFC, 0x69, 0x78, 0xAA, 0xDA, 0x1D, 0xA2]
);

/// ST_FW_CALLOUT_CLASSIFY_CONNECT_IPV4_KEY
static ST_FW_CALLOUT_CLASSIFY_CONNECT_IPV4: GUID = GUID::from_values(
    0xA4E010B5, 0xDC3F, 0x474A, [0xB7, 0xC2, 0x2F, 0x32, 0x69, 0x94, 0x5F, 0x41]
);

/// ST_FW_CALLOUT_CLASSIFY_CONNECT_IPV6_KEY
static ST_FW_CALLOUT_CLASSIFY_CONNECT_IPV6: GUID = GUID::from_values(
    0x6B634022, 0xB3D3, 0x4667, [0x88, 0xBA, 0xBF, 0x50, 0x28, 0x85, 0x8F, 0x52]
);

/// ST_FW_CALLOUT_PERMIT_SPLIT_APPS_IPV4_CONN_KEY
static ST_FW_CALLOUT_PERMIT_SPLIT_APPS_IPV4_CONN: GUID = GUID::from_values(
    0x33F3EDCC, 0xEB5E, 0x41CF, [0x92, 0x50, 0x70, 0x2C, 0x94, 0xA2, 0x8E, 0x39]
);

/// ST_FW_CALLOUT_PERMIT_SPLIT_APPS_IPV4_RECV_KEY
static ST_FW_CALLOUT_PERMIT_SPLIT_APPS_IPV4_RECV: GUID = GUID::from_values(
    0xA7A13809, 0x0DE6, 0x48AB, [0x9B, 0xB8, 0x20, 0xA8, 0xBC, 0xEC, 0x37, 0xAB]
);

/// ST_FW_CALLOUT_PERMIT_SPLIT_APPS_IPV6_CONN_KEY
static ST_FW_CALLOUT_PERMIT_SPLIT_APPS_IPV6_CONN: GUID = GUID::from_values(
    0x7B7E0055, 0x89F5, 0x4760, [0x89, 0x28, 0xCC, 0xD5, 0x7C, 0x88, 0x30, 0xAB]
);

/// ST_FW_CALLOUT_PERMIT_SPLIT_APPS_IPV6_RECV_KEY
static ST_FW_CALLOUT_PERMIT_SPLIT_APPS_IPV6_RECV: GUID = GUID::from_values(
    0xB40B78EF, 0x5642, 0x40EF, [0xAC, 0x4D, 0xF9, 0x65, 0x12, 0x61, 0xF9, 0xE7]
);

/// ST_FW_CALLOUT_BLOCK_SPLIT_APPS_IPV4_CONN_KEY
static ST_FW_CALLOUT_BLOCK_SPLIT_APPS_IPV4_CONN: GUID = GUID::from_values(
    0x974AA588, 0x397A, 0x483E, [0xAC, 0x29, 0x88, 0xF4, 0xF4, 0x11, 0x2A, 0xC2]
);

/// ST_FW_CALLOUT_BLOCK_SPLIT_APPS_IPV4_RECV_KEY
static ST_FW_CALLOUT_BLOCK_SPLIT_APPS_IPV4_RECV: GUID = GUID::from_values(
    0x8E314FD7, 0xBDD3, 0x45A4, [0xA7, 0x12, 0x46, 0x03, 0x6B, 0x25, 0xB3, 0xE1]
);

/// ST_FW_CALLOUT_BLOCK_SPLIT_APPS_IPV6_CONN_KEY
static ST_FW_CALLOUT_BLOCK_SPLIT_APPS_IPV6_CONN: GUID = GUID::from_values(
    0x466B7800, 0x5EF4, 0x4772, [0xAA, 0x79, 0xE0, 0xA8, 0x34, 0x32, 0x82, 0x14]
);

/// ST_FW_CALLOUT_BLOCK_SPLIT_APPS_IPV6_RECV_KEY
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

/// Provider name
const PROVIDER_NAME: &str = "Mullvad Split Tunnel";
const PROVIDER_DESC: &str = "Mullvad Split Tunnel WFP provider";

/// Sublayer name
const SUBLAYER_NAME: &str = "WinFW Baseline Sublayer";
const SUBLAYER_DESC: &str = "Mullvad split tunnel WFP sublayer";

/// WFP Engine handle wrapper
pub struct WfpEngine {
    handle: HANDLE,
    provider_registered: bool,
    sublayer_registered: bool,
}

// SAFETY: HANDLE is a thin pointer, WFP engine is thread-safe
unsafe impl Send for WfpEngine {}
unsafe impl Sync for WfpEngine {}

impl WfpEngine {
    /// Open a new WFP engine session
    pub fn open() -> VpnResult<Self> {
        let mut handle = HANDLE::default();

        let result = unsafe {
            FwpmEngineOpen0(
                None,                           // Server name (local)
                RPC_C_AUTHN_WINNT,             // Auth service
                None,                           // Auth identity
                None,                           // Session (default)
                &mut handle,
            )
        };

        if result != 0 {
            return Err(VpnError::SplitTunnel(format!(
                "Failed to open WFP engine: 0x{:08X}",
                result
            )));
        }

        log::info!("WFP engine opened successfully");
        Ok(Self {
            handle,
            provider_registered: false,
            sublayer_registered: false,
        })
    }

    /// Register SwiftTunnel as a WFP provider
    pub fn register_provider(&mut self) -> VpnResult<()> {
        if self.provider_registered {
            return Ok(());
        }

        // Check if provider already exists
        let mut provider_ptr: *mut FWPM_PROVIDER0 = ptr::null_mut();
        let get_result = unsafe {
            FwpmProviderGetByKey0(self.handle, &ST_FW_PROVIDER_KEY, &mut provider_ptr)
        };

        if get_result == 0 {
            // Provider already exists
            unsafe {
                FwpmFreeMemory0(&mut (provider_ptr as *mut _));
            }
            log::info!("WFP provider already registered");
            self.provider_registered = true;
            return Ok(());
        }

        // Create provider name as wide string
        let name_wide: Vec<u16> = PROVIDER_NAME.encode_utf16().chain(std::iter::once(0)).collect();
        let desc_wide: Vec<u16> = PROVIDER_DESC.encode_utf16().chain(std::iter::once(0)).collect();

        let provider = FWPM_PROVIDER0 {
            providerKey: ST_FW_PROVIDER_KEY,
            displayData: FWPM_DISPLAY_DATA0 {
                name: windows::core::PWSTR(name_wide.as_ptr() as *mut u16),
                description: windows::core::PWSTR(desc_wide.as_ptr() as *mut u16),
            },
            // Non-persistent: cleaned up when WFP engine closes (session-scoped)
            // PERSISTENT flag caused driver INITIALIZE to fail with ALREADY_EXISTS
            flags: 0u32,
            providerData: FWP_BYTE_BLOB::default(),
            serviceName: windows::core::PWSTR::null(),
        };

        let result = unsafe { FwpmProviderAdd0(self.handle, &provider, None) };

        if result != 0 && result != FWP_E_ALREADY_EXISTS.0 as u32 {
            return Err(VpnError::SplitTunnel(format!(
                "Failed to add WFP provider: 0x{:08X}",
                result
            )));
        }

        self.provider_registered = true;
        log::info!("WFP provider registered: {}", PROVIDER_NAME);
        Ok(())
    }

    /// Create the split tunnel sublayer
    pub fn create_sublayer(&mut self) -> VpnResult<()> {
        if self.sublayer_registered {
            return Ok(());
        }

        // Ensure provider is registered first
        self.register_provider()?;

        // Check if sublayer already exists
        let mut sublayer_ptr: *mut FWPM_SUBLAYER0 = ptr::null_mut();
        let get_result = unsafe {
            FwpmSubLayerGetByKey0(self.handle, &ST_FW_WINFW_BASELINE_SUBLAYER_KEY, &mut sublayer_ptr)
        };

        if get_result == 0 {
            // Sublayer already exists
            unsafe {
                FwpmFreeMemory0(&mut (sublayer_ptr as *mut _));
            }
            log::info!("WFP sublayer already exists");
            self.sublayer_registered = true;
            return Ok(());
        }

        // Create sublayer name as wide string
        let name_wide: Vec<u16> = SUBLAYER_NAME.encode_utf16().chain(std::iter::once(0)).collect();
        let desc_wide: Vec<u16> = SUBLAYER_DESC.encode_utf16().chain(std::iter::once(0)).collect();

        let sublayer = FWPM_SUBLAYER0 {
            subLayerKey: ST_FW_WINFW_BASELINE_SUBLAYER_KEY,
            displayData: FWPM_DISPLAY_DATA0 {
                name: windows::core::PWSTR(name_wide.as_ptr() as *mut u16),
                description: windows::core::PWSTR(desc_wide.as_ptr() as *mut u16),
            },
            // Non-persistent: cleaned up when WFP engine closes (session-scoped)
            // PERSISTENT flag caused driver INITIALIZE to fail with ALREADY_EXISTS
            flags: 0u32,
            providerKey: ptr::addr_of!(ST_FW_PROVIDER_KEY) as *mut GUID,
            providerData: FWP_BYTE_BLOB::default(),
            weight: 0x8000, // Medium-high weight
        };

        let result = unsafe { FwpmSubLayerAdd0(self.handle, &sublayer, None) };

        if result != 0 && result != FWP_E_ALREADY_EXISTS.0 as u32 {
            return Err(VpnError::SplitTunnel(format!(
                "Failed to add WFP sublayer: 0x{:08X}",
                result
            )));
        }

        self.sublayer_registered = true;
        log::info!("WFP sublayer created: {}", SUBLAYER_NAME);
        Ok(())
    }

    /// Create sublayer without provider association (for use after driver creates provider)
    pub fn create_sublayer_standalone(&mut self) -> VpnResult<()> {
        if self.sublayer_registered {
            return Ok(());
        }

        // Check if sublayer already exists
        let mut sublayer_ptr: *mut FWPM_SUBLAYER0 = ptr::null_mut();
        let get_result = unsafe {
            FwpmSubLayerGetByKey0(self.handle, &ST_FW_WINFW_BASELINE_SUBLAYER_KEY, &mut sublayer_ptr)
        };

        if get_result == 0 {
            // Sublayer already exists
            unsafe {
                FwpmFreeMemory0(&mut (sublayer_ptr as *mut _));
            }
            log::info!("WFP sublayer already exists");
            self.sublayer_registered = true;
            return Ok(());
        }

        // Create sublayer name as wide string
        let name_wide: Vec<u16> = SUBLAYER_NAME.encode_utf16().chain(std::iter::once(0)).collect();
        let desc_wide: Vec<u16> = SUBLAYER_DESC.encode_utf16().chain(std::iter::once(0)).collect();

        // Create sublayer WITHOUT providerKey - no association with any provider
        // This avoids potential issues with the driver's provider
        let sublayer = FWPM_SUBLAYER0 {
            subLayerKey: ST_FW_WINFW_BASELINE_SUBLAYER_KEY,
            displayData: FWPM_DISPLAY_DATA0 {
                name: windows::core::PWSTR(name_wide.as_ptr() as *mut u16),
                description: windows::core::PWSTR(desc_wide.as_ptr() as *mut u16),
            },
            flags: 0u32, // Non-persistent
            providerKey: ptr::null_mut(), // NO provider association
            providerData: FWP_BYTE_BLOB::default(),
            weight: 0x8000, // Medium-high weight
        };

        let result = unsafe { FwpmSubLayerAdd0(self.handle, &sublayer, None) };

        if result != 0 && result != FWP_E_ALREADY_EXISTS.0 as u32 {
            return Err(VpnError::SplitTunnel(format!(
                "Failed to add standalone WFP sublayer: 0x{:08X}",
                result
            )));
        }

        self.sublayer_registered = true;
        log::info!("WFP sublayer created (standalone): {}", SUBLAYER_NAME);
        Ok(())
    }

    /// Add a permit filter for the VPN interface
    /// This allows traffic through the VPN tunnel
    pub fn add_tunnel_filter(&self, interface_luid: u64, layer: FilterLayer) -> VpnResult<u64> {
        let layer_key = layer.to_guid();

        // Create filter name
        let name = format!("SwiftTunnel {} Filter", layer.name());
        let name_wide: Vec<u16> = name.encode_utf16().chain(std::iter::once(0)).collect();

        // Create condition: match by interface LUID
        let mut condition_value = FWP_CONDITION_VALUE0::default();
        condition_value.r#type = FWP_UINT64;
        condition_value.Anonymous.uint64 = &interface_luid as *const u64 as *mut u64;

        let condition = FWPM_FILTER_CONDITION0 {
            fieldKey: FWPM_CONDITION_INTERFACE_INDEX,
            matchType: FWP_MATCH_EQUAL,
            conditionValue: condition_value,
        };

        let filter = FWPM_FILTER0 {
            filterKey: GUID::zeroed(),
            displayData: FWPM_DISPLAY_DATA0 {
                name: windows::core::PWSTR(name_wide.as_ptr() as *mut u16),
                description: windows::core::PWSTR::null(),
            },
            flags: FWPM_FILTER_FLAGS::default(),
            providerKey: ptr::addr_of!(ST_FW_PROVIDER_KEY) as *mut GUID,
            providerData: FWP_BYTE_BLOB::default(),
            layerKey: layer_key,
            subLayerKey: ST_FW_WINFW_BASELINE_SUBLAYER_KEY,
            weight: FWP_VALUE0 {
                r#type: FWP_UINT8,
                Anonymous: FWP_VALUE0_0 { uint8: 10 },
            },
            numFilterConditions: 1,
            filterCondition: &condition as *const _ as *mut _,
            action: FWPM_ACTION0 {
                r#type: FWP_ACTION_PERMIT,
                Anonymous: FWPM_ACTION0_0::default(),
            },
            Anonymous: FWPM_FILTER0_0::default(),
            reserved: ptr::null_mut(),
            filterId: 0,
            effectiveWeight: FWP_VALUE0::default(),
        };

        let mut filter_id: u64 = 0;
        let result = unsafe { FwpmFilterAdd0(self.handle, &filter, None, Some(&mut filter_id)) };

        if result != 0 {
            return Err(VpnError::SplitTunnel(format!(
                "Failed to add {} filter: 0x{:08X}",
                layer.name(),
                result
            )));
        }

        log::debug!("Added {} filter, ID: {}", layer.name(), filter_id);
        Ok(filter_id)
    }

    /// Remove a filter by ID
    pub fn remove_filter(&self, filter_id: u64) -> VpnResult<()> {
        let result = unsafe { FwpmFilterDeleteById0(self.handle, filter_id) };

        if result != 0 && result != FWP_E_FILTER_NOT_FOUND.0 as u32 {
            return Err(VpnError::SplitTunnel(format!(
                "Failed to remove filter {}: 0x{:08X}",
                filter_id, result
            )));
        }

        Ok(())
    }

    /// Get the sublayer GUID (for split tunnel driver)
    pub fn sublayer_guid(&self) -> GUID {
        ST_FW_WINFW_BASELINE_SUBLAYER_KEY
    }

    /// Get the provider GUID
    pub fn provider_guid(&self) -> GUID {
        ST_FW_PROVIDER_KEY
    }

    /// Check if ready for split tunnel (provider and sublayer exist)
    pub fn is_ready(&self) -> bool {
        self.provider_registered && self.sublayer_registered
    }

    /// Cleanup only legacy SwiftTunnel WFP objects (NOT Mullvad callouts)
    /// Use this when driver has already called initialize() and registered callouts
    pub fn cleanup_legacy_objects(&self) {
        // Clean up LEGACY SwiftTunnel WFP objects (from old code with PERSISTENT flags)
        // These must be removed or they could cause conflicts
        let result = unsafe {
            FwpmSubLayerDeleteByKey0(self.handle, &LEGACY_ST_SUBLAYER_KEY)
        };
        if result == 0 {
            log::info!("Deleted legacy SwiftTunnel sublayer");
        }

        let result = unsafe {
            FwpmProviderDeleteByKey0(self.handle, &LEGACY_ST_PROVIDER_KEY)
        };
        if result == 0 {
            log::info!("Deleted legacy SwiftTunnel provider");
        }
    }

    /// Close the WFP engine (filters persist)
    pub fn close(&mut self) {
        if !self.handle.is_invalid() {
            unsafe {
                let _ = FwpmEngineClose0(self.handle);
            }
            self.handle = HANDLE::default();
            log::info!("WFP engine closed");
        }
    }

    /// Delete Mullvad WFP callouts that may be left from a previous session
    /// This is CRITICAL - the callouts are registered with PERSISTENT flag and survive
    /// across sessions. If not deleted, driver INITIALIZE will fail with FWP_E_ALREADY_EXISTS.
    /// Call this before initializing the split tunnel driver.
    pub fn cleanup_mullvad_callouts(&self) -> usize {
        let mut deleted_count = 0;

        log::info!("Cleaning up Mullvad WFP callouts (12 callouts)...");

        for guid in MULLVAD_CALLOUT_GUIDS.iter() {
            let result = unsafe {
                FwpmCalloutDeleteByKey0(self.handle, guid)
            };
            if result == 0 {
                deleted_count += 1;
            }
            // Ignore errors - callout may not exist
        }

        if deleted_count > 0 {
            log::info!("Deleted {} Mullvad WFP callouts", deleted_count);
        } else {
            log::debug!("No Mullvad WFP callouts found to delete");
        }

        deleted_count
    }

    /// Delete ALL filters associated with the Mullvad sublayer
    /// This is more thorough than relying on sublayer cascade deletion
    /// Filters created by the driver's Firewall::ApplyConfiguration() have dynamic IDs
    pub fn cleanup_mullvad_filters(&self) -> usize {
        let mut deleted_count = 0;

        log::info!("Enumerating and deleting Mullvad WFP filters...");

        unsafe {
            // Create enum template to filter by sublayer
            let template = FWPM_FILTER_ENUM_TEMPLATE0 {
                providerKey: ptr::null_mut(),
                layerKey: GUID::zeroed(),
                enumType: FWP_FILTER_ENUM_FULLY_CONTAINED,
                flags: 0,
                providerContextTemplate: ptr::null_mut(),
                numFilterConditions: 0,
                filterCondition: ptr::null_mut(),
                actionMask: 0xFFFFFFFF, // All action types
                calloutKey: ptr::null_mut(),
            };

            let mut enum_handle = HANDLE::default();
            let result = FwpmFilterCreateEnumHandle0(
                self.handle,
                Some(&template),
                &mut enum_handle,
            );

            if result != 0 {
                log::warn!("Failed to create filter enum handle: 0x{:08X}", result);
                return 0;
            }

            // Enumerate filters in batches
            loop {
                let mut entries: *mut *mut FWPM_FILTER0 = ptr::null_mut();
                let mut num_entries: u32 = 0;

                let result = FwpmFilterEnum0(
                    self.handle,
                    enum_handle,
                    100, // Batch size
                    &mut entries,
                    &mut num_entries,
                );

                if result != 0 || num_entries == 0 {
                    break;
                }

                // Process each filter
                for i in 0..num_entries as isize {
                    let filter = *entries.offset(i);
                    if filter.is_null() {
                        continue;
                    }

                    let filter_ref = &*filter;

                    // Check if this filter belongs to the Mullvad sublayer
                    if filter_ref.subLayerKey == ST_FW_WINFW_BASELINE_SUBLAYER_KEY {
                        let delete_result = FwpmFilterDeleteById0(self.handle, filter_ref.filterId);
                        if delete_result == 0 {
                            deleted_count += 1;
                        }
                    }

                    // Also check if it belongs to the Mullvad provider
                    if !filter_ref.providerKey.is_null() {
                        let provider_key = &*filter_ref.providerKey;
                        if *provider_key == ST_FW_PROVIDER_KEY {
                            let delete_result = FwpmFilterDeleteById0(self.handle, filter_ref.filterId);
                            if delete_result == 0 {
                                deleted_count += 1;
                            }
                        }
                    }
                }

                // Free the memory
                FwpmFreeMemory0(&mut (entries as *mut _));
            }

            let _ = FwpmFilterDestroyEnumHandle0(self.handle, enum_handle);
        }

        if deleted_count > 0 {
            log::info!("Deleted {} Mullvad WFP filters", deleted_count);
        } else {
            log::debug!("No Mullvad WFP filters found to delete");
        }

        deleted_count
    }

    /// Cleanup all SwiftTunnel WFP objects (for uninstall)
    pub fn cleanup_all(&self) -> VpnResult<()> {
        log::info!("Cleaning up all SwiftTunnel WFP objects...");

        // First, delete Mullvad callouts (MUST be done before sublayers/provider)
        self.cleanup_mullvad_callouts();

        // Delete sublayer (will delete associated filters)
        let result = unsafe {
            FwpmSubLayerDeleteByKey0(self.handle, &ST_FW_WINFW_BASELINE_SUBLAYER_KEY)
        };
        if result == 0 {
            log::info!("Deleted Mullvad baseline sublayer");
        } else if result != FWP_E_SUBLAYER_NOT_FOUND.0 as u32 {
            log::warn!("Failed to delete sublayer: 0x{:08X}", result);
        }

        // Delete provider
        let result = unsafe {
            FwpmProviderDeleteByKey0(self.handle, &ST_FW_PROVIDER_KEY)
        };
        if result == 0 {
            log::info!("Deleted Mullvad provider");
        } else if result != FWP_E_PROVIDER_NOT_FOUND.0 as u32 {
            log::warn!("Failed to delete provider: 0x{:08X}", result);
        }

        // Clean up LEGACY SwiftTunnel WFP objects (from old code with PERSISTENT flags)
        // These must be removed or driver INITIALIZE will fail with ALREADY_EXISTS
        let result = unsafe {
            FwpmSubLayerDeleteByKey0(self.handle, &LEGACY_ST_SUBLAYER_KEY)
        };
        if result == 0 {
            log::info!("Deleted legacy SwiftTunnel sublayer");
        }

        let result = unsafe {
            FwpmProviderDeleteByKey0(self.handle, &LEGACY_ST_PROVIDER_KEY)
        };
        if result == 0 {
            log::info!("Deleted legacy SwiftTunnel provider");
        }

        log::info!("WFP cleanup complete");
        Ok(())
    }
}

impl Drop for WfpEngine {
    fn drop(&mut self) {
        self.close();
    }
}

/// WFP filter layers we care about
#[derive(Debug, Clone, Copy)]
pub enum FilterLayer {
    /// Outbound IPv4 at connect time
    AleConnectV4,
    /// Outbound IPv6 at connect time
    AleConnectV6,
    /// Inbound IPv4 at receive time
    AleRecvAcceptV4,
    /// Inbound IPv6 at receive time
    AleRecvAcceptV6,
}

impl FilterLayer {
    fn to_guid(&self) -> GUID {
        match self {
            FilterLayer::AleConnectV4 => FWPM_LAYER_ALE_AUTH_CONNECT_V4,
            FilterLayer::AleConnectV6 => FWPM_LAYER_ALE_AUTH_CONNECT_V6,
            FilterLayer::AleRecvAcceptV4 => FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V4,
            FilterLayer::AleRecvAcceptV6 => FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V6,
        }
    }

    fn name(&self) -> &'static str {
        match self {
            FilterLayer::AleConnectV4 => "ALE Connect IPv4",
            FilterLayer::AleConnectV6 => "ALE Connect IPv6",
            FilterLayer::AleRecvAcceptV4 => "ALE Recv IPv4",
            FilterLayer::AleRecvAcceptV6 => "ALE Recv IPv6",
        }
    }
}

/// Cleanup stale WFP objects from previous sessions
///
/// MUST be called at app startup BEFORE any VPN/driver operations.
/// This cleans up persistent Mullvad WFP objects (filters, callouts, sublayer, provider)
/// that may exist from a previous session that crashed or didn't clean up properly.
///
/// If stale objects exist when driver.initialize() runs, it will fail with
/// FWP_E_ALREADY_EXISTS (0x80320009). And if we clean up AFTER initialize(),
/// we'd delete the objects that were just registered.
///
/// Order of deletion matters (most dependent first):
/// 1. Filters first (they reference callouts and sublayer)
/// 2. Callouts second (they reference the sublayer)
/// 3. Sublayer third (it references the provider)
/// 4. Provider last
pub fn cleanup_stale_wfp_callouts() {
    log::info!("Cleaning up stale WFP objects from previous sessions...");

    if let Ok(engine) = WfpEngine::open() {
        // Step 0: Delete ALL filters associated with Mullvad sublayer/provider
        // CRITICAL: Filters must be deleted FIRST - they reference callouts
        // This fixes the FWP_E_ALREADY_EXISTS error on SET_CONFIGURATION
        let filters_deleted = engine.cleanup_mullvad_filters();
        if filters_deleted > 0 {
            log::info!("Deleted {} stale Mullvad WFP filters", filters_deleted);
        }

        // Step 1: Delete Mullvad callouts (they reference sublayer)
        let callouts_deleted = engine.cleanup_mullvad_callouts();
        if callouts_deleted > 0 {
            log::info!("Deleted {} stale Mullvad WFP callouts", callouts_deleted);
        }

        // Step 2: Delete Mullvad sublayer (it references provider)
        let result = unsafe {
            FwpmSubLayerDeleteByKey0(engine.handle, &ST_FW_WINFW_BASELINE_SUBLAYER_KEY)
        };
        if result == 0 {
            log::info!("Deleted stale Mullvad sublayer");
        } else if result != FWP_E_SUBLAYER_NOT_FOUND.0 as u32 {
            log::debug!("Mullvad sublayer delete: 0x{:08X} (may not exist)", result);
        }

        // Step 3: Delete Mullvad provider
        let result = unsafe {
            FwpmProviderDeleteByKey0(engine.handle, &ST_FW_PROVIDER_KEY)
        };
        if result == 0 {
            log::info!("Deleted stale Mullvad provider");
        } else if result != FWP_E_PROVIDER_NOT_FOUND.0 as u32 {
            log::debug!("Mullvad provider delete: 0x{:08X} (may not exist)", result);
        }

        // Step 4: Cleanup legacy SwiftTunnel objects (old code with different GUIDs)
        engine.cleanup_legacy_objects();

        log::info!("WFP stale object cleanup complete");
    } else {
        log::warn!("Could not open WFP engine for cleanup (may need admin rights)");
    }
}

/// Helper to setup WFP for split tunneling
///
/// Setup WFP infrastructure BEFORE driver.initialize()
///
/// CRITICAL: This must be called BEFORE driver.initialize()!
/// The Mullvad driver's IOCTL_ST_INITIALIZE registers WFP callouts that REFERENCE
/// the sublayer - so the sublayer must exist first!
///
/// Correct initialization order:
/// 1. driver.open()
/// 2. setup_wfp_for_split_tunnel() - THIS FUNCTION (creates provider + sublayer)
/// 3. driver.initialize() - registers WFP callouts that use the sublayer
/// 4. driver.configure()
///
/// If the sublayer doesn't exist when driver.initialize() or configure() runs,
/// you'll get FWP_E_SUBLAYER_NOT_FOUND (0x80320007).
pub fn setup_wfp_for_split_tunnel(_interface_luid: u64) -> VpnResult<WfpEngine> {
    log::info!("Setting up WFP infrastructure for split tunneling...");

    let mut engine = WfpEngine::open()?;

    // NOTE: Do NOT cleanup Mullvad callouts here!
    // The driver's IOCTL_ST_INITIALIZE registers callouts, so if we call this
    // after driver.initialize(), we'll delete the callouts it just registered.
    // Cleanup of stale callouts from previous sessions should be done once at
    // app startup via cleanup_stale_state() BEFORE any driver operations.

    // Only cleanup legacy SwiftTunnel objects (not Mullvad driver objects)
    engine.cleanup_legacy_objects();

    // Step 2: Register provider (required before sublayer)
    log::info!("Registering WFP provider...");
    if let Err(e) = engine.register_provider() {
        // Provider might already exist - that's OK
        log::warn!("Provider registration: {} (may already exist)", e);
    }

    // Step 3: Create sublayer (CRITICAL - driver callouts reference this!)
    log::info!("Creating WFP sublayer...");
    if let Err(e) = engine.create_sublayer() {
        // Sublayer might already exist - that's OK
        log::warn!("Sublayer creation: {} (may already exist)", e);
    }

    log::info!("WFP infrastructure ready - provider and sublayer registered");
    Ok(engine)
}

// RPC authentication constant
const RPC_C_AUTHN_WINNT: u32 = 10;
