//! Windows Filtering Platform (WFP) Integration
//!
//! Creates WFP provider, sublayer, and filters required for split tunneling.
//! The Mullvad split tunnel driver requires WFP sublayers to exist before
//! it can create its filtering rules.

use crate::error::VpnError;
use std::ptr;
use windows::core::GUID;
use windows::Win32::Foundation::*;
use windows::Win32::NetworkManagement::WindowsFilteringPlatform::*;

/// Mullvad Split Tunnel WFP Provider GUID
static ST_FW_PROVIDER_KEY: GUID = GUID::from_values(
    0xE2C114EE,
    0xF32A,
    0x4264,
    [0xA6, 0xCB, 0x3F, 0xA7, 0x99, 0x63, 0x56, 0xD9],
);

/// Mullvad Split Tunnel WFP Sublayer GUID
static ST_FW_WINFW_BASELINE_SUBLAYER_KEY: GUID = GUID::from_values(
    0xC78056FF,
    0x2BC1,
    0x4211,
    [0xAA, 0xDD, 0x7F, 0x35, 0x8D, 0xEF, 0x20, 0x2D],
);

const PROVIDER_NAME: &str = "Mullvad Split Tunnel";
const PROVIDER_DESC: &str = "Mullvad Split Tunnel WFP provider";
const SUBLAYER_NAME: &str = "WinFW Baseline Sublayer";
const SUBLAYER_DESC: &str = "Mullvad split tunnel WFP sublayer";

/// WFP Engine handle wrapper
pub struct WfpEngine {
    handle: HANDLE,
    provider_registered: bool,
    sublayer_registered: bool,
}

unsafe impl Send for WfpEngine {}
unsafe impl Sync for WfpEngine {}

impl WfpEngine {
    /// Open a new WFP engine session
    pub fn open() -> Result<Self, VpnError> {
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

    /// Register as a WFP provider
    pub fn register_provider(&mut self) -> Result<(), VpnError> {
        if self.provider_registered {
            return Ok(());
        }

        // Check if provider already exists
        let mut provider_ptr: *mut FWPM_PROVIDER0 = ptr::null_mut();
        let get_result = unsafe {
            FwpmProviderGetByKey0(self.handle, &ST_FW_PROVIDER_KEY, &mut provider_ptr)
        };

        if get_result == 0 {
            unsafe {
                FwpmFreeMemory0(&mut (provider_ptr as *mut _));
            }
            log::info!("WFP provider already registered");
            self.provider_registered = true;
            return Ok(());
        }

        let name_wide: Vec<u16> = PROVIDER_NAME.encode_utf16().chain(std::iter::once(0)).collect();
        let desc_wide: Vec<u16> = PROVIDER_DESC.encode_utf16().chain(std::iter::once(0)).collect();

        let provider = FWPM_PROVIDER0 {
            providerKey: ST_FW_PROVIDER_KEY,
            displayData: FWPM_DISPLAY_DATA0 {
                name: windows::core::PWSTR(name_wide.as_ptr() as *mut u16),
                description: windows::core::PWSTR(desc_wide.as_ptr() as *mut u16),
            },
            flags: FWPM_PROVIDER_FLAG_PERSISTENT,
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
    pub fn create_sublayer(&mut self) -> Result<(), VpnError> {
        if self.sublayer_registered {
            return Ok(());
        }

        self.register_provider()?;

        // Check if sublayer already exists
        let mut sublayer_ptr: *mut FWPM_SUBLAYER0 = ptr::null_mut();
        let get_result = unsafe {
            FwpmSubLayerGetByKey0(self.handle, &ST_FW_WINFW_BASELINE_SUBLAYER_KEY, &mut sublayer_ptr)
        };

        if get_result == 0 {
            unsafe {
                FwpmFreeMemory0(&mut (sublayer_ptr as *mut _));
            }
            log::info!("WFP sublayer already exists");
            self.sublayer_registered = true;
            return Ok(());
        }

        let name_wide: Vec<u16> = SUBLAYER_NAME.encode_utf16().chain(std::iter::once(0)).collect();
        let desc_wide: Vec<u16> = SUBLAYER_DESC.encode_utf16().chain(std::iter::once(0)).collect();

        let sublayer = FWPM_SUBLAYER0 {
            subLayerKey: ST_FW_WINFW_BASELINE_SUBLAYER_KEY,
            displayData: FWPM_DISPLAY_DATA0 {
                name: windows::core::PWSTR(name_wide.as_ptr() as *mut u16),
                description: windows::core::PWSTR(desc_wide.as_ptr() as *mut u16),
            },
            flags: FWPM_SUBLAYER_FLAG_PERSISTENT,
            providerKey: ptr::addr_of!(ST_FW_PROVIDER_KEY) as *mut GUID,
            providerData: FWP_BYTE_BLOB::default(),
            weight: 0x8000,
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

    /// Add a permit filter for the VPN interface
    pub fn add_tunnel_filter(&self, interface_luid: u64, layer: FilterLayer) -> Result<u64, VpnError> {
        let layer_key = layer.to_guid();

        let name = format!("SwiftTunnel {} Filter", layer.name());
        let name_wide: Vec<u16> = name.encode_utf16().chain(std::iter::once(0)).collect();

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
            flags: FWPM_FILTER_FLAGS(0),
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

    /// Close the WFP engine
    pub fn close(&mut self) {
        if !self.handle.is_invalid() {
            unsafe {
                let _ = FwpmEngineClose0(self.handle);
            }
            self.handle = HANDLE::default();
            log::info!("WFP engine closed");
        }
    }

    pub fn is_ready(&self) -> bool {
        self.provider_registered && self.sublayer_registered
    }
}

impl Drop for WfpEngine {
    fn drop(&mut self) {
        self.close();
    }
}

/// WFP filter layers
#[derive(Debug, Clone, Copy)]
pub enum FilterLayer {
    AleConnectV4,
    AleConnectV6,
    AleRecvAcceptV4,
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

/// Setup WFP for split tunneling
pub fn setup_wfp_for_split_tunnel(interface_luid: u64) -> Result<WfpEngine, VpnError> {
    log::info!("Setting up WFP for split tunneling...");

    let mut engine = WfpEngine::open()?;

    engine.register_provider()?;
    engine.create_sublayer()?;

    engine.add_tunnel_filter(interface_luid, FilterLayer::AleConnectV4)?;
    engine.add_tunnel_filter(interface_luid, FilterLayer::AleRecvAcceptV4)?;

    log::info!("WFP setup complete for interface LUID {}", interface_luid);
    Ok(engine)
}

const RPC_C_AUTHN_WINNT: u32 = 10;
