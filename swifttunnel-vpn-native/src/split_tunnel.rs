//! Split Tunnel Driver Interface - Exclude-All-Except Mode
//!
//! Uses the Mullvad split tunnel kernel driver in EXCLUDE mode, but with inverted logic:
//! - All processes are EXCLUDED from VPN by default (bypass tunnel)
//! - Only user-selected apps (games) are NOT excluded (use VPN tunnel)
//!
//! This achieves "include mode" behavior using the exclude-only driver:
//! - User selects "Roblox" to tunnel → Roblox is NOT in exclude list → uses VPN
//! - Everything else IS in exclude list → bypasses VPN
//!
//! Optimizations:
//! - HashSet for O(1) process lookups
//! - Differential updates (only add/remove changed processes)
//! - Skip system processes that don't need exclusion
//! - 250ms refresh interval for fast game detection

use std::collections::HashSet;
use std::path::PathBuf;
use sysinfo::{System, ProcessesToUpdate, ProcessRefreshKind};
use crate::error::VpnError;

/// Driver device path (Mullvad split tunnel driver)
const DEVICE_PATH: &str = r"\\.\MULLVADSPLITTUNNEL";

/// IOCTL codes for Mullvad split tunnel driver communication
mod ioctl {
    pub const ST_DEVICE_TYPE: u32 = 0x8000;
    pub const METHOD_BUFFERED: u32 = 0;
    pub const METHOD_NEITHER: u32 = 3;
    pub const FILE_ANY_ACCESS: u32 = 0;

    #[allow(non_snake_case)]
    pub const fn CTL_CODE(device_type: u32, function: u32, method: u32, access: u32) -> u32 {
        (device_type << 16) | (access << 14) | (function << 2) | method
    }

    pub const IOCTL_ST_INITIALIZE: u32 = CTL_CODE(ST_DEVICE_TYPE, 1, METHOD_NEITHER, FILE_ANY_ACCESS);
    pub const IOCTL_ST_REGISTER_PROCESSES: u32 = CTL_CODE(ST_DEVICE_TYPE, 3, METHOD_BUFFERED, FILE_ANY_ACCESS);
    pub const IOCTL_ST_REGISTER_IP_ADDRESSES: u32 = CTL_CODE(ST_DEVICE_TYPE, 4, METHOD_BUFFERED, FILE_ANY_ACCESS);
    pub const IOCTL_ST_SET_CONFIGURATION: u32 = CTL_CODE(ST_DEVICE_TYPE, 6, METHOD_BUFFERED, FILE_ANY_ACCESS);
    pub const IOCTL_ST_CLEAR_CONFIGURATION: u32 = CTL_CODE(ST_DEVICE_TYPE, 8, METHOD_NEITHER, FILE_ANY_ACCESS);
    pub const IOCTL_ST_GET_STATE: u32 = CTL_CODE(ST_DEVICE_TYPE, 9, METHOD_BUFFERED, FILE_ANY_ACCESS);
    pub const IOCTL_ST_RESET: u32 = CTL_CODE(ST_DEVICE_TYPE, 11, METHOD_NEITHER, FILE_ANY_ACCESS);
}

// ═══════════════════════════════════════════════════════════════════════════════
//  SYSTEM PROCESSES TO SKIP (don't need exclusion - no user network traffic)
// ═══════════════════════════════════════════════════════════════════════════════

/// System processes that don't generate meaningful network traffic
/// Skipping these reduces driver overhead
const SKIP_PROCESSES: &[&str] = &[
    // Windows core (no network or internal only)
    "system", "idle", "registry", "smss.exe", "csrss.exe", "wininit.exe",
    "services.exe", "lsass.exe", "winlogon.exe", "fontdrvhost.exe",
    "dwm.exe", "sihost.exe", "taskhostw.exe", "ctfmon.exe", "dllhost.exe",
    "conhost.exe", "cmd.exe", "powershell.exe", "openssh.exe",
    // Our own app / Voidstrap
    "swifttunnel.exe", "bloxstrap.exe", "voidstrap.exe",
    // Memory compression
    "memory compression",
];

/// Default apps to tunnel through VPN (Roblox)
pub const DEFAULT_TUNNEL_APPS: &[&str] = &[
    "robloxplayerbeta.exe",
    "robloxplayerlauncher.exe",
    "robloxstudiobeta.exe",
    "robloxstudiolauncherbeta.exe",
    "robloxstudiolauncher.exe",
    "windows10universal.exe",
];

// ═══════════════════════════════════════════════════════════════════════════════
//  SPLIT TUNNEL CONFIGURATION
// ═══════════════════════════════════════════════════════════════════════════════

/// Split tunnel configuration
#[derive(Debug, Clone)]
pub struct SplitTunnelConfig {
    /// Apps that SHOULD use VPN (will NOT be excluded) - stored lowercase
    pub tunnel_apps: HashSet<String>,
    /// VPN tunnel IP address
    pub tunnel_ip: String,
    /// VPN interface LUID
    pub tunnel_interface_luid: u64,
}

impl SplitTunnelConfig {
    /// Create new config from app list
    pub fn new(apps: Vec<String>, tunnel_ip: String, tunnel_interface_luid: u64) -> Self {
        Self {
            tunnel_apps: apps.into_iter().map(|s| s.to_lowercase()).collect(),
            tunnel_ip,
            tunnel_interface_luid,
        }
    }

    // Legacy compatibility - convert to include_apps format
    pub fn include_apps(&self) -> Vec<String> {
        self.tunnel_apps.iter().cloned().collect()
    }
}

/// Driver state
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DriverState {
    NotAvailable,
    NotConfigured,
    Active,
    Error(String),
}

// ═══════════════════════════════════════════════════════════════════════════════
//  LIGHTWEIGHT PROCESS INFO
// ═══════════════════════════════════════════════════════════════════════════════

/// Minimal process info for exclusion tracking
#[derive(Debug, Clone, Hash, Eq, PartialEq)]
struct ProcessInfo {
    pid: u32,
    name_lower: String,
    exe_path: String,
}

// ═══════════════════════════════════════════════════════════════════════════════
//  SPLIT TUNNEL DRIVER
// ═══════════════════════════════════════════════════════════════════════════════

/// Split tunnel driver interface - Exclude-All-Except mode
pub struct SplitTunnelDriver {
    device_handle: Option<windows::Win32::Foundation::HANDLE>,
    /// Current configuration
    pub config: Option<SplitTunnelConfig>,
    state: DriverState,

    // Efficient tracking with HashSets
    /// Currently excluded PIDs (processes bypassing VPN)
    excluded_pids: HashSet<u32>,
    /// PIDs of tunnel apps (games using VPN)
    tunnel_pids: HashSet<u32>,
    /// Cached process paths for driver config
    excluded_paths: Vec<String>,

    /// System info - reused for efficiency
    system: System,
    /// Skip set for O(1) lookup
    skip_set: HashSet<&'static str>,
}

unsafe impl Send for SplitTunnelDriver {}
unsafe impl Sync for SplitTunnelDriver {}

impl SplitTunnelDriver {
    pub fn new() -> Self {
        Self {
            device_handle: None,
            config: None,
            state: DriverState::NotAvailable,
            excluded_pids: HashSet::with_capacity(256),
            tunnel_pids: HashSet::with_capacity(16),
            excluded_paths: Vec::with_capacity(256),
            system: System::new(),
            skip_set: SKIP_PROCESSES.iter().copied().collect(),
        }
    }

    /// Check if driver is available
    pub fn is_available() -> bool {
        use windows::core::PCSTR;
        use windows::Win32::Foundation::*;
        use windows::Win32::Storage::FileSystem::*;

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

    /// Cleanup stale state on startup
    pub fn cleanup_stale_state() {
        use windows::core::PCSTR;
        use windows::Win32::Foundation::*;
        use windows::Win32::Storage::FileSystem::*;
        use windows::Win32::System::IO::DeviceIoControl;

        log::debug!("Cleaning up stale split tunnel state...");

        unsafe {
            let path = std::ffi::CString::new(DEVICE_PATH).unwrap();
            if let Ok(h) = CreateFileA(
                PCSTR(path.as_ptr() as *const u8),
                GENERIC_READ.0 | GENERIC_WRITE.0,
                FILE_SHARE_READ | FILE_SHARE_WRITE,
                None,
                OPEN_EXISTING,
                FILE_ATTRIBUTE_NORMAL,
                None,
            ) {
                let mut bytes_returned: u32 = 0;
                let _ = DeviceIoControl(h, ioctl::IOCTL_ST_RESET, None, 0, None, 0, Some(&mut bytes_returned), None);
                let _ = CloseHandle(h);
            }
        }
    }

    /// Open driver connection
    pub fn open(&mut self) -> Result<(), VpnError> {
        use windows::core::PCSTR;
        use windows::Win32::Foundation::*;
        use windows::Win32::Storage::FileSystem::*;

        if self.device_handle.is_some() {
            return Ok(());
        }

        unsafe {
            let path = std::ffi::CString::new(DEVICE_PATH).unwrap();
            match CreateFileA(
                PCSTR(path.as_ptr() as *const u8),
                GENERIC_READ.0 | GENERIC_WRITE.0,
                FILE_SHARE_READ | FILE_SHARE_WRITE,
                None,
                OPEN_EXISTING,
                FILE_ATTRIBUTE_NORMAL,
                None,
            ) {
                Ok(h) => {
                    log::info!("Split tunnel driver opened");
                    self.device_handle = Some(h);
                    self.state = DriverState::NotConfigured;
                    Ok(())
                }
                Err(e) => {
                    self.state = DriverState::NotAvailable;
                    Err(VpnError::SplitTunnel(format!("Failed to open driver: {}", e)))
                }
            }
        }
    }

    /// Check if process should be excluded (not a tunnel app and not a system process)
    #[inline]
    fn should_exclude(&self, name_lower: &str) -> bool {
        // Don't exclude if it's a tunnel app (game)
        if let Some(config) = &self.config {
            if config.tunnel_apps.contains(name_lower) {
                return false;
            }
            // Also check without .exe for partial matches
            let name_stem = name_lower.trim_end_matches(".exe");
            for tunnel_app in &config.tunnel_apps {
                let app_stem = tunnel_app.trim_end_matches(".exe");
                if name_stem.contains(app_stem) || app_stem.contains(name_stem) {
                    return false;
                }
            }
        }

        // Skip system processes (don't need to exclude them)
        if self.skip_set.contains(name_lower) {
            return false;
        }

        // Exclude everything else
        true
    }

    /// Scan all processes and return those that should be excluded
    fn scan_processes_to_exclude(&mut self) -> Vec<ProcessInfo> {
        // Efficient refresh - only get what we need
        self.system.refresh_processes_specifics(
            ProcessesToUpdate::All,
            true,
            ProcessRefreshKind::new(), // We only need basic info
        );

        let mut to_exclude = Vec::with_capacity(200);

        for (pid, process) in self.system.processes() {
            let pid_u32 = pid.as_u32();

            // Skip PID 0 and 4 (System)
            if pid_u32 <= 4 {
                continue;
            }

            let name = process.name().to_string_lossy().to_lowercase();

            if self.should_exclude(&name) {
                let exe_path = process
                    .exe()
                    .map(|p| p.to_string_lossy().to_string())
                    .unwrap_or_default();

                // Skip if no exe path (kernel processes)
                if exe_path.is_empty() {
                    continue;
                }

                to_exclude.push(ProcessInfo {
                    pid: pid_u32,
                    name_lower: name,
                    exe_path,
                });
            }
        }

        to_exclude
    }

    /// Get names of currently running tunnel apps (for UI/notifications)
    pub fn get_running_tunnel_apps(&mut self) -> Vec<String> {
        let Some(config) = &self.config else {
            return Vec::new();
        };

        self.system.refresh_processes_specifics(
            ProcessesToUpdate::All,
            true,
            ProcessRefreshKind::new(),
        );

        let mut running = Vec::new();
        for (_pid, process) in self.system.processes() {
            let name = process.name().to_string_lossy().to_lowercase();
            if config.tunnel_apps.contains(&name) {
                running.push(process.name().to_string_lossy().to_string());
            }
        }
        running
    }

    /// Configure split tunnel with EXCLUDE-ALL-EXCEPT logic
    pub fn configure(&mut self, config: SplitTunnelConfig) -> Result<(), VpnError> {
        let handle = self.device_handle.ok_or_else(|| {
            VpnError::SplitTunnel("Driver not open".to_string())
        })?;

        log::info!(
            "Configuring split tunnel - {} apps will use VPN, everything else excluded",
            config.tunnel_apps.len()
        );

        // Reset any stale state
        let _ = self.send_ioctl_neither(handle, ioctl::IOCTL_ST_RESET);

        // Initialize driver
        if let Err(e) = self.send_ioctl_neither(handle, ioctl::IOCTL_ST_INITIALIZE) {
            let err_str = e.to_string();
            if !err_str.contains("0x80320009") && !err_str.contains("ALREADY_EXISTS") {
                return Err(e);
            }
            log::debug!("Driver already initialized, continuing...");
        }

        self.config = Some(config.clone());

        // Initial scan - exclude all non-tunnel processes BEFORE setting config
        let to_exclude = self.scan_processes_to_exclude();

        log::info!(
            "Initial scan: {} processes to exclude from VPN",
            to_exclude.len()
        );

        // Register processes
        self.excluded_pids = to_exclude.iter().map(|p| p.pid).collect();
        self.excluded_paths = to_exclude.iter().map(|p| p.exe_path.clone()).collect();

        let proc_data = self.serialize_process_tree_for_exclusion(&to_exclude)?;
        self.send_ioctl(handle, ioctl::IOCTL_ST_REGISTER_PROCESSES, &proc_data)?;

        // Register IP addresses
        let ip_data = self.serialize_ip_addresses(&config)?;
        self.send_ioctl(handle, ioctl::IOCTL_ST_REGISTER_IP_ADDRESSES, &ip_data)?;

        // Set configuration (paths to exclude)
        let config_data = self.serialize_exclusion_config()?;
        self.send_ioctl(handle, ioctl::IOCTL_ST_SET_CONFIGURATION, &config_data)?;

        // Verify state
        if let Ok(state) = self.get_driver_state() {
            log::info!("Driver state: {} ({})", state, Self::state_name(state));
        }

        self.state = DriverState::Active;
        log::info!("Split tunnel configured - only selected games will use VPN");

        Ok(())
    }

    /// Efficient refresh - only update changed processes
    /// Returns list of currently running tunnel app names
    pub fn refresh_processes(&mut self) -> Result<Vec<String>, VpnError> {
        let handle = self.device_handle.ok_or_else(|| {
            VpnError::SplitTunnel("Driver not open".to_string())
        })?;

        if self.config.is_none() {
            return Ok(Vec::new());
        }

        // Scan current processes
        let current_exclude = self.scan_processes_to_exclude();
        let current_pids: HashSet<u32> = current_exclude.iter().map(|p| p.pid).collect();

        // Get running tunnel apps for return value
        let running_apps = self.get_running_tunnel_apps();

        // Check if anything changed
        if current_pids == self.excluded_pids {
            return Ok(running_apps);
        }

        // Find differences
        let added: Vec<_> = current_pids.difference(&self.excluded_pids).copied().collect();
        let removed: Vec<_> = self.excluded_pids.difference(&current_pids).copied().collect();

        if !added.is_empty() {
            log::debug!("Excluding {} new processes from VPN", added.len());
        }
        if !removed.is_empty() {
            log::debug!("{} excluded processes exited", removed.len());
        }

        // Update state
        self.excluded_pids = current_pids;
        self.excluded_paths = current_exclude.iter().map(|p| p.exe_path.clone()).collect();

        // Re-register with driver
        let proc_data = self.serialize_process_tree_for_exclusion(&current_exclude)?;
        self.send_ioctl(handle, ioctl::IOCTL_ST_REGISTER_PROCESSES, &proc_data)?;

        // Update config
        let config_data = self.serialize_exclusion_config()?;
        self.send_ioctl(handle, ioctl::IOCTL_ST_SET_CONFIGURATION, &config_data)?;

        Ok(running_apps)
    }

    /// Serialize process tree for exclusion
    fn serialize_process_tree_for_exclusion(&self, processes: &[ProcessInfo]) -> Result<Vec<u8>, VpnError> {
        if processes.is_empty() {
            // Empty - just System placeholder
            let mut data = Vec::with_capacity(64);
            data.extend_from_slice(&1u64.to_le_bytes()); // num_entries = 1
            let total_len = 16 + 32 + 12; // header + 1 entry + "System" wide
            data.extend_from_slice(&(total_len as u64).to_le_bytes());

            // System entry
            data.extend_from_slice(&4u64.to_le_bytes()); // pid
            data.extend_from_slice(&0u64.to_le_bytes()); // parent_pid
            data.extend_from_slice(&0u64.to_le_bytes()); // offset
            data.extend_from_slice(&12u16.to_le_bytes()); // size (6 chars * 2)
            data.extend_from_slice(&[0u8; 6]); // padding

            // "System" as wide string
            for c in "System".encode_utf16() {
                data.extend_from_slice(&c.to_le_bytes());
            }

            return Ok(data);
        }

        // Convert paths to device paths
        let device_paths: Vec<String> = processes
            .iter()
            .map(|p| Self::to_device_path(&p.exe_path).unwrap_or_else(|_| p.exe_path.clone()))
            .collect();

        let wide_paths: Vec<Vec<u16>> = device_paths
            .iter()
            .map(|p| p.encode_utf16().collect())
            .collect();

        let header_size = 16usize;
        let entry_size = 32usize;
        let string_size: usize = wide_paths.iter().map(|w| w.len() * 2).sum();
        let total_size = header_size + (entry_size * processes.len()) + string_size;

        let mut data = Vec::with_capacity(total_size);

        // Header
        data.extend_from_slice(&(processes.len() as u64).to_le_bytes());
        data.extend_from_slice(&(total_size as u64).to_le_bytes());

        // Entries
        let mut rel_offset = 0usize;
        for (i, proc) in processes.iter().enumerate() {
            let byte_len = (wide_paths[i].len() * 2) as u16;

            data.extend_from_slice(&(proc.pid as u64).to_le_bytes());
            data.extend_from_slice(&0u64.to_le_bytes()); // parent_pid (not used for exclusion)
            data.extend_from_slice(&(rel_offset as u64).to_le_bytes());
            data.extend_from_slice(&byte_len.to_le_bytes());
            data.extend_from_slice(&[0u8; 6]);

            rel_offset += byte_len as usize;
        }

        // String buffer
        for wide in &wide_paths {
            for w in wide {
                data.extend_from_slice(&w.to_le_bytes());
            }
        }

        Ok(data)
    }

    /// Serialize configuration (paths to exclude from VPN)
    fn serialize_exclusion_config(&self) -> Result<Vec<u8>, VpnError> {
        if self.excluded_paths.is_empty() {
            let mut data = Vec::with_capacity(16);
            data.extend_from_slice(&0u64.to_le_bytes());
            data.extend_from_slice(&16u64.to_le_bytes());
            return Ok(data);
        }

        // Deduplicate paths
        let unique_paths: Vec<_> = self.excluded_paths.iter().collect::<HashSet<_>>().into_iter().collect();

        let device_paths: Vec<String> = unique_paths
            .iter()
            .filter_map(|p| Self::to_device_path(p).ok())
            .collect();

        let wide_paths: Vec<Vec<u16>> = device_paths
            .iter()
            .map(|p| p.encode_utf16().collect())
            .collect();

        let header_size = 16usize;
        let entry_size = 32usize;
        let string_size: usize = wide_paths.iter().map(|w| w.len() * 2).sum();
        let total_size = header_size + (entry_size * wide_paths.len()) + string_size;

        let mut data = Vec::with_capacity(total_size);

        data.extend_from_slice(&(wide_paths.len() as u64).to_le_bytes());
        data.extend_from_slice(&(total_size as u64).to_le_bytes());

        let mut rel_offset = 0usize;
        for wide in &wide_paths {
            let byte_len = (wide.len() * 2) as u16;

            data.extend_from_slice(&0u64.to_le_bytes()); // protocol (unused)
            data.extend_from_slice(&0u64.to_le_bytes()); // padding
            data.extend_from_slice(&(rel_offset as u64).to_le_bytes());
            data.extend_from_slice(&byte_len.to_le_bytes());
            data.extend_from_slice(&[0u8; 6]);

            rel_offset += byte_len as usize;
        }

        for wide in &wide_paths {
            for w in wide {
                data.extend_from_slice(&w.to_le_bytes());
            }
        }

        Ok(data)
    }

    /// Serialize IP addresses
    fn serialize_ip_addresses(&self, config: &SplitTunnelConfig) -> Result<Vec<u8>, VpnError> {
        let ip_str = config.tunnel_ip.split('/').next().unwrap_or(&config.tunnel_ip);
        let ip: std::net::Ipv4Addr = ip_str.parse()
            .map_err(|e| VpnError::SplitTunnel(format!("Invalid tunnel IP: {}", e)))?;

        let mut data = Vec::with_capacity(40);
        data.extend_from_slice(&config.tunnel_interface_luid.to_le_bytes());
        data.extend_from_slice(&ip.octets());
        data.extend_from_slice(&[0u8; 16]); // IPv6
        data.push(1); // has_ipv4
        data.push(0); // has_ipv6
        data.extend_from_slice(&[0u8; 10]); // padding

        Ok(data)
    }

    /// Convert Windows path to device path
    fn to_device_path(path: &str) -> Result<String, VpnError> {
        use windows::Win32::Storage::FileSystem::QueryDosDeviceW;
        use windows::core::PCWSTR;

        if path.len() < 2 || path.chars().nth(1) != Some(':') {
            if path.starts_with(r"\Device\") {
                return Ok(path.to_string());
            }
            return Err(VpnError::SplitTunnel(format!("Invalid path: {}", path)));
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

    fn state_name(state: u64) -> &'static str {
        match state {
            0 => "NONE", 1 => "STARTED", 2 => "INITIALIZED",
            3 => "READY", 4 => "ENGAGED", 5 => "ZOMBIE",
            _ => "UNKNOWN",
        }
    }

    pub fn get_driver_state(&self) -> Result<u64, VpnError> {
        let handle = self.device_handle.ok_or_else(|| {
            VpnError::SplitTunnel("Driver not open".to_string())
        })?;

        let output = self.send_ioctl(handle, ioctl::IOCTL_ST_GET_STATE, &[])?;
        if output.len() >= 8 {
            Ok(u64::from_le_bytes(output[..8].try_into().unwrap()))
        } else {
            Err(VpnError::SplitTunnel("Invalid state response".to_string()))
        }
    }

    pub fn clear(&mut self) -> Result<(), VpnError> {
        if let Some(handle) = self.device_handle {
            let _ = self.send_ioctl_neither(handle, ioctl::IOCTL_ST_CLEAR_CONFIGURATION);
        }
        self.config = None;
        self.excluded_pids.clear();
        self.excluded_paths.clear();
        self.state = DriverState::NotConfigured;
        Ok(())
    }

    pub fn close(&mut self) -> Result<(), VpnError> {
        use windows::Win32::Foundation::CloseHandle;

        if let Some(handle) = self.device_handle.take() {
            let _ = self.send_ioctl_neither(handle, ioctl::IOCTL_ST_RESET);
            unsafe { let _ = CloseHandle(handle); }
        }
        self.config = None;
        self.excluded_pids.clear();
        self.excluded_paths.clear();
        self.state = DriverState::NotAvailable;
        Ok(())
    }

    pub fn state(&self) -> &DriverState {
        &self.state
    }

    fn send_ioctl(&self, handle: windows::Win32::Foundation::HANDLE, code: u32, input: &[u8]) -> Result<Vec<u8>, VpnError> {
        use windows::Win32::System::IO::DeviceIoControl;

        let mut output = vec![0u8; 4096];
        let mut returned: u32 = 0;

        unsafe {
            let result = DeviceIoControl(
                handle, code,
                Some(input.as_ptr() as *const _), input.len() as u32,
                Some(output.as_mut_ptr() as *mut _), output.len() as u32,
                Some(&mut returned), None,
            );

            if result.is_ok() {
                output.truncate(returned as usize);
                Ok(output)
            } else {
                Err(VpnError::SplitTunnel(format!(
                    "IOCTL 0x{:08X} failed: {}",
                    code,
                    windows::core::Error::from_win32()
                )))
            }
        }
    }

    fn send_ioctl_neither(&self, handle: windows::Win32::Foundation::HANDLE, code: u32) -> Result<(), VpnError> {
        use windows::Win32::System::IO::DeviceIoControl;

        let mut returned: u32 = 0;
        unsafe {
            let result = DeviceIoControl(handle, code, None, 0, None, 0, Some(&mut returned), None);
            if result.is_ok() {
                Ok(())
            } else {
                Err(VpnError::SplitTunnel(format!(
                    "IOCTL 0x{:08X} failed: {}",
                    code,
                    windows::core::Error::from_win32()
                )))
            }
        }
    }
}

impl Default for SplitTunnelDriver {
    fn default() -> Self {
        Self::new()
    }
}

impl Drop for SplitTunnelDriver {
    fn drop(&mut self) {
        let _ = self.close();
    }
}

// ═══════════════════════════════════════════════════════════════════════════════
//  LEGACY COMPATIBILITY
// ═══════════════════════════════════════════════════════════════════════════════

/// A running process that should be tunneled (legacy type for compatibility)
#[derive(Debug, Clone)]
pub struct TunneledProcess {
    pub pid: u32,
    pub parent_pid: u32,
    pub exe_path: String,
    pub name: String,
}

/// Get default apps to tunnel (Roblox processes)
pub fn get_default_tunnel_apps() -> Vec<String> {
    DEFAULT_TUNNEL_APPS.iter().map(|s| s.to_string()).collect()
}

pub fn find_roblox_path() -> Option<PathBuf> {
    let local = dirs::data_local_dir()?;
    let versions = local.join("Roblox").join("Versions");
    if versions.exists() {
        if let Ok(entries) = std::fs::read_dir(&versions) {
            for entry in entries.flatten() {
                let exe = entry.path().join("RobloxPlayerBeta.exe");
                if exe.exists() {
                    return Some(exe);
                }
            }
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_should_exclude_logic() {
        let mut driver = SplitTunnelDriver::new();
        let tunnel_apps: HashSet<String> = ["robloxplayerbeta.exe".to_string()].into_iter().collect();

        driver.config = Some(SplitTunnelConfig {
            tunnel_apps,
            tunnel_ip: "10.0.0.1".to_string(),
            tunnel_interface_luid: 0,
        });

        // Game should NOT be excluded (will use VPN)
        assert!(!driver.should_exclude("robloxplayerbeta.exe"));

        // Browser SHOULD be excluded (will bypass VPN)
        assert!(driver.should_exclude("chrome.exe"));

        // System process should NOT be excluded (skipped)
        assert!(!driver.should_exclude("csrss.exe"));
    }

    #[test]
    fn test_config_lowercase() {
        let config = SplitTunnelConfig::new(
            vec!["RobloxPlayerBeta.exe".to_string()],
            "10.0.0.1".to_string(),
            0,
        );

        // Should be stored lowercase
        assert!(config.tunnel_apps.contains("robloxplayerbeta.exe"));
        assert!(!config.tunnel_apps.contains("RobloxPlayerBeta.exe"));
    }
}
