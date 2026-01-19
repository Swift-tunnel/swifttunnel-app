//! Split Tunnel Driver Interface
//!
//! Communicates with the Mullvad split tunnel kernel driver to enable
//! per-process VPN routing. Only specified applications (like Roblox)
//! will have their traffic routed through the VPN.
//!
//! Uses the open-source mullvad-split-tunnel.sys driver (GPL-3.0).
//! Driver source: https://github.com/mullvad/win-split-tunnel

use std::path::PathBuf;
use sysinfo::{System, ProcessesToUpdate};
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
    pub const IOCTL_ST_RESET: u32 = CTL_CODE(ST_DEVICE_TYPE, 11, METHOD_NEITHER, FILE_ANY_ACCESS);
}

/// Default apps to tunnel through VPN
pub const DEFAULT_TUNNEL_APPS: &[&str] = &[
    "RobloxPlayerBeta.exe",
    "RobloxPlayerLauncher.exe",
    "RobloxStudioBeta.exe",
    "RobloxStudioLauncherBeta.exe",
    "RobloxStudioLauncher.exe",
    "Windows10Universal.exe",
];

/// Split tunnel configuration
#[derive(Debug, Clone)]
pub struct SplitTunnelConfig {
    pub include_apps: Vec<String>,
    pub tunnel_ip: String,
    pub tunnel_interface_luid: u64,
}

/// A running process that should be tunneled
#[derive(Debug, Clone)]
pub struct TunneledProcess {
    pub pid: u32,
    pub parent_pid: u32,
    pub exe_path: String,
    pub name: String,
}

impl TunneledProcess {
    pub fn matches_config(&self, include_apps: &[String]) -> bool {
        let name_lower = self.name.to_lowercase();

        for app in include_apps {
            let app_filename = std::path::Path::new(app)
                .file_name()
                .and_then(|n| n.to_str())
                .unwrap_or(app)
                .to_lowercase();

            if name_lower == app_filename {
                return true;
            }

            let app_stem = app_filename.trim_end_matches(".exe");
            if name_lower.contains(app_stem) {
                return true;
            }
        }
        false
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

/// Split tunnel driver interface
pub struct SplitTunnelDriver {
    device_handle: Option<windows::Win32::Foundation::HANDLE>,
    config: Option<SplitTunnelConfig>,
    state: DriverState,
    registered_pids: Vec<u32>,
    system: System,
}

unsafe impl Send for SplitTunnelDriver {}
unsafe impl Sync for SplitTunnelDriver {}

impl SplitTunnelDriver {
    pub fn new() -> Self {
        Self {
            device_handle: None,
            config: None,
            state: DriverState::NotAvailable,
            registered_pids: Vec::new(),
            system: System::new_all(),
        }
    }

    /// Check if the driver is available
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

    /// Open connection to the driver
    pub fn open(&mut self) -> Result<(), VpnError> {
        use windows::core::PCSTR;
        use windows::Win32::Foundation::*;
        use windows::Win32::Storage::FileSystem::*;

        if self.device_handle.is_some() {
            return Ok(());
        }

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
                    log::info!("Split tunnel driver opened successfully");
                    self.device_handle = Some(h);
                    self.state = DriverState::NotConfigured;
                    Ok(())
                }
                Err(e) => {
                    log::warn!("Failed to open split tunnel driver: {}", e);
                    self.state = DriverState::NotAvailable;
                    Err(VpnError::SplitTunnel(format!(
                        "Failed to open driver: {}. Is mullvad-split-tunnel.sys installed?",
                        e
                    )))
                }
            }
        }
    }

    /// Configure split tunneling
    pub fn configure(&mut self, config: SplitTunnelConfig) -> Result<(), VpnError> {
        let handle = self.device_handle.ok_or_else(|| {
            VpnError::SplitTunnel("Driver not open".to_string())
        })?;

        log::info!(
            "Configuring split tunnel for {} apps, interface LUID: {}",
            config.include_apps.len(),
            config.tunnel_interface_luid
        );

        // Initialize driver
        self.send_ioctl_neither(handle, ioctl::IOCTL_ST_INITIALIZE)?;

        // Register process tree
        let config_clone = config.clone();
        let proc_data = self.serialize_process_tree(&config_clone)?;
        self.send_ioctl(handle, ioctl::IOCTL_ST_REGISTER_PROCESSES, &proc_data)?;

        // Register IP addresses
        let ip_data = self.serialize_ip_addresses(&config)?;
        self.send_ioctl(handle, ioctl::IOCTL_ST_REGISTER_IP_ADDRESSES, &ip_data)?;

        // Set configuration
        let config_data = self.serialize_config(&config)?;
        self.send_ioctl(handle, ioctl::IOCTL_ST_SET_CONFIGURATION, &config_data)?;

        self.config = Some(config);
        self.state = DriverState::Active;

        log::info!("Split tunnel configured successfully");
        Ok(())
    }

    /// Find matching processes
    pub fn find_matching_processes(&mut self, include_apps: &[String]) -> Vec<TunneledProcess> {
        self.system.refresh_processes(ProcessesToUpdate::All, true);

        let mut matching = Vec::new();

        for (pid, process) in self.system.processes() {
            let name = process.name().to_string_lossy().to_string();
            let exe_path = process
                .exe()
                .map(|p| p.to_string_lossy().to_string())
                .unwrap_or_default();
            let parent_pid = process.parent().map(|p| p.as_u32()).unwrap_or(0);

            let tp = TunneledProcess {
                pid: pid.as_u32(),
                parent_pid,
                exe_path,
                name,
            };

            if tp.matches_config(include_apps) {
                matching.push(tp);
            }
        }

        matching
    }

    /// Refresh process registration
    pub fn refresh_processes(&mut self) -> Result<Vec<String>, VpnError> {
        let handle = self.device_handle.ok_or_else(|| {
            VpnError::SplitTunnel("Driver not open".to_string())
        })?;

        let config = match &self.config {
            Some(c) => c.clone(),
            None => return Ok(Vec::new()),
        };

        let running_processes = self.find_matching_processes(&config.include_apps);
        let new_pids: Vec<u32> = running_processes.iter().map(|p| p.pid).collect();
        let new_names: Vec<String> = running_processes.iter().map(|p| p.name.clone()).collect();

        let mut old_pids = self.registered_pids.clone();
        old_pids.sort();
        let mut sorted_new = new_pids.clone();
        sorted_new.sort();

        if old_pids != sorted_new {
            // Re-register process tree
            let proc_data = self.serialize_process_tree(&config)?;
            self.send_ioctl(handle, ioctl::IOCTL_ST_REGISTER_PROCESSES, &proc_data)?;
        }

        Ok(new_names)
    }

    /// Clear configuration
    pub fn clear(&mut self) -> Result<(), VpnError> {
        let handle = match self.device_handle {
            Some(h) => h,
            None => return Ok(()),
        };

        self.send_ioctl_neither(handle, ioctl::IOCTL_ST_CLEAR_CONFIGURATION)?;
        self.config = None;
        self.state = DriverState::NotConfigured;
        Ok(())
    }

    /// Close driver connection
    pub fn close(&mut self) -> Result<(), VpnError> {
        use windows::Win32::Foundation::CloseHandle;

        if let Some(handle) = self.device_handle.take() {
            let _ = self.send_ioctl_neither(handle, ioctl::IOCTL_ST_RESET);
            unsafe {
                let _ = CloseHandle(handle);
            }
            log::info!("Split tunnel driver closed");
        }

        self.config = None;
        self.state = DriverState::NotAvailable;
        Ok(())
    }

    fn serialize_process_tree(&mut self, config: &SplitTunnelConfig) -> Result<Vec<u8>, VpnError> {
        let running_processes = self.find_matching_processes(&config.include_apps);

        if !running_processes.is_empty() {
            log::info!("Found {} matching processes to tunnel", running_processes.len());
            for proc in &running_processes {
                log::info!("  - {} (PID {})", proc.name, proc.pid);
            }
        }

        let processes_to_register: Vec<(u64, u64, String)> = if running_processes.is_empty() {
            vec![(4, 0, "System".to_string())]
        } else {
            running_processes
                .iter()
                .map(|p| {
                    let device_path = Self::to_device_path(&p.exe_path)
                        .unwrap_or_else(|_| p.exe_path.clone());
                    (p.pid as u64, p.parent_pid as u64, device_path)
                })
                .collect()
        };

        self.registered_pids = processes_to_register
            .iter()
            .filter(|(pid, _, _)| *pid != 4)
            .map(|(pid, _, _)| *pid as u32)
            .collect();

        let header_size: usize = 16;
        let entry_size: usize = 32;
        let num_entries = processes_to_register.len();

        let wide_paths: Vec<Vec<u16>> = processes_to_register
            .iter()
            .map(|(_, _, path)| path.encode_utf16().collect())
            .collect();

        let string_buffer_size: usize = wide_paths.iter().map(|w| w.len() * 2).sum();
        let total_size = header_size + (entry_size * num_entries) + string_buffer_size;

        let mut data = Vec::with_capacity(total_size);

        data.extend_from_slice(&(num_entries as u64).to_le_bytes());
        data.extend_from_slice(&(total_size as u64).to_le_bytes());

        let mut relative_offset: usize = 0;
        for (i, (pid, parent_pid, _)) in processes_to_register.iter().enumerate() {
            let byte_length = (wide_paths[i].len() * 2) as u16;

            data.extend_from_slice(&(*pid as u64).to_le_bytes());
            data.extend_from_slice(&(*parent_pid as u64).to_le_bytes());
            data.extend_from_slice(&(relative_offset as u64).to_le_bytes());
            data.extend_from_slice(&byte_length.to_le_bytes());
            data.extend_from_slice(&[0u8; 6]);

            relative_offset += byte_length as usize;
        }

        for wide in &wide_paths {
            for w in wide {
                data.extend_from_slice(&w.to_le_bytes());
            }
        }

        Ok(data)
    }

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

    fn serialize_config(&self, config: &SplitTunnelConfig) -> Result<Vec<u8>, VpnError> {
        let num_entries = config.include_apps.len();

        if num_entries == 0 {
            let mut data = Vec::with_capacity(16);
            data.extend_from_slice(&0u64.to_le_bytes());
            data.extend_from_slice(&16u64.to_le_bytes());
            return Ok(data);
        }

        let mut device_paths: Vec<Vec<u16>> = Vec::new();
        for app_path in &config.include_apps {
            let device_path = Self::to_device_path(app_path)?;
            let wide: Vec<u16> = device_path.encode_utf16().collect();
            device_paths.push(wide);
        }

        let header_size: usize = 16;
        let entry_size: usize = 32;
        let entries_size = num_entries * entry_size;

        let string_buffer_size: usize = device_paths.iter().map(|w| w.len() * 2).sum();
        let total_length = header_size + entries_size + string_buffer_size;

        let mut data = Vec::with_capacity(total_length);

        data.extend_from_slice(&(num_entries as u64).to_le_bytes());
        data.extend_from_slice(&(total_length as u64).to_le_bytes());

        let mut relative_offset: usize = 0;
        for wide in &device_paths {
            let byte_length = (wide.len() * 2) as u16;

            data.extend_from_slice(&0u64.to_le_bytes()); // protocol
            data.extend_from_slice(&0u64.to_le_bytes()); // padding
            data.extend_from_slice(&(relative_offset as u64).to_le_bytes());
            data.extend_from_slice(&byte_length.to_le_bytes());
            data.extend_from_slice(&[0u8; 6]);

            relative_offset += byte_length as usize;
        }

        for wide in &device_paths {
            for w in wide {
                data.extend_from_slice(&w.to_le_bytes());
            }
        }

        Ok(data)
    }

    fn to_device_path(path: &str) -> Result<String, VpnError> {
        use windows::Win32::Storage::FileSystem::QueryDosDeviceW;
        use windows::core::PCWSTR;

        if path.len() < 2 || !path.chars().nth(1).map(|c| c == ':').unwrap_or(false) {
            if path.starts_with(r"\Device\") {
                return Ok(path.to_string());
            }
            return Err(VpnError::SplitTunnel(format!("Invalid path format: {}", path)));
        }

        let drive = &path[0..2];
        let rest = &path[2..];

        let drive_wide: Vec<u16> = drive.encode_utf16().chain(std::iter::once(0)).collect();
        let mut device_name = vec![0u16; 260];

        unsafe {
            let len = QueryDosDeviceW(
                PCWSTR(drive_wide.as_ptr()),
                Some(&mut device_name),
            );

            if len == 0 {
                return Ok(format!(r"\Device\HarddiskVolume1{}", rest));
            }

            let actual_len = device_name.iter().position(|&c| c == 0).unwrap_or(device_name.len());
            let device_str = String::from_utf16_lossy(&device_name[..actual_len]);

            Ok(format!("{}{}", device_str, rest))
        }
    }

    fn send_ioctl(
        &self,
        handle: windows::Win32::Foundation::HANDLE,
        ioctl_code: u32,
        input: &[u8],
    ) -> Result<Vec<u8>, VpnError> {
        use windows::Win32::System::IO::DeviceIoControl;

        let mut output = vec![0u8; 4096];
        let mut bytes_returned: u32 = 0;

        unsafe {
            let result = DeviceIoControl(
                handle,
                ioctl_code,
                Some(input.as_ptr() as *const std::ffi::c_void),
                input.len() as u32,
                Some(output.as_mut_ptr() as *mut std::ffi::c_void),
                output.len() as u32,
                Some(&mut bytes_returned),
                None,
            );

            if result.is_ok() {
                output.truncate(bytes_returned as usize);
                Ok(output)
            } else {
                let error = windows::core::Error::from_win32();
                Err(VpnError::SplitTunnel(format!(
                    "IOCTL 0x{:08X} failed: {}",
                    ioctl_code,
                    error
                )))
            }
        }
    }

    fn send_ioctl_neither(
        &self,
        handle: windows::Win32::Foundation::HANDLE,
        ioctl_code: u32,
    ) -> Result<(), VpnError> {
        use windows::Win32::System::IO::DeviceIoControl;

        let mut bytes_returned: u32 = 0;

        unsafe {
            let result = DeviceIoControl(
                handle,
                ioctl_code,
                None,
                0,
                None,
                0,
                Some(&mut bytes_returned),
                None,
            );

            if result.is_ok() {
                Ok(())
            } else {
                let error = windows::core::Error::from_win32();
                Err(VpnError::SplitTunnel(format!(
                    "IOCTL 0x{:08X} failed: {}",
                    ioctl_code,
                    error
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

/// Get default apps to tunnel
pub fn get_default_tunnel_apps() -> Vec<String> {
    DEFAULT_TUNNEL_APPS.iter().map(|s| s.to_string()).collect()
}
