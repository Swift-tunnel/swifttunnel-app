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
use super::{VpnError, VpnResult};

/// Driver device path (Mullvad split tunnel driver)
const DEVICE_PATH: &str = r"\\.\MULLVADSPLITTUNNEL";

/// IOCTL codes for Mullvad split tunnel driver communication
mod ioctl {
    /// Mullvad split tunnel device type
    pub const ST_DEVICE_TYPE: u32 = 0x8000;
    pub const METHOD_BUFFERED: u32 = 0;
    pub const METHOD_NEITHER: u32 = 3;
    pub const FILE_ANY_ACCESS: u32 = 0;

    #[allow(non_snake_case)]
    pub const fn CTL_CODE(device_type: u32, function: u32, method: u32, access: u32) -> u32 {
        (device_type << 16) | (access << 14) | (function << 2) | method
    }

    // Mullvad split tunnel IOCTL codes (matching driver exactly)
    pub const IOCTL_ST_INITIALIZE: u32 = CTL_CODE(ST_DEVICE_TYPE, 1, METHOD_NEITHER, FILE_ANY_ACCESS);
    pub const IOCTL_ST_DEQUEUE_EVENT: u32 = CTL_CODE(ST_DEVICE_TYPE, 2, METHOD_BUFFERED, FILE_ANY_ACCESS);
    pub const IOCTL_ST_REGISTER_PROCESSES: u32 = CTL_CODE(ST_DEVICE_TYPE, 3, METHOD_BUFFERED, FILE_ANY_ACCESS);
    pub const IOCTL_ST_REGISTER_IP_ADDRESSES: u32 = CTL_CODE(ST_DEVICE_TYPE, 4, METHOD_BUFFERED, FILE_ANY_ACCESS);
    pub const IOCTL_ST_GET_IP_ADDRESSES: u32 = CTL_CODE(ST_DEVICE_TYPE, 5, METHOD_BUFFERED, FILE_ANY_ACCESS);
    pub const IOCTL_ST_SET_CONFIGURATION: u32 = CTL_CODE(ST_DEVICE_TYPE, 6, METHOD_BUFFERED, FILE_ANY_ACCESS);
    pub const IOCTL_ST_GET_CONFIGURATION: u32 = CTL_CODE(ST_DEVICE_TYPE, 7, METHOD_BUFFERED, FILE_ANY_ACCESS);
    pub const IOCTL_ST_CLEAR_CONFIGURATION: u32 = CTL_CODE(ST_DEVICE_TYPE, 8, METHOD_NEITHER, FILE_ANY_ACCESS);
    pub const IOCTL_ST_GET_STATE: u32 = CTL_CODE(ST_DEVICE_TYPE, 9, METHOD_BUFFERED, FILE_ANY_ACCESS);
    pub const IOCTL_ST_QUERY_PROCESS: u32 = CTL_CODE(ST_DEVICE_TYPE, 10, METHOD_BUFFERED, FILE_ANY_ACCESS);
    pub const IOCTL_ST_RESET: u32 = CTL_CODE(ST_DEVICE_TYPE, 11, METHOD_NEITHER, FILE_ANY_ACCESS);
}

/// Split tunnel configuration
#[derive(Debug, Clone)]
pub struct SplitTunnelConfig {
    /// List of application paths to tunnel (e.g., "C:\...\RobloxPlayerBeta.exe")
    pub include_apps: Vec<String>,
    /// VPN tunnel IP address
    pub tunnel_ip: String,
    /// VPN interface LUID (from Wintun adapter)
    pub tunnel_interface_luid: u64,
}

/// Default apps to tunnel through VPN (just executable names, not full paths)
/// These are matched case-insensitively against running process names
pub const DEFAULT_TUNNEL_APPS: &[&str] = &[
    // Roblox Player processes
    "RobloxPlayerBeta.exe",
    "RobloxPlayerLauncher.exe",
    // Roblox Studio processes
    "RobloxStudioBeta.exe",
    "RobloxStudioLauncherBeta.exe",
    "RobloxStudioLauncher.exe",
    // Windows Store/UWP version
    "Windows10Universal.exe",
];

// ═══════════════════════════════════════════════════════════════════════════════
//  GAME PRESETS
//  Pre-configured process lists for popular games
// ═══════════════════════════════════════════════════════════════════════════════

/// Game preset for quick selection of which game to tunnel
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum GamePreset {
    Roblox,
    Valorant,
    Fortnite,
}

impl GamePreset {
    /// Get all available presets
    pub fn all() -> &'static [GamePreset] {
        &[GamePreset::Roblox, GamePreset::Valorant, GamePreset::Fortnite]
    }

    /// Get the process names associated with this game preset
    pub fn process_names(&self) -> &'static [&'static str] {
        match self {
            GamePreset::Roblox => &[
                "RobloxPlayerBeta.exe",
                "RobloxPlayerLauncher.exe",
                "RobloxStudioBeta.exe",
                "RobloxStudioLauncherBeta.exe",
                "RobloxStudioLauncher.exe",
                "Windows10Universal.exe",
            ],
            GamePreset::Valorant => &[
                "VALORANT-Win64-Shipping.exe",
                "VALORANT.exe",
                "RiotClientServices.exe",
                "RiotClientUx.exe",
                "RiotClientUxRender.exe",
            ],
            GamePreset::Fortnite => &[
                "FortniteClient-Win64-Shipping.exe",
                "FortniteLauncher.exe",
                "EpicGamesLauncher.exe",
                "EpicWebHelper.exe",
            ],
        }
    }

    /// Get the display name for the preset
    pub fn display_name(&self) -> &'static str {
        match self {
            GamePreset::Roblox => "Roblox",
            GamePreset::Valorant => "Valorant",
            GamePreset::Fortnite => "Fortnite",
        }
    }

    /// Get an icon/emoji for the preset
    pub fn icon(&self) -> &'static str {
        match self {
            GamePreset::Roblox => "🎮",
            GamePreset::Valorant => "🎯",
            GamePreset::Fortnite => "🏝️",
        }
    }

    /// Get a short description of the preset
    pub fn description(&self) -> &'static str {
        match self {
            GamePreset::Roblox => "Roblox Player & Studio",
            GamePreset::Valorant => "Valorant + Riot Client",
            GamePreset::Fortnite => "Fortnite + Epic Launcher",
        }
    }
}

/// Get apps to tunnel for a set of selected game presets
pub fn get_apps_for_presets(presets: &[GamePreset]) -> Vec<String> {
    let mut apps: Vec<String> = presets
        .iter()
        .flat_map(|p| p.process_names())
        .map(|s| s.to_string())
        .collect();

    // Remove duplicates while preserving order
    let mut seen = std::collections::HashSet::new();
    apps.retain(|app| seen.insert(app.clone()));

    apps
}

/// Get apps to tunnel from a HashSet of presets (convenience function for GUI)
pub fn get_apps_for_preset_set(presets: &std::collections::HashSet<GamePreset>) -> Vec<String> {
    let preset_vec: Vec<GamePreset> = presets.iter().cloned().collect();
    get_apps_for_presets(&preset_vec)
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
    /// Check if this process matches any of the configured app patterns
    ///
    /// Handles both full paths and just filenames in include_apps.
    /// Matching is case-insensitive and extracts the filename from paths.
    pub fn matches_config(&self, include_apps: &[String]) -> bool {
        let name_lower = self.name.to_lowercase();

        for app in include_apps {
            // Extract just the filename if it's a full path
            let app_filename = std::path::Path::new(app)
                .file_name()
                .and_then(|n| n.to_str())
                .unwrap_or(app)
                .to_lowercase();

            // Direct match on process name (most reliable)
            if name_lower == app_filename {
                return true;
            }

            // Partial match: process name contains the app name (without .exe)
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
    /// Driver not loaded/available
    NotAvailable,
    /// Driver loaded but not configured
    NotConfigured,
    /// Driver configured and active
    Active,
    /// Driver error
    Error(String),
}

/// Split tunnel driver interface
pub struct SplitTunnelDriver {
    device_handle: Option<windows::Win32::Foundation::HANDLE>,
    config: Option<SplitTunnelConfig>,
    state: DriverState,
    /// Currently registered tunneled processes (PIDs)
    registered_pids: Vec<u32>,
    /// System info for process scanning
    system: System,
}

// SAFETY: Windows HANDLE is a thin pointer that can be safely sent between threads.
// The underlying kernel object is thread-safe.
unsafe impl Send for SplitTunnelDriver {}
unsafe impl Sync for SplitTunnelDriver {}

impl SplitTunnelDriver {
    /// Create a new split tunnel driver interface
    pub fn new() -> Self {
        Self {
            device_handle: None,
            config: None,
            state: DriverState::NotAvailable,
            registered_pids: Vec::new(),
            system: System::new_all(),
        }
    }

    /// Find all running processes that match the configured apps
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

    /// Check if any configured apps (like Roblox) are running
    pub fn is_any_target_running(&mut self) -> bool {
        if let Some(config) = &self.config {
            let apps = config.include_apps.clone();
            !self.find_matching_processes(&apps).is_empty()
        } else {
            false
        }
    }

    /// Get names of currently running tunneled processes
    pub fn get_running_target_names(&mut self) -> Vec<String> {
        if let Some(config) = &self.config {
            let apps = config.include_apps.clone();
            self.find_matching_processes(&apps)
                .iter()
                .map(|p| p.name.clone())
                .collect()
        } else {
            Vec::new()
        }
    }

    /// Get currently registered PIDs
    pub fn registered_pids(&self) -> &[u32] {
        &self.registered_pids
    }

    /// Check if the driver is available (installed and running)
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
    pub fn open(&mut self) -> VpnResult<()> {
        use windows::core::PCSTR;
        use windows::Win32::Foundation::*;
        use windows::Win32::Storage::FileSystem::*;

        if self.device_handle.is_some() {
            return Ok(()); // Already open
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
                        "Failed to open driver: {}. The split tunnel driver may not be installed.",
                        e
                    )))
                }
            }
        }
    }

    /// Configure split tunneling with Mullvad driver
    pub fn configure(&mut self, config: SplitTunnelConfig) -> VpnResult<()> {
        let handle = self.device_handle.ok_or_else(|| {
            VpnError::SplitTunnel("Driver not open".to_string())
        })?;

        log::info!(
            "Configuring split tunnel for {} apps, interface LUID: {}",
            config.include_apps.len(),
            config.tunnel_interface_luid
        );

        // Step 1: Initialize the driver (required before any other operations)
        log::debug!("Initializing split tunnel driver...");
        self.send_ioctl_neither(handle, ioctl::IOCTL_ST_INITIALIZE)?;

        // Step 2: Register process tree with System placeholder FIRST
        // IMPORTANT: The Mullvad driver requires SET_CONFIGURATION before registering
        // actual process PIDs. We register a placeholder first, then refresh after config.
        let placeholder_data = self.serialize_placeholder_process_tree()?;
        log::debug!("Registering placeholder process tree ({} bytes)...", placeholder_data.len());
        self.send_ioctl(handle, ioctl::IOCTL_ST_REGISTER_PROCESSES, &placeholder_data)?;

        // Step 3: Register IP addresses for the tunnel interface
        // Uses ST_IP_ADDRESSES struct (40 bytes)
        let ip_data = self.serialize_ip_addresses(&config)?;
        log::debug!("Registering tunnel IP addresses ({} bytes)...", ip_data.len());
        self.send_ioctl(handle, ioctl::IOCTL_ST_REGISTER_IP_ADDRESSES, &ip_data)?;

        // Step 4: Set configuration (which apps to tunnel)
        let config_data = self.serialize_config(&config)?;
        log::debug!("Setting split tunnel configuration ({} bytes)...", config_data.len());
        self.send_ioctl(handle, ioctl::IOCTL_ST_SET_CONFIGURATION, &config_data)?;

        self.config = Some(config);
        self.state = DriverState::Active;

        log::info!("Split tunnel configured successfully");

        // Step 5: NOW refresh to detect any already-running target processes
        // This is the key fix - we must register actual PIDs AFTER SET_CONFIGURATION
        log::debug!("Refreshing process list to detect already-running targets...");
        match self.refresh_processes() {
            Ok(has_processes) => {
                if has_processes {
                    log::info!("Already-running target processes detected and registered");
                } else {
                    log::info!("No target processes currently running, will detect when they start");
                }
            }
            Err(e) => {
                // Don't fail configuration if refresh fails - processes will be detected on next refresh
                log::warn!("Failed to refresh processes after configuration: {}", e);
            }
        }

        Ok(())
    }

    /// Serialize a placeholder process tree (just System process)
    /// Used during initial configuration before SET_CONFIGURATION is called
    fn serialize_placeholder_process_tree(&mut self) -> VpnResult<Vec<u8>> {
        // Register System process (PID 4) as placeholder
        // The driver needs at least one entry, but we can't register actual target PIDs
        // until after SET_CONFIGURATION is complete
        let processes_to_register: Vec<(u64, u64, String)> = vec![(4, 0, "System".to_string())];

        // Clear registered PIDs - will be populated by refresh_processes()
        self.registered_pids.clear();

        // Calculate sizes
        let header_size: usize = 16;
        let entry_size: usize = 32;
        let num_entries = processes_to_register.len();

        // Convert paths to wide strings
        let wide_paths: Vec<Vec<u16>> = processes_to_register
            .iter()
            .map(|(_, _, path)| path.encode_utf16().collect())
            .collect();

        let string_buffer_size: usize = wide_paths.iter().map(|w| w.len() * 2).sum();
        let total_size = header_size + (entry_size * num_entries) + string_buffer_size;

        let mut data = Vec::with_capacity(total_size);

        // Header
        data.extend_from_slice(&(num_entries as u64).to_le_bytes()); // num_entries
        data.extend_from_slice(&(total_size as u64).to_le_bytes()); // total_length

        // Entries - calculate relative offsets
        let mut relative_offset: usize = 0;
        for (i, (pid, parent_pid, _)) in processes_to_register.iter().enumerate() {
            let byte_length = (wide_paths[i].len() * 2) as u16;

            data.extend_from_slice(&(*pid as u64).to_le_bytes()); // pid
            data.extend_from_slice(&(*parent_pid as u64).to_le_bytes()); // parent_pid
            data.extend_from_slice(&(relative_offset as u64).to_le_bytes()); // image_name_offset (RELATIVE)
            data.extend_from_slice(&byte_length.to_le_bytes()); // image_name_size (2 bytes)
            data.extend_from_slice(&[0u8; 6]); // padding to 32 bytes

            relative_offset += byte_length as usize;
        }

        // String buffer
        for wide in &wide_paths {
            for w in wide {
                data.extend_from_slice(&w.to_le_bytes());
            }
        }

        log::debug!("Placeholder process tree: {} entries, {} total bytes", num_entries, data.len());
        Ok(data)
    }

    /// Serialize process tree for REGISTER_PROCESSES
    ///
    /// The Mullvad driver requires a process tree before SET_CONFIGURATION.
    /// Format:
    /// - Header: num_entries (8 bytes) + total_length (8 bytes)
    /// - Entries: 32 bytes each (pid(8) + parent_pid(8) + image_name_offset(8) + image_name_size(2) + padding(6))
    /// - String buffer: concatenated device paths (wide chars)
    ///
    /// IMPORTANT: image_name_offset is RELATIVE to the start of the string section, not absolute!
    fn serialize_process_tree(&mut self, config: &SplitTunnelConfig) -> VpnResult<Vec<u8>> {
        // Find all running processes that match the configured apps
        let running_processes = self.find_matching_processes(&config.include_apps);

        // Log what we found
        if running_processes.is_empty() {
            log::info!("No matching processes currently running. Split tunnel will activate when target apps start.");
        } else {
            log::info!("Found {} matching processes to tunnel:", running_processes.len());
            for proc in &running_processes {
                log::info!("  - {} (PID {}) from {}", proc.name, proc.pid, proc.exe_path);
            }
        }

        // If no processes are running, register System process as placeholder
        // The driver still needs at least one entry
        let processes_to_register: Vec<(u64, u64, String)> = if running_processes.is_empty() {
            vec![(4, 0, "System".to_string())]
        } else {
            running_processes
                .iter()
                .map(|p| {
                    // Convert path to device path for the driver
                    let device_path = Self::to_device_path(&p.exe_path)
                        .unwrap_or_else(|_| p.exe_path.clone());
                    (p.pid as u64, p.parent_pid as u64, device_path)
                })
                .collect()
        };

        // Store registered PIDs
        self.registered_pids = processes_to_register
            .iter()
            .filter(|(pid, _, _)| *pid != 4) // Don't include System process
            .map(|(pid, _, _)| *pid as u32)
            .collect();

        // Calculate sizes
        let header_size: usize = 16;
        let entry_size: usize = 32;
        let num_entries = processes_to_register.len();

        // Convert paths to wide strings
        let wide_paths: Vec<Vec<u16>> = processes_to_register
            .iter()
            .map(|(_, _, path)| path.encode_utf16().collect())
            .collect();

        let string_buffer_size: usize = wide_paths.iter().map(|w| w.len() * 2).sum();
        let total_size = header_size + (entry_size * num_entries) + string_buffer_size;

        let mut data = Vec::with_capacity(total_size);

        // Header
        data.extend_from_slice(&(num_entries as u64).to_le_bytes()); // num_entries
        data.extend_from_slice(&(total_size as u64).to_le_bytes()); // total_length

        // Entries - calculate relative offsets
        let mut relative_offset: usize = 0;
        for (i, (pid, parent_pid, _)) in processes_to_register.iter().enumerate() {
            let byte_length = (wide_paths[i].len() * 2) as u16;

            data.extend_from_slice(&(*pid as u64).to_le_bytes()); // pid
            data.extend_from_slice(&(*parent_pid as u64).to_le_bytes()); // parent_pid
            data.extend_from_slice(&(relative_offset as u64).to_le_bytes()); // image_name_offset (RELATIVE)
            data.extend_from_slice(&byte_length.to_le_bytes()); // image_name_size (2 bytes)
            data.extend_from_slice(&[0u8; 6]); // padding to 32 bytes

            relative_offset += byte_length as usize;
        }

        // String buffer
        for wide in &wide_paths {
            for w in wide {
                data.extend_from_slice(&w.to_le_bytes());
            }
        }

        log::debug!("Process tree: {} entries, {} total bytes", num_entries, data.len());
        Ok(data)
    }

    /// Refresh process registration - call this periodically to detect new Roblox processes
    pub fn refresh_processes(&mut self) -> VpnResult<bool> {
        let handle = self.device_handle.ok_or_else(|| {
            VpnError::SplitTunnel("Driver not open".to_string())
        })?;

        let config = match &self.config {
            Some(c) => c.clone(),
            None => return Ok(false),
        };

        // Find current running processes
        let running_processes = self.find_matching_processes(&config.include_apps);
        let new_pids: Vec<u32> = running_processes.iter().map(|p| p.pid).collect();

        // Check if anything changed
        let mut old_pids = self.registered_pids.clone();
        old_pids.sort();
        let mut sorted_new = new_pids.clone();
        sorted_new.sort();

        if old_pids == sorted_new {
            // No change
            return Ok(!new_pids.is_empty());
        }

        // Log changes
        for pid in &new_pids {
            if !old_pids.contains(pid) {
                if let Some(proc) = running_processes.iter().find(|p| p.pid == *pid) {
                    log::info!("Detected new process to tunnel: {} (PID {})", proc.name, pid);
                }
            }
        }
        for pid in &old_pids {
            if !new_pids.contains(pid) {
                log::info!("Process exited: PID {}", pid);
            }
        }

        // Re-register process tree with new processes
        let proc_data = self.serialize_process_tree(&config)?;
        log::debug!("Re-registering process tree ({} bytes)...", proc_data.len());
        self.send_ioctl(handle, ioctl::IOCTL_ST_REGISTER_PROCESSES, &proc_data)?;

        Ok(!new_pids.is_empty())
    }

    /// Serialize IP addresses for the tunnel using ST_IP_ADDRESSES struct
    ///
    /// Format (40 bytes total):
    /// - interface_luid: u64 (8 bytes)
    /// - tunnel_ipv4: [u8; 4] (4 bytes) - network byte order
    /// - tunnel_ipv6: [u8; 16] (16 bytes)
    /// - has_ipv4: u8 (1 byte)
    /// - has_ipv6: u8 (1 byte)
    /// - padding: [u8; 10] (10 bytes)
    fn serialize_ip_addresses(&self, config: &SplitTunnelConfig) -> VpnResult<Vec<u8>> {
        // Parse the tunnel IP (e.g., "10.0.0.77/16" -> 10.0.0.77)
        let ip_str = config.tunnel_ip.split('/').next().unwrap_or(&config.tunnel_ip);

        let ip: std::net::Ipv4Addr = ip_str.parse()
            .map_err(|e| VpnError::SplitTunnel(format!("Invalid tunnel IP: {}", e)))?;

        let mut data = Vec::with_capacity(40);

        // interface_luid (8 bytes)
        data.extend_from_slice(&config.tunnel_interface_luid.to_le_bytes());

        // tunnel_ipv4 (4 bytes) - network byte order
        data.extend_from_slice(&ip.octets());

        // tunnel_ipv6 (16 bytes) - zeros for now
        data.extend_from_slice(&[0u8; 16]);

        // has_ipv4 (1 byte)
        data.push(1);

        // has_ipv6 (1 byte)
        data.push(0);

        // padding (10 bytes)
        data.extend_from_slice(&[0u8; 10]);

        debug_assert_eq!(data.len(), 40, "ST_IP_ADDRESSES must be 40 bytes");
        Ok(data)
    }

    /// Add an application to the tunnel list
    /// Note: Mullvad driver requires re-registering process tree and configuration
    pub fn add_app(&mut self, exe_path: &str) -> VpnResult<()> {
        let handle = self.device_handle.ok_or_else(|| {
            VpnError::SplitTunnel("Driver not open".to_string())
        })?;

        log::info!("Adding app to split tunnel: {}", exe_path);

        // Update local config
        {
            let config = self.config.as_mut().ok_or_else(|| {
                VpnError::SplitTunnel("No configuration set".to_string())
            })?;

            if !config.include_apps.contains(&exe_path.to_string()) {
                config.include_apps.push(exe_path.to_string());
            }
        }

        // Re-register process tree (required before SET_CONFIGURATION)
        let config_clone = self.config.clone().unwrap();
        let proc_data = self.serialize_process_tree(&config_clone)?;
        self.send_ioctl(handle, ioctl::IOCTL_ST_REGISTER_PROCESSES, &proc_data)?;

        // Re-serialize and send full configuration
        let config_data = self.serialize_config(&config_clone)?;
        self.send_ioctl(handle, ioctl::IOCTL_ST_SET_CONFIGURATION, &config_data)?;

        Ok(())
    }

    /// Remove an application from the tunnel list
    /// Note: Mullvad driver requires re-registering process tree and configuration
    pub fn remove_app(&mut self, exe_path: &str) -> VpnResult<()> {
        let handle = self.device_handle.ok_or_else(|| {
            VpnError::SplitTunnel("Driver not open".to_string())
        })?;

        log::info!("Removing app from split tunnel: {}", exe_path);

        // Update local config
        {
            let config = self.config.as_mut().ok_or_else(|| {
                VpnError::SplitTunnel("No configuration set".to_string())
            })?;

            config.include_apps.retain(|p| p != exe_path);
        }

        // Re-register process tree (required before SET_CONFIGURATION)
        let config_clone = self.config.clone().unwrap();
        let proc_data = self.serialize_process_tree(&config_clone)?;
        self.send_ioctl(handle, ioctl::IOCTL_ST_REGISTER_PROCESSES, &proc_data)?;

        // Re-serialize and send full configuration
        let config_data = self.serialize_config(&config_clone)?;
        self.send_ioctl(handle, ioctl::IOCTL_ST_SET_CONFIGURATION, &config_data)?;

        Ok(())
    }

    /// Get current driver state from kernel
    /// Returns the state as u64: 0=NONE, 1=STARTED, 2=INITIALIZED, 3=READY, 4=ENGAGED
    pub fn get_driver_state(&self) -> VpnResult<u64> {
        let handle = self.device_handle.ok_or_else(|| {
            VpnError::SplitTunnel("Driver not open".to_string())
        })?;

        let output = self.send_ioctl(handle, ioctl::IOCTL_ST_GET_STATE, &[])?;

        if output.len() >= 8 {
            let state = u64::from_le_bytes([
                output[0], output[1], output[2], output[3],
                output[4], output[5], output[6], output[7],
            ]);
            Ok(state)
        } else {
            Err(VpnError::SplitTunnel(format!(
                "GET_STATE returned {} bytes, expected 8",
                output.len()
            )))
        }
    }

    /// Clear all split tunnel configuration
    pub fn clear(&mut self) -> VpnResult<()> {
        let handle = match self.device_handle {
            Some(h) => h,
            None => return Ok(()), // Already closed/not configured
        };

        log::info!("Clearing split tunnel configuration");

        // IOCTL_ST_CLEAR_CONFIGURATION uses METHOD_NEITHER
        self.send_ioctl_neither(handle, ioctl::IOCTL_ST_CLEAR_CONFIGURATION)?;

        self.config = None;
        self.state = DriverState::NotConfigured;

        Ok(())
    }

    /// Close the driver connection
    pub fn close(&mut self) -> VpnResult<()> {
        use windows::Win32::Foundation::CloseHandle;

        if let Some(handle) = self.device_handle.take() {
            // Reset driver before closing (IOCTL_ST_RESET uses METHOD_NEITHER)
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

    /// Get current driver state
    pub fn state(&self) -> &DriverState {
        &self.state
    }

    /// Get current configuration
    pub fn config(&self) -> Option<&SplitTunnelConfig> {
        self.config.as_ref()
    }

    /// Serialize configuration for Mullvad split tunnel driver
    ///
    /// Format (same as REGISTER_PROCESSES):
    /// - Header: NumEntries (8 bytes) + TotalLength (8 bytes) = 16 bytes
    /// - Entries: 32 bytes each:
    ///   - protocol (8 bytes) - unused, set to 0
    ///   - padding (8 bytes)
    ///   - ImageNameOffset (8 bytes) - RELATIVE to string section start!
    ///   - ImageNameLength (2 bytes)
    ///   - padding (6 bytes)
    /// - String buffer: concatenated device paths (wide chars, no null terminator)
    ///
    /// IMPORTANT: ImageNameOffset is RELATIVE to the start of the string section, not absolute!
    fn serialize_config(&self, config: &SplitTunnelConfig) -> VpnResult<Vec<u8>> {
        let num_entries = config.include_apps.len();

        if num_entries == 0 {
            // Empty configuration - just header
            let mut data = Vec::with_capacity(16);
            data.extend_from_slice(&0u64.to_le_bytes()); // NumEntries = 0
            data.extend_from_slice(&16u64.to_le_bytes()); // TotalLength = 16 (header only)
            return Ok(data);
        }

        // Convert paths to device paths and collect as wide strings
        let mut device_paths: Vec<Vec<u16>> = Vec::new();
        for app_path in &config.include_apps {
            let device_path = Self::to_device_path(app_path)?;
            let wide: Vec<u16> = device_path.encode_utf16().collect();
            device_paths.push(wide);
        }

        // Calculate sizes
        let header_size: usize = 16; // NumEntries (8) + TotalLength (8)
        let entry_size: usize = 32; // Full ConfigurationEntry size
        let entries_size = num_entries * entry_size;

        let mut string_buffer_size: usize = 0;
        for wide in &device_paths {
            string_buffer_size += wide.len() * 2; // 2 bytes per wide char
        }

        let total_length = header_size + entries_size + string_buffer_size;

        let mut data = Vec::with_capacity(total_length);

        // Header
        data.extend_from_slice(&(num_entries as u64).to_le_bytes()); // NumEntries
        data.extend_from_slice(&(total_length as u64).to_le_bytes()); // TotalLength

        // Entries - using RELATIVE offsets (relative to string section start)
        let mut relative_offset: usize = 0;
        for wide in &device_paths {
            let byte_length = (wide.len() * 2) as u16;

            // ConfigurationEntry structure (32 bytes total):
            data.extend_from_slice(&0u64.to_le_bytes()); // protocol (unused)
            data.extend_from_slice(&0u64.to_le_bytes()); // padding
            data.extend_from_slice(&(relative_offset as u64).to_le_bytes()); // ImageNameOffset (RELATIVE!)
            data.extend_from_slice(&byte_length.to_le_bytes()); // ImageNameLength (2 bytes)
            data.extend_from_slice(&[0u8; 6]); // Padding to 32 bytes

            relative_offset += byte_length as usize;
        }

        // String buffer
        for wide in &device_paths {
            for w in wide {
                data.extend_from_slice(&w.to_le_bytes());
            }
        }

        log::debug!("Configuration: {} entries, {} total bytes", num_entries, data.len());
        Ok(data)
    }

    /// Convert a Windows path to a device path
    /// e.g., "C:\Users\..." -> "\Device\HarddiskVolume1\Users\..."
    fn to_device_path(path: &str) -> VpnResult<String> {
        use windows::Win32::Storage::FileSystem::{
            QueryDosDeviceW, GetVolumePathNameW,
        };
        use windows::core::PCWSTR;

        // Extract drive letter (e.g., "C:")
        if path.len() < 2 || !path.chars().nth(1).map(|c| c == ':').unwrap_or(false) {
            // Already might be a device path or invalid
            if path.starts_with(r"\Device\") {
                return Ok(path.to_string());
            }
            return Err(VpnError::SplitTunnel(format!("Invalid path format: {}", path)));
        }

        let drive = &path[0..2]; // e.g., "C:"
        let rest = &path[2..]; // e.g., "\Users\..."

        // Query the device name for this drive letter
        let drive_wide: Vec<u16> = drive.encode_utf16().chain(std::iter::once(0)).collect();
        let mut device_name = vec![0u16; 260];

        unsafe {
            let len = QueryDosDeviceW(
                PCWSTR(drive_wide.as_ptr()),
                Some(&mut device_name),
            );

            if len == 0 {
                // Fallback: assume standard naming
                return Ok(format!(r"\Device\HarddiskVolume1{}", rest));
            }

            // Find the null terminator
            let actual_len = device_name.iter().position(|&c| c == 0).unwrap_or(device_name.len());
            let device_str = String::from_utf16_lossy(&device_name[..actual_len]);

            Ok(format!("{}{}", device_str, rest))
        }
    }

    /// Serialize a single path for add/remove operations (legacy, may not be used)
    fn serialize_path(&self, path: &str) -> VpnResult<Vec<u8>> {
        let device_path = Self::to_device_path(path)?;
        let wide: Vec<u16> = device_path.encode_utf16().collect();
        let mut data = Vec::new();
        data.extend_from_slice(&(wide.len() as u32).to_le_bytes());
        for w in wide {
            data.extend_from_slice(&w.to_le_bytes());
        }
        Ok(data)
    }

    /// Send IOCTL to driver (METHOD_BUFFERED)
    fn send_ioctl(
        &self,
        handle: windows::Win32::Foundation::HANDLE,
        ioctl_code: u32,
        input: &[u8],
    ) -> VpnResult<Vec<u8>> {
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

    /// Send IOCTL to driver (METHOD_NEITHER - no input/output buffers)
    fn send_ioctl_neither(
        &self,
        handle: windows::Win32::Foundation::HANDLE,
        ioctl_code: u32,
    ) -> VpnResult<()> {
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
        Self {
            device_handle: None,
            config: None,
            state: DriverState::NotAvailable,
            registered_pids: Vec::new(),
            system: System::new_all(),
        }
    }
}

impl Drop for SplitTunnelDriver {
    fn drop(&mut self) {
        let _ = self.close();
    }
}

/// Find Roblox executable path
pub fn find_roblox_path() -> Option<PathBuf> {
    // Check common Roblox installation locations
    let local_app_data = dirs::data_local_dir()?;

    let roblox_path = local_app_data
        .join("Roblox")
        .join("Versions");

    if roblox_path.exists() {
        // Find the latest version directory
        if let Ok(entries) = std::fs::read_dir(&roblox_path) {
            for entry in entries.flatten() {
                let exe_path = entry.path().join("RobloxPlayerBeta.exe");
                if exe_path.exists() {
                    return Some(exe_path);
                }
            }
        }
    }

    None
}

/// Find Roblox Studio executable path
pub fn find_roblox_studio_path() -> Option<PathBuf> {
    let local_app_data = dirs::data_local_dir()?;

    let roblox_path = local_app_data
        .join("Roblox")
        .join("Versions");

    if roblox_path.exists() {
        if let Ok(entries) = std::fs::read_dir(&roblox_path) {
            for entry in entries.flatten() {
                let exe_path = entry.path().join("RobloxStudioBeta.exe");
                if exe_path.exists() {
                    return Some(exe_path);
                }
            }
        }
    }

    None
}

/// Get default apps to tunnel (returns exe names, not full paths)
///
/// Using just exe names is more reliable because:
/// 1. Roblox updates change the version folder hash
/// 2. Matching by exe name works regardless of install location
/// 3. Works even if Roblox isn't installed yet (will detect when it starts)
pub fn get_default_tunnel_apps() -> Vec<String> {
    DEFAULT_TUNNEL_APPS.iter().map(|s| s.to_string()).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ioctl_codes() {
        // Verify IOCTL codes are non-zero
        assert_ne!(ioctl::IOCTL_ST_SET_CONFIGURATION, 0);
        assert_ne!(ioctl::IOCTL_ST_GET_STATE, 0);
        assert_ne!(ioctl::IOCTL_ST_CLEAR_CONFIGURATION, 0);
        assert_ne!(ioctl::IOCTL_ST_REGISTER_PROCESSES, 0);
        assert_ne!(ioctl::IOCTL_ST_REGISTER_IP_ADDRESSES, 0);
    }

    #[test]
    fn test_process_matching_exe_name() {
        let process = TunneledProcess {
            pid: 1234,
            parent_pid: 100,
            exe_path: r"C:\Users\Test\AppData\Local\Roblox\Versions\version-abc123\RobloxPlayerBeta.exe".to_string(),
            name: "RobloxPlayerBeta.exe".to_string(),
        };

        // Should match with just exe name
        let apps = vec!["RobloxPlayerBeta.exe".to_string()];
        assert!(process.matches_config(&apps));

        // Should match case-insensitively
        let apps_lower = vec!["robloxplayerbeta.exe".to_string()];
        assert!(process.matches_config(&apps_lower));

        // Should NOT match different process
        let apps_other = vec!["chrome.exe".to_string()];
        assert!(!process.matches_config(&apps_other));
    }

    #[test]
    fn test_process_matching_full_path() {
        let process = TunneledProcess {
            pid: 1234,
            parent_pid: 100,
            exe_path: r"C:\Users\Test\AppData\Local\Roblox\Versions\version-xyz789\RobloxPlayerBeta.exe".to_string(),
            name: "RobloxPlayerBeta.exe".to_string(),
        };

        // Should match even if config has a different version hash path
        // because we extract just the filename
        let apps = vec![r"C:\Users\Other\AppData\Local\Roblox\Versions\version-abc123\RobloxPlayerBeta.exe".to_string()];
        assert!(process.matches_config(&apps));
    }

    #[test]
    fn test_get_default_tunnel_apps() {
        let apps = get_default_tunnel_apps();
        assert!(!apps.is_empty());
        assert!(apps.contains(&"RobloxPlayerBeta.exe".to_string()));
        assert!(apps.contains(&"RobloxStudioBeta.exe".to_string()));
    }

    #[test]
    fn test_serialize_path() {
        let driver = SplitTunnelDriver::new();
        let data = driver.serialize_path("C:\\test.exe").unwrap();
        assert!(!data.is_empty());
    }

    #[test]
    fn test_serialize_ip_addresses_size() {
        let driver = SplitTunnelDriver::new();
        let config = SplitTunnelConfig {
            include_apps: vec![],
            tunnel_ip: "10.0.0.1".to_string(),
            tunnel_interface_luid: 12345,
        };
        let data = driver.serialize_ip_addresses(&config).unwrap();
        // ST_IP_ADDRESSES struct must be exactly 40 bytes
        assert_eq!(data.len(), 40);
    }

    #[test]
    fn test_serialize_config_empty() {
        let driver = SplitTunnelDriver::new();
        let config = SplitTunnelConfig {
            include_apps: vec![],
            tunnel_ip: "10.0.0.1".to_string(),
            tunnel_interface_luid: 12345,
        };
        let data = driver.serialize_config(&config).unwrap();
        // Empty config should be just header (16 bytes)
        assert_eq!(data.len(), 16);
    }
}
