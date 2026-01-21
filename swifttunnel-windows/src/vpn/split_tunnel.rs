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
//! - Configurable refresh interval

use std::collections::HashSet;
use std::path::PathBuf;
use sysinfo::{System, ProcessesToUpdate, ProcessRefreshKind, UpdateKind};
use super::{VpnError, VpnResult};

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
///
/// IMPORTANT: Processes in this list are NOT added to the exclude list,
/// which means they will use VPN by default. Only add processes here that:
/// 1. Don't do ANY network I/O, OR
/// 2. MUST use VPN (like our own app to prevent detection loops)
///
/// Do NOT add: cmd.exe, powershell.exe, openssh.exe, conhost.exe, dllhost.exe
/// These all can do network I/O and should be excluded (bypass VPN).
const SKIP_PROCESSES: &[&str] = &[
    // Windows core (internal IPC only, no user-facing network)
    "system", "idle", "registry", "smss.exe", "csrss.exe", "wininit.exe",
    "services.exe", "lsass.exe", "winlogon.exe", "fontdrvhost.exe",
    "dwm.exe", "sihost.exe", "taskhostw.exe", "ctfmon.exe",
    // Our own app - must use VPN to prevent IP detection from showing tunnel IP
    "swifttunnel.exe", "swifttunnel-fps-booster.exe",
    // Memory compression
    "memory compression",
];

// ═══════════════════════════════════════════════════════════════════════════════
//  GAME PRESETS
// ═══════════════════════════════════════════════════════════════════════════════

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum GamePreset {
    Roblox,
    Valorant,
    Fortnite,
}

impl GamePreset {
    pub fn all() -> &'static [GamePreset] {
        &[GamePreset::Roblox, GamePreset::Valorant, GamePreset::Fortnite]
    }

    /// Process names that should use VPN (NOT be excluded)
    pub fn process_names(&self) -> &'static [&'static str] {
        match self {
            GamePreset::Roblox => &[
                "robloxplayerbeta.exe",
                "robloxplayerlauncher.exe",
                "robloxstudiobeta.exe",
                "robloxstudiolauncherbeta.exe",
                "robloxstudiolauncher.exe",
                "windows10universal.exe",
            ],
            GamePreset::Valorant => &[
                "valorant-win64-shipping.exe",
                "valorant.exe",
                "riotclientservices.exe",
                "riotclientux.exe",
                "riotclientuxrender.exe",
            ],
            GamePreset::Fortnite => &[
                "fortniteclient-win64-shipping.exe",
                "fortnitelauncher.exe",
                "epicgameslauncher.exe",
                "epicwebhelper.exe",
            ],
        }
    }

    pub fn display_name(&self) -> &'static str {
        match self {
            GamePreset::Roblox => "Roblox",
            GamePreset::Valorant => "Valorant",
            GamePreset::Fortnite => "Fortnite",
        }
    }

    pub fn icon(&self) -> &'static str {
        match self {
            GamePreset::Roblox => "🎮",
            GamePreset::Valorant => "🎯",
            GamePreset::Fortnite => "🏝️",
        }
    }

    pub fn description(&self) -> &'static str {
        match self {
            GamePreset::Roblox => "Roblox Player & Studio",
            GamePreset::Valorant => "Valorant + Riot Client",
            GamePreset::Fortnite => "Fortnite + Epic Launcher",
        }
    }
}

/// Get all process names that should use VPN for given presets
pub fn get_tunnel_apps_for_presets(presets: &HashSet<GamePreset>) -> HashSet<String> {
    presets
        .iter()
        .flat_map(|p| p.process_names())
        .map(|s| s.to_lowercase())
        .collect()
}

// Legacy compatibility
pub fn get_apps_for_presets(presets: &[GamePreset]) -> Vec<String> {
    presets
        .iter()
        .flat_map(|p| p.process_names())
        .map(|s| s.to_string())
        .collect()
}

pub fn get_apps_for_preset_set(presets: &HashSet<GamePreset>) -> Vec<String> {
    presets
        .iter()
        .flat_map(|p| p.process_names())
        .map(|s| s.to_string())
        .collect()
}

// ═══════════════════════════════════════════════════════════════════════════════
//  SPLIT TUNNEL CONFIGURATION
// ═══════════════════════════════════════════════════════════════════════════════

#[derive(Debug, Clone)]
pub struct SplitTunnelConfig {
    /// Apps that SHOULD use VPN (will NOT be excluded)
    pub tunnel_apps: HashSet<String>,
    /// VPN tunnel IP address (assigned by VPN server)
    pub tunnel_ip: String,
    /// Real internet IP address (from default gateway interface)
    pub internet_ip: String,
    /// VPN interface LUID (not used by driver, kept for compatibility)
    pub tunnel_interface_luid: u64,
}

impl SplitTunnelConfig {
    pub fn new(tunnel_apps: Vec<String>, tunnel_ip: String, internet_ip: String, tunnel_interface_luid: u64) -> Self {
        Self {
            tunnel_apps: tunnel_apps.into_iter().map(|s| s.to_lowercase()).collect(),
            tunnel_ip,
            internet_ip,
            tunnel_interface_luid,
        }
    }

    // For backwards compatibility with old code that uses include_apps
    pub fn include_apps(&self) -> Vec<String> {
        self.tunnel_apps.iter().cloned().collect()
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DriverState {
    NotAvailable,
    NotConfigured,
    /// Driver is initialized (WFP callouts registered) but not yet configured
    Initialized,
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

pub struct SplitTunnelDriver {
    device_handle: Option<windows::Win32::Foundation::HANDLE>,
    /// Current configuration (public for dynamic updates)
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

    /// Check if the split tunnel driver is available
    /// Returns true if driver is running and accessible, false otherwise
    /// Note: Driver must be installed via MSI installer - no auto-installation
    pub fn check_driver_available() -> bool {
        if Self::is_available() {
            log::debug!("Split tunnel driver is available");
            return true;
        }

        log::error!("Split tunnel driver not available. Please reinstall SwiftTunnel to fix this.");
        false
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
    pub fn open(&mut self) -> VpnResult<()> {
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

    /// Initialize the driver - registers WFP callouts
    ///
    /// CRITICAL: setup_wfp_for_split_tunnel() MUST be called BEFORE this method!
    /// The driver's IOCTL_ST_INITIALIZE registers WFP callouts that REFERENCE
    /// the sublayer created by setup_wfp_for_split_tunnel().
    ///
    /// Correct order:
    /// 1. driver.open()
    /// 2. setup_wfp_for_split_tunnel() - creates provider + sublayer
    /// 3. driver.initialize() - THIS METHOD (registers callouts using the sublayer)
    /// 4. driver.configure()
    pub fn initialize(&mut self) -> VpnResult<()> {
        let handle = self.device_handle.ok_or(VpnError::DriverNotOpen)?;

        // Reset any stale state from previous sessions
        log::debug!("Resetting driver state...");
        let _ = self.send_ioctl_neither(handle, ioctl::IOCTL_ST_RESET);

        // Initialize driver - this registers WFP callouts
        log::info!("Initializing split tunnel driver (registering WFP callouts)...");
        if let Err(e) = self.send_ioctl_neither(handle, ioctl::IOCTL_ST_INITIALIZE) {
            let err_str = e.to_string();
            // 0x80320009 = FWP_E_ALREADY_EXISTS - driver already initialized, that's OK
            if !err_str.contains("0x80320009") && !err_str.contains("ALREADY_EXISTS") {
                log::error!("Driver initialization failed: {}", e);
                self.state = DriverState::Error(err_str);
                return Err(e);
            }
            log::debug!("Driver already initialized (OK to continue)");
        }

        self.state = DriverState::Initialized;
        log::info!("Split tunnel driver initialized - WFP callouts registered");
        Ok(())
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
        // Refresh with exe paths - critical for getting process paths
        // ProcessRefreshKind::new() alone doesn't refresh exe paths!
        self.system.refresh_processes_specifics(
            ProcessesToUpdate::All,
            true,
            ProcessRefreshKind::new().with_exe(UpdateKind::OnlyIfNotSet),
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

    /// Get names of currently running tunnel apps (for UI)
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

    // Legacy compatibility
    pub fn get_running_target_names(&mut self) -> Vec<String> {
        self.get_running_tunnel_apps()
    }

    /// Configure split tunnel with EXCLUDE-ALL-EXCEPT logic
    ///
    /// IMPORTANT: The correct initialization order is:
    /// 1. driver.open()
    /// 2. setup_wfp_for_split_tunnel() - creates WFP provider + sublayer
    /// 3. driver.initialize() - registers WFP callouts (need sublayer to exist!)
    /// 4. driver.configure() - THIS METHOD
    pub fn configure(&mut self, config: SplitTunnelConfig) -> VpnResult<()> {
        let handle = self.device_handle.ok_or(VpnError::DriverNotOpen)?;

        // Check state - must be Initialized (after initialize() was called)
        if self.state != DriverState::Initialized {
            log::error!(
                "configure() called in wrong state: {:?} (expected Initialized)",
                self.state
            );
            return Err(VpnError::DriverNotInitialized);
        }

        log::info!(
            "Configuring split tunnel - {} apps will use VPN, everything else excluded",
            config.tunnel_apps.len()
        );

        // NOTE: RESET and INITIALIZE are NOT called here - they're done in initialize()
        // This is critical: WFP filters can only be added AFTER initialize() registers callouts

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

        // Set split tunnel configuration (paths to exclude from VPN)
        // The driver needs to know which executables should bypass the VPN
        let config_data = self.serialize_split_config()?;
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
    /// Returns true if any tunnel apps are running
    pub fn refresh_exclusions(&mut self) -> VpnResult<bool> {
        let handle = self.device_handle.ok_or_else(|| {
            VpnError::SplitTunnel("Driver not open".to_string())
        })?;

        if self.config.is_none() {
            return Ok(false);
        }

        // Scan current processes
        let current_exclude = self.scan_processes_to_exclude();
        let current_pids: HashSet<u32> = current_exclude.iter().map(|p| p.pid).collect();

        // Check if anything changed
        if current_pids == self.excluded_pids {
            // No change - check if any tunnel apps running
            let tunnel_running = !self.get_running_tunnel_apps().is_empty();
            return Ok(tunnel_running);
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

        // Re-register processes with driver
        // Note: We DON'T resend SET_CONFIGURATION here because the tunnel LUID
        // doesn't change during a session - it was set once during configure()
        let proc_data = self.serialize_process_tree_for_exclusion(&current_exclude)?;
        self.send_ioctl(handle, ioctl::IOCTL_ST_REGISTER_PROCESSES, &proc_data)?;

        let tunnel_running = !self.get_running_tunnel_apps().is_empty();
        Ok(tunnel_running)
    }

    // Legacy compatibility
    pub fn refresh_processes(&mut self) -> VpnResult<bool> {
        self.refresh_exclusions()
    }

    /// Serialize process tree for exclusion
    fn serialize_process_tree_for_exclusion(&self, processes: &[ProcessInfo]) -> VpnResult<Vec<u8>> {
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

    /// Serialize configuration for IOCTL_ST_SET_CONFIGURATION
    ///
    /// The Mullvad driver expects a variable-length buffer with:
    /// - ST_CONFIGURATION_HEADER (16 bytes): NumEntries (u64) + TotalLength (u64)
    /// - ST_CONFIGURATION_ENTRY[N] (16 bytes each): ImageNameOffset (u64) + ImageNameLength (u16) + padding (6 bytes)
    /// - String buffer: UTF-16 device paths (no null terminators)
    ///
    /// The paths specify which executables should be split tunneled (excluded from VPN).
    fn serialize_split_config(&self) -> VpnResult<Vec<u8>> {
        if self.excluded_paths.is_empty() {
            // Driver rejects empty configuration, so return error
            return Err(VpnError::SplitTunnel(
                "No processes to exclude - configuration cannot be empty".to_string(),
            ));
        }

        // Convert paths to device paths and deduplicate
        let unique_paths: Vec<_> = self.excluded_paths
            .iter()
            .collect::<HashSet<_>>()
            .into_iter()
            .collect();

        let device_paths: Vec<String> = unique_paths
            .iter()
            .filter_map(|p| Self::to_device_path(p).ok())
            .collect();

        if device_paths.is_empty() {
            return Err(VpnError::SplitTunnel(
                "Failed to convert any paths to device paths".to_string(),
            ));
        }

        // Convert to UTF-16 (no null terminators)
        let wide_paths: Vec<Vec<u16>> = device_paths
            .iter()
            .map(|p| p.encode_utf16().collect())
            .collect();

        // Calculate sizes
        let header_size = 16usize;  // NumEntries (8) + TotalLength (8)
        let entry_size = 16usize;   // ImageNameOffset (8) + ImageNameLength (2) + padding (6)
        let string_size: usize = wide_paths.iter().map(|w| w.len() * 2).sum();
        let total_size = header_size + (entry_size * device_paths.len()) + string_size;

        let mut data = Vec::with_capacity(total_size);

        // Header
        data.extend_from_slice(&(device_paths.len() as u64).to_le_bytes()); // NumEntries
        data.extend_from_slice(&(total_size as u64).to_le_bytes());          // TotalLength

        // Entries
        let mut string_offset = 0usize;
        for wide in &wide_paths {
            let byte_len = (wide.len() * 2) as u16;

            data.extend_from_slice(&(string_offset as u64).to_le_bytes()); // ImageNameOffset
            data.extend_from_slice(&byte_len.to_le_bytes());                // ImageNameLength
            data.extend_from_slice(&[0u8; 6]);                              // Padding

            string_offset += byte_len as usize;
        }

        // String buffer
        for wide in &wide_paths {
            for w in wide {
                data.extend_from_slice(&w.to_le_bytes());
            }
        }

        log::info!(
            "SET_CONFIGURATION: {} paths, {} bytes total",
            device_paths.len(),
            data.len()
        );

        Ok(data)
    }

    /// Serialize IP addresses for IOCTL_ST_REGISTER_IP_ADDRESSES
    ///
    /// The driver expects ST_IP_ADDRESSES struct (40 bytes):
    /// - TunnelIpv4: 4 bytes (VPN assigned IP)
    /// - InternetIpv4: 4 bytes (real internet interface IP)
    /// - TunnelIpv6: 16 bytes (zeros if not using IPv6)
    /// - InternetIpv6: 16 bytes (zeros if not using IPv6)
    fn serialize_ip_addresses(&self, config: &SplitTunnelConfig) -> VpnResult<Vec<u8>> {
        // Parse tunnel IP (VPN assigned IP)
        let tunnel_ip_str = config.tunnel_ip.split('/').next().unwrap_or(&config.tunnel_ip);
        let tunnel_ipv4: std::net::Ipv4Addr = tunnel_ip_str.parse()
            .map_err(|e| VpnError::SplitTunnel(format!("Invalid tunnel IP '{}': {}", tunnel_ip_str, e)))?;

        // Parse internet IP (real interface IP)
        let internet_ip_str = config.internet_ip.split('/').next().unwrap_or(&config.internet_ip);
        let internet_ipv4: std::net::Ipv4Addr = internet_ip_str.parse()
            .map_err(|e| VpnError::SplitTunnel(format!("Invalid internet IP '{}': {}", internet_ip_str, e)))?;

        log::info!("Registering IPs with driver - Tunnel: {}, Internet: {}", tunnel_ipv4, internet_ipv4);

        // Build ST_IP_ADDRESSES struct (40 bytes)
        let mut data = Vec::with_capacity(40);
        data.extend_from_slice(&tunnel_ipv4.octets());    // TunnelIpv4: 4 bytes
        data.extend_from_slice(&internet_ipv4.octets());  // InternetIpv4: 4 bytes
        data.extend_from_slice(&[0u8; 16]);               // TunnelIpv6: 16 bytes (zeros)
        data.extend_from_slice(&[0u8; 16]);               // InternetIpv6: 16 bytes (zeros)

        debug_assert_eq!(data.len(), 40, "ST_IP_ADDRESSES must be exactly 40 bytes");

        Ok(data)
    }

    /// Convert Windows path to device path
    fn to_device_path(path: &str) -> VpnResult<String> {
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

    pub fn get_driver_state(&self) -> VpnResult<u64> {
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

    pub fn clear(&mut self) -> VpnResult<()> {
        if let Some(handle) = self.device_handle {
            let _ = self.send_ioctl_neither(handle, ioctl::IOCTL_ST_CLEAR_CONFIGURATION);
        }
        self.config = None;
        self.excluded_pids.clear();
        self.excluded_paths.clear();
        self.state = DriverState::NotConfigured;
        Ok(())
    }

    pub fn close(&mut self) -> VpnResult<()> {
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

    pub fn config(&self) -> Option<&SplitTunnelConfig> {
        self.config.as_ref()
    }

    fn send_ioctl(&self, handle: windows::Win32::Foundation::HANDLE, code: u32, input: &[u8]) -> VpnResult<Vec<u8>> {
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

    fn send_ioctl_neither(&self, handle: windows::Win32::Foundation::HANDLE, code: u32) -> VpnResult<()> {
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
//  LEGACY TYPES FOR COMPATIBILITY
// ═══════════════════════════════════════════════════════════════════════════════

#[derive(Debug, Clone)]
pub struct TunneledProcess {
    pub pid: u32,
    pub parent_pid: u32,
    pub exe_path: String,
    pub name: String,
}

pub const DEFAULT_TUNNEL_APPS: &[&str] = &[
    "RobloxPlayerBeta.exe",
    "RobloxPlayerLauncher.exe",
    "RobloxStudioBeta.exe",
];

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

pub fn find_roblox_studio_path() -> Option<PathBuf> {
    let local = dirs::data_local_dir()?;
    let versions = local.join("Roblox").join("Versions");
    if versions.exists() {
        if let Ok(entries) = std::fs::read_dir(&versions) {
            for entry in entries.flatten() {
                let exe = entry.path().join("RobloxStudioBeta.exe");
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
        let mut tunnel_apps = HashSet::new();
        tunnel_apps.insert("robloxplayerbeta.exe".to_string());

        driver.config = Some(SplitTunnelConfig {
            tunnel_apps,
            tunnel_ip: "10.0.0.1".to_string(),
            tunnel_interface_luid: 0,
        });

        // Game should NOT be excluded
        assert!(!driver.should_exclude("robloxplayerbeta.exe"));

        // Browser SHOULD be excluded
        assert!(driver.should_exclude("chrome.exe"));

        // System process should NOT be excluded (skipped)
        assert!(!driver.should_exclude("csrss.exe"));
    }

    #[test]
    fn test_game_preset_lowercase() {
        let presets: HashSet<GamePreset> = [GamePreset::Roblox].into_iter().collect();
        let apps = get_tunnel_apps_for_presets(&presets);

        assert!(apps.contains("robloxplayerbeta.exe"));
        // All should be lowercase
        for app in &apps {
            assert_eq!(app, &app.to_lowercase());
        }
    }
}
