//! Split Tunnel - ndisapi-based Implementation
//!
//! Uses Windows Packet Filter (ndisapi) for packet-level split tunneling.
//! This replaces the Mullvad WFP-based driver with a simpler approach:
//!
//! Architecture (v2 - Parallel):
//! - Per-CPU packet workers with affinity (WireGuard-like)
//! - Lock-free process cache (RCU pattern for <0.1ms lookups)
//! - Batch packet reading to amortize syscall overhead
//! - 30ms cache refresh for instant game detection
//!
//! Benefits:
//! - <0.1ms added latency for routing decisions
//! - Scales linearly with CPU cores
//! - No lock contention between packet workers
//! - No WFP complexity (callouts, filters, sublayers, providers)

use super::parallel_interceptor::{ParallelInterceptor, QueueOverflowMode, ThroughputStats};
use super::{VpnError, VpnResult};
use std::collections::HashSet;
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

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
        &[
            GamePreset::Roblox,
            GamePreset::Valorant,
            GamePreset::Fortnite,
        ]
    }

    /// Process names that should use VPN
    pub fn process_names(&self) -> &'static [&'static str] {
        match self {
            GamePreset::Roblox => &[
                // Main game client (most common)
                "robloxplayerbeta.exe",
                "robloxplayer.exe",       // Some users don't have "beta" suffix
                "windows10universal.exe", // Microsoft Store version
                // Launchers
                "robloxplayerlauncher.exe",
                // Studio
                "robloxstudiobeta.exe",
                "robloxstudio.exe", // Some users don't have "beta" suffix
                "robloxstudiolauncherbeta.exe",
                "robloxstudiolauncher.exe",
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

/// Legacy compatibility
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
    /// Apps that SHOULD use VPN
    pub tunnel_apps: HashSet<String>,
    /// VPN interface LUID (for adapter identification)
    pub tunnel_interface_luid: u64,
}

impl SplitTunnelConfig {
    pub fn new(tunnel_apps: Vec<String>, tunnel_interface_luid: u64) -> Self {
        Self {
            tunnel_apps: tunnel_apps.into_iter().map(|s| s.to_lowercase()).collect(),
            tunnel_interface_luid,
        }
    }

    /// For backwards compatibility
    pub fn include_apps(&self) -> Vec<String> {
        self.tunnel_apps.iter().cloned().collect()
    }
}

// ═══════════════════════════════════════════════════════════════════════════════
//  DRIVER STATE
// ═══════════════════════════════════════════════════════════════════════════════

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DriverState {
    NotAvailable,
    NotConfigured,
    Initialized,
    Active,
    Error(String),
}

// ═══════════════════════════════════════════════════════════════════════════════
//  SPLIT TUNNEL DRIVER (ndisapi-based)
// ═══════════════════════════════════════════════════════════════════════════════

/// Split tunnel driver using Windows Packet Filter (ndisapi)
///
/// Uses ParallelInterceptor for per-CPU packet processing with <0.1ms latency.
pub struct SplitTunnelDriver {
    /// Parallel packet interceptor (per-CPU workers)
    parallel_interceptor: Option<ParallelInterceptor>,
    /// Current configuration
    pub config: Option<SplitTunnelConfig>,
    /// Current state
    state: DriverState,
    /// Stop flag for background tasks
    stop_flag: Arc<AtomicBool>,
}

unsafe impl Send for SplitTunnelDriver {}
unsafe impl Sync for SplitTunnelDriver {}

impl SplitTunnelDriver {
    pub fn new() -> Self {
        log::info!("Split tunnel: Using parallel mode (per-CPU workers, <0.1ms latency)");

        Self {
            parallel_interceptor: None,
            config: None,
            state: DriverState::NotAvailable,
            stop_flag: Arc::new(AtomicBool::new(false)),
        }
    }

    /// Set the auto-router for automatic relay switching based on game server region
    pub fn set_auto_router(&mut self, router: std::sync::Arc<super::auto_routing::AutoRouter>) {
        if let Some(ref mut interceptor) = self.parallel_interceptor {
            interceptor.set_auto_router(router);
        } else {
            log::warn!("Cannot set auto router: parallel interceptor not created yet");
        }
    }

    /// Set the V3 UDP relay context for unencrypted game traffic relay
    ///
    /// This enables lowest-latency mode: workers forward packets directly to relay
    /// server without encryption.
    pub fn set_relay_context(&mut self, relay: std::sync::Arc<super::udp_relay::UdpRelay>) {
        if let Some(ref mut interceptor) = self.parallel_interceptor {
            interceptor.set_relay_context(relay);
            log::info!("V3 relay context set for unencrypted UDP forwarding");
        } else {
            log::warn!("Cannot set relay context: parallel interceptor not created yet");
        }
    }

    pub fn set_queue_overflow_mode(&mut self, mode: QueueOverflowMode) {
        if let Some(ref mut interceptor) = self.parallel_interceptor {
            interceptor.set_queue_overflow_mode(mode);
        } else {
            log::warn!(
                "Cannot set queue overflow mode ({:?}): parallel interceptor not created yet",
                mode
            );
        }
    }

    /// Get the V3 UDP relay context if set
    pub fn get_relay_context(&self) -> Option<std::sync::Arc<super::udp_relay::UdpRelay>> {
        self.parallel_interceptor
            .as_ref()
            .and_then(|p| p.get_relay_context())
    }

    /// Check if driver is available (can open device)
    pub fn is_available() -> bool {
        ParallelInterceptor::check_driver_available()
    }

    /// Check if the split tunnel driver is available
    /// Will attempt to load the driver if not available
    pub fn check_driver_available() -> bool {
        // Check if WinpkFilter driver is installed
        if ParallelInterceptor::check_driver_available() {
            log::info!("Windows Packet Filter driver is available");
            return true;
        }

        // Starting/creating services and installing drivers requires elevation.
        // If we're not elevated, fail fast so the UI can guide the user through
        // an explicit UAC install flow.
        if !crate::utils::is_administrator() {
            log::warn!(
                "Windows Packet Filter driver not available and process is not elevated; skipping service start / MSI install"
            );
            return false;
        }

        // Try to start the driver service
        if let Err(e) = Self::ensure_driver_service() {
            log::error!("Failed to ensure driver service: {}", e);
        } else {
            // Check again after service start
            if ParallelInterceptor::check_driver_available() {
                log::info!("Windows Packet Filter driver available after service start");
                return true;
            }
        }

        // Try to install from bundled MSI
        log::info!("Attempting to install WinpkFilter from bundled MSI...");
        if let Err(e) = Self::install_driver_from_msi() {
            log::warn!("Failed to install from bundled MSI: {}", e);
        } else {
            // Check again after MSI install
            std::thread::sleep(std::time::Duration::from_secs(2));
            if ParallelInterceptor::check_driver_available() {
                log::info!("Windows Packet Filter driver available after MSI install");
                return true;
            }
        }

        log::error!("Windows Packet Filter driver not available");
        false
    }

    /// Try to install the driver from bundled MSI
    fn install_driver_from_msi() -> Result<(), String> {
        // Look for bundled MSI in common locations
        let msi_paths = [
            // Same directory as exe (for portable/dev)
            std::env::current_exe().ok().and_then(|p| {
                p.parent()
                    .map(|d| d.join("drivers").join("WinpkFilter-x64.msi"))
            }),
            // Tauri bundles assets under a sibling `resources/` directory.
            std::env::current_exe().ok().and_then(|p| {
                p.parent().map(|d| {
                    d.join("resources")
                        .join("drivers")
                        .join("WinpkFilter-x64.msi")
                })
            }),
            std::env::current_exe().ok().and_then(|p| {
                p.parent()
                    .map(|d| d.join("resources").join("WinpkFilter-x64.msi"))
            }),
            // Program Files installation
            Some(PathBuf::from(
                r"C:\Program Files\SwiftTunnel\drivers\WinpkFilter-x64.msi",
            )),
            Some(PathBuf::from(
                r"C:\Program Files\SwiftTunnel\resources\drivers\WinpkFilter-x64.msi",
            )),
        ];

        let mut msi_path = None;
        for path_opt in &msi_paths {
            if let Some(path) = path_opt {
                if path.exists() {
                    msi_path = Some(path.clone());
                    break;
                }
            }
        }

        let msi_path = msi_path.ok_or_else(|| {
            "WinpkFilter-x64.msi not found. Please download from: https://github.com/wiresock/ndisapi/releases".to_string()
        })?;

        log::info!("Installing WinpkFilter from: {}", msi_path.display());

        // Run msiexec to install silently
        let output = std::process::Command::new("msiexec")
            .args([
                "/i",
                &msi_path.to_string_lossy(),
                "/qn", // Quiet, no UI
                "/norestart",
            ])
            .output()
            .map_err(|e| format!("Failed to run msiexec: {}", e))?;

        if output.status.success() {
            log::info!("WinpkFilter MSI installation completed successfully");
            Ok(())
        } else {
            let stderr = String::from_utf8_lossy(&output.stderr);
            let code = output.status.code().unwrap_or(-1);
            // Exit code 1638 = another version already installed (not an error)
            if code == 1638 {
                log::info!("WinpkFilter already installed (different version)");
                Ok(())
            } else {
                Err(format!("msiexec failed with code {}: {}", code, stderr))
            }
        }
    }

    /// Get the path to the driver file
    fn get_driver_path() -> Option<PathBuf> {
        // First try: Same directory as executable (for dev builds)
        if let Ok(exe_path) = std::env::current_exe() {
            if let Some(exe_dir) = exe_path.parent() {
                let driver_path = exe_dir.join("drivers").join("ndisrd.sys");
                if driver_path.exists() {
                    return Some(driver_path);
                }
            }
        }

        // Second try: Program Files installation
        let program_files =
            std::env::var("ProgramFiles").unwrap_or_else(|_| "C:\\Program Files".to_string());
        let install_path = PathBuf::from(&program_files)
            .join("SwiftTunnel")
            .join("drivers")
            .join("ndisrd.sys");
        if install_path.exists() {
            return Some(install_path);
        }

        // Third try: System32 drivers folder (default WinpkFilter location)
        let system_path = PathBuf::from(r"C:\Windows\System32\drivers\ndisrd.sys");
        if system_path.exists() {
            return Some(system_path);
        }

        None
    }

    /// Ensure the driver service exists and is started
    ///
    /// Requires administrator privileges to create or start the driver service.
    fn ensure_driver_service() -> Result<(), String> {
        use windows::Win32::System::Services::*;
        use windows::core::PCWSTR;

        const SERVICE_NAME: &str = "NDISRD";

        // Check for administrator privileges first
        if !crate::utils::is_administrator() {
            return Err(
                "Administrator privileges required to manage driver service. \
                Please run SwiftTunnel as Administrator."
                    .to_string(),
            );
        }

        // Get driver path
        let driver_path = Self::get_driver_path();

        unsafe {
            // Open Service Control Manager
            let scm = OpenSCManagerW(PCWSTR::null(), PCWSTR::null(), SC_MANAGER_ALL_ACCESS)
                .map_err(|e| format!("Failed to open SCM: {}", e))?;

            let service_name_wide: Vec<u16> = SERVICE_NAME
                .encode_utf16()
                .chain(std::iter::once(0))
                .collect();

            // Try to open existing service
            match OpenServiceW(scm, PCWSTR(service_name_wide.as_ptr()), SERVICE_ALL_ACCESS) {
                Ok(service) => {
                    log::info!("NDISRD service exists, checking status...");

                    // Query status
                    let mut status = SERVICE_STATUS::default();
                    if let Ok(_) = QueryServiceStatus(service, &mut status) {
                        if status.dwCurrentState == SERVICE_RUNNING {
                            log::info!("NDISRD service is running");
                            let _ = CloseServiceHandle(service);
                            let _ = CloseServiceHandle(scm);
                            return Ok(());
                        }

                        // Try to start it
                        log::info!("Starting NDISRD service...");
                        match StartServiceW(service, None) {
                            Ok(_) => {
                                log::info!("NDISRD service started");
                                std::thread::sleep(std::time::Duration::from_millis(500));
                            }
                            Err(e) => {
                                log::warn!("Failed to start NDISRD service: {}", e);
                            }
                        }
                    }

                    let _ = CloseServiceHandle(service);
                }
                Err(_) => {
                    log::info!("NDISRD service does not exist");

                    // Only try to create if we have the driver file
                    if let Some(driver_path) = driver_path {
                        log::info!(
                            "Creating NDISRD service with driver: {}",
                            driver_path.display()
                        );

                        let display_name_wide: Vec<u16> = "Windows Packet Filter"
                            .encode_utf16()
                            .chain(std::iter::once(0))
                            .collect();
                        let binary_path_wide: Vec<u16> = driver_path
                            .to_string_lossy()
                            .encode_utf16()
                            .chain(std::iter::once(0))
                            .collect();

                        match CreateServiceW(
                            scm,
                            PCWSTR(service_name_wide.as_ptr()),
                            PCWSTR(display_name_wide.as_ptr()),
                            SERVICE_ALL_ACCESS,
                            SERVICE_KERNEL_DRIVER,
                            SERVICE_DEMAND_START,
                            SERVICE_ERROR_NORMAL,
                            PCWSTR(binary_path_wide.as_ptr()),
                            None,
                            None,
                            None,
                            None,
                            None,
                        ) {
                            Ok(service) => {
                                log::info!("NDISRD service created, starting...");
                                let _ = StartServiceW(service, None);
                                std::thread::sleep(std::time::Duration::from_millis(500));
                                let _ = CloseServiceHandle(service);
                            }
                            Err(e) => {
                                log::error!("Failed to create NDISRD service: {}", e);
                            }
                        }
                    } else {
                        log::warn!("Driver file not found, cannot create service");
                    }
                }
            }

            let _ = CloseServiceHandle(scm);
        }

        Ok(())
    }

    /// Stop the driver service
    pub fn stop_driver_service() -> Result<(), String> {
        use windows::Win32::System::Services::*;
        use windows::core::PCWSTR;

        const SERVICE_NAME: &str = "NDISRD";

        unsafe {
            let scm = OpenSCManagerW(PCWSTR::null(), PCWSTR::null(), SC_MANAGER_ALL_ACCESS)
                .map_err(|e| format!("Failed to open SCM: {}", e))?;

            let service_name_wide: Vec<u16> = SERVICE_NAME
                .encode_utf16()
                .chain(std::iter::once(0))
                .collect();

            match OpenServiceW(scm, PCWSTR(service_name_wide.as_ptr()), SERVICE_STOP) {
                Ok(service) => {
                    let mut status = SERVICE_STATUS::default();
                    let _ = ControlService(service, SERVICE_CONTROL_STOP, &mut status);
                    let _ = CloseServiceHandle(service);
                    log::info!("NDISRD service stop requested");
                }
                Err(_) => {
                    log::debug!("NDISRD service not found (may not be installed)");
                }
            }

            let _ = CloseServiceHandle(scm);
        }

        Ok(())
    }

    /// Restart the driver service
    pub fn restart_driver_service() -> Result<(), String> {
        Self::stop_driver_service()?;
        std::thread::sleep(std::time::Duration::from_millis(500));
        Self::ensure_driver_service()
    }

    /// Cleanup stale state from previous sessions
    pub fn cleanup_stale_state() {
        log::info!("Cleaning up stale split tunnel state...");
        // With ndisapi, there's no persistent state to clean up
        // The driver handles cleanup automatically
        log::info!("Stale state cleanup complete");
    }

    /// Open the driver
    pub fn open(&mut self) -> VpnResult<()> {
        if self.parallel_interceptor.is_some() {
            log::warn!("Split tunnel already open");
            return Ok(());
        }

        log::info!("Opening split tunnel driver (ndisapi, parallel)...");

        let tunnel_apps: Vec<String> = self
            .config
            .as_ref()
            .map(|c| c.tunnel_apps.iter().cloned().collect())
            .unwrap_or_default();

        let interceptor = ParallelInterceptor::new(tunnel_apps);
        self.parallel_interceptor = Some(interceptor);

        self.state = DriverState::NotConfigured;

        log::info!("Split tunnel driver opened");
        Ok(())
    }

    /// Initialize the driver
    pub fn initialize(&mut self) -> VpnResult<()> {
        log::info!("Initializing split tunnel driver...");

        let interceptor = self
            .parallel_interceptor
            .as_mut()
            .ok_or_else(|| VpnError::SplitTunnel("Driver not open".to_string()))?;
        interceptor.initialize()?;

        self.state = DriverState::Initialized;
        log::info!("Split tunnel driver initialized");
        Ok(())
    }

    /// Get running tunnel app names
    pub fn get_running_tunnel_apps(&mut self) -> Vec<String> {
        if let Some(ref interceptor) = self.parallel_interceptor {
            let snapshot = interceptor.get_snapshot();
            snapshot
                .tunnel_pids
                .iter()
                .filter_map(|pid| snapshot.pid_names.get(pid))
                .cloned()
                .collect()
        } else {
            Vec::new()
        }
    }

    /// Get running target names (alias for get_running_tunnel_apps)
    pub fn get_running_target_names(&mut self) -> Vec<String> {
        self.get_running_tunnel_apps()
    }

    /// Configure split tunnel with the given settings
    pub fn configure(&mut self, config: SplitTunnelConfig) -> VpnResult<()> {
        if self.state == DriverState::NotAvailable {
            return Err(VpnError::SplitTunnelNotAvailable);
        }

        log::info!(
            "Configuring split tunnel: {} apps to tunnel",
            config.tunnel_apps.len()
        );
        log::debug!("Tunnel apps: {:?}", config.tunnel_apps);

        let interceptor = self
            .parallel_interceptor
            .as_mut()
            .ok_or_else(|| VpnError::SplitTunnel("Driver not open".to_string()))?;

        // Configure the interceptor
        // Pass the LUID for reliable adapter identification even when
        // Windows API friendly name lookup fails (issue after v0.9.11)
        interceptor.configure(
            "SwiftTunnel", // VPN adapter name
            config.tunnel_apps.iter().cloned().collect(),
            config.tunnel_interface_luid, // LUID for reliable detection
        )?;

        // Start packet interception
        interceptor.start()?;

        self.config = Some(config);
        self.state = DriverState::Active;

        log::info!("Split tunnel configured and active");
        Ok(())
    }

    /// Refresh process exclusions
    pub fn refresh_exclusions(&mut self) -> VpnResult<bool> {
        // Cache refresher runs automatically in background
        // Just check if tunnel apps are running
        let running = !self.get_running_tunnel_apps().is_empty();
        Ok(running)
    }

    /// Re-bind split tunnel interception to the currently active network interface if needed.
    ///
    /// This is primarily to handle default-route changes (Ethernet <-> Wi-Fi) while the app
    /// remains connected, which otherwise results in "connected but 0 packets tunneled".
    pub fn maybe_rebind_on_default_route_change(&mut self) -> VpnResult<bool> {
        if self.state != DriverState::Active {
            return Ok(false);
        }

        let config = match self.config.as_ref() {
            Some(c) => c,
            None => return Ok(false),
        };

        let interceptor = match self.parallel_interceptor.as_mut() {
            Some(i) => i,
            None => return Ok(false),
        };

        interceptor
            .maybe_rebind_on_default_route_change("SwiftTunnel", config.tunnel_interface_luid)
    }

    /// Refresh processes (alias for refresh_exclusions)
    pub fn refresh_processes(&mut self) -> VpnResult<bool> {
        self.refresh_exclusions()
    }

    /// Get driver state value (for compatibility)
    pub fn get_driver_state(&self) -> VpnResult<u64> {
        match &self.state {
            DriverState::NotAvailable => Ok(0),
            DriverState::NotConfigured => Ok(1),
            DriverState::Initialized => Ok(2),
            DriverState::Active => Ok(4),
            DriverState::Error(_) => Ok(0),
        }
    }

    /// Clear configuration
    pub fn clear(&mut self) -> VpnResult<()> {
        if let Some(interceptor) = &mut self.parallel_interceptor {
            interceptor.stop();
        }
        self.config = None;
        self.state = DriverState::NotConfigured;
        log::info!("Split tunnel configuration cleared");
        Ok(())
    }

    /// Close the driver
    pub fn close(&mut self) -> VpnResult<()> {
        log::info!("Closing split tunnel driver...");

        if let Some(mut interceptor) = self.parallel_interceptor.take() {
            interceptor.stop();
        }

        self.config = None;
        self.state = DriverState::NotAvailable;
        self.stop_flag.store(true, Ordering::SeqCst);

        log::info!("Split tunnel driver closed");
        Ok(())
    }

    /// Get current state
    pub fn state(&self) -> &DriverState {
        &self.state
    }

    /// Get current configuration
    pub fn config(&self) -> Option<&SplitTunnelConfig> {
        self.config.as_ref()
    }

    /// Get throughput stats for GUI display
    ///
    /// Returns a clonable ThroughputStats that tracks bytes sent/received through the VPN tunnel.
    /// Returns None if interceptor is not active.
    pub fn get_throughput_stats(&self) -> Option<ThroughputStats> {
        self.parallel_interceptor
            .as_ref()
            .map(|p| p.get_throughput_stats())
    }

    /// Get diagnostic info for UI display
    ///
    /// Returns: (adapter_name, has_default_route, packets_tunneled, packets_bypassed)
    pub fn get_diagnostics(&self) -> Option<(Option<String>, bool, u64, u64)> {
        self.parallel_interceptor
            .as_ref()
            .map(|p| p.get_diagnostics())
    }

    /// Get detected game server IPs for notifications (Bloxstrap-style)
    pub fn get_detected_game_servers(&self) -> Vec<std::net::Ipv4Addr> {
        self.parallel_interceptor
            .as_ref()
            .map(|p| p.get_detected_game_servers())
            .unwrap_or_default()
    }

    /// Clear detected game servers (call on disconnect)
    pub fn clear_detected_game_servers(&self) {
        if let Some(ref p) = self.parallel_interceptor {
            p.clear_detected_game_servers();
        }
    }

    /// Immediately register a process detected via ETW for tunneling
    ///
    /// Called when ETW detects a watched process starting. This adds the
    /// PID → name mapping to the process cache INSTANTLY (microseconds),
    /// so when the first packet arrives, the process is already known.
    ///
    /// This fixes Roblox Error 279 when launching from browser:
    /// - Browser spawns RobloxPlayerBeta.exe via roblox-player:// protocol
    /// - ETW notifies us within MICROSECONDS (not 50ms polling!)
    /// - We register the process here
    /// - First packet arrives → process is already in cache → TUNNELED!
    pub fn register_process_immediate(&self, pid: u32, name: String) {
        if let Some(ref interceptor) = self.parallel_interceptor {
            interceptor.register_process_immediate(pid, name);
            // Also trigger immediate cache refresh for connection table
            interceptor.trigger_refresh();
        } else {
            log::warn!("Cannot register process: parallel interceptor not active");
        }
    }

    /// Switch relay address (proxy to ParallelInterceptor)
    pub fn switch_relay_addr(&self, new_addr: std::net::SocketAddr) -> bool {
        if let Some(ref interceptor) = self.parallel_interceptor {
            interceptor.switch_relay_addr(new_addr)
        } else {
            log::warn!("Cannot switch relay: no parallel interceptor");
            false
        }
    }

    /// Get current relay address (proxy to ParallelInterceptor)
    pub fn current_relay_addr(&self) -> Option<std::net::SocketAddr> {
        self.parallel_interceptor
            .as_ref()
            .and_then(|p| p.current_relay_addr())
    }

    /// Trigger immediate cache refresh (called by ETW when game process detected)
    /// This wakes up the cache refresher from its 2-second sleep
    pub fn trigger_cache_refresh(&self) {
        if let Some(ref interceptor) = self.parallel_interceptor {
            interceptor.trigger_refresh();
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_game_preset_names() {
        assert!(!GamePreset::Roblox.process_names().is_empty());
        assert!(!GamePreset::Valorant.process_names().is_empty());
        assert!(!GamePreset::Fortnite.process_names().is_empty());
    }

    #[test]
    fn test_config_creation() {
        let config = SplitTunnelConfig::new(vec!["robloxplayerbeta.exe".to_string()], 12345);
        assert!(config.tunnel_apps.contains("robloxplayerbeta.exe"));
    }

    #[test]
    fn test_driver_state() {
        let driver = SplitTunnelDriver::new();
        assert_eq!(*driver.state(), DriverState::NotAvailable);
    }
}
