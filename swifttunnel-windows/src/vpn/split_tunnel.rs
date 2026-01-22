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

use std::collections::HashSet;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use super::packet_interceptor::{PacketInterceptor, WireguardContext};
use super::parallel_interceptor::{ParallelInterceptor, ThroughputStats, VpnEncryptContext};
use super::{VpnError, VpnResult};

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

    /// Process names that should use VPN
    pub fn process_names(&self) -> &'static [&'static str] {
        match self {
            GamePreset::Roblox => &[
                "robloxplayerbeta.exe",
                "robloxplayerlauncher.exe",
                "robloxstudiobeta.exe",
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
    /// VPN tunnel IP address (assigned by VPN server)
    pub tunnel_ip: String,
    /// Real internet IP address (from default gateway interface)
    pub internet_ip: String,
    /// VPN interface LUID (for adapter identification)
    pub tunnel_interface_luid: u64,
}

impl SplitTunnelConfig {
    pub fn new(
        tunnel_apps: Vec<String>,
        tunnel_ip: String,
        internet_ip: String,
        tunnel_interface_luid: u64,
    ) -> Self {
        Self {
            tunnel_apps: tunnel_apps.into_iter().map(|s| s.to_lowercase()).collect(),
            tunnel_ip,
            internet_ip,
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
/// v2: Uses ParallelInterceptor for per-CPU packet processing with <0.1ms latency.
/// Maintains API compatibility with the old implementation.
pub struct SplitTunnelDriver {
    /// Parallel packet interceptor (per-CPU workers)
    parallel_interceptor: Option<ParallelInterceptor>,
    /// Legacy packet interceptor (fallback)
    interceptor: Option<PacketInterceptor>,
    /// Whether to use parallel mode (default: true)
    use_parallel: bool,
    /// Current configuration
    pub config: Option<SplitTunnelConfig>,
    /// Current state
    state: DriverState,
    /// Stop flag for background tasks
    stop_flag: Arc<AtomicBool>,
    /// WireGuard context for packet encapsulation
    wireguard_ctx: Option<Arc<WireguardContext>>,
    /// Wintun session for parallel interceptor
    wintun_session: Option<Arc<wintun::Session>>,
}

unsafe impl Send for SplitTunnelDriver {}
unsafe impl Sync for SplitTunnelDriver {}

impl SplitTunnelDriver {
    pub fn new() -> Self {
        // Check SWIFTTUNNEL_PARALLEL env var for mode selection
        let use_parallel = std::env::var("SWIFTTUNNEL_PARALLEL")
            .map(|v| v != "0" && v.to_lowercase() != "false")
            .unwrap_or(true); // Default to parallel mode

        if use_parallel {
            log::info!("Split tunnel: Using parallel mode (per-CPU workers, <0.1ms latency)");
        } else {
            log::info!("Split tunnel: Using legacy single-threaded mode");
        }

        Self {
            parallel_interceptor: None,
            interceptor: None,
            use_parallel,
            config: None,
            state: DriverState::NotAvailable,
            stop_flag: Arc::new(AtomicBool::new(false)),
            wireguard_ctx: None,
            wintun_session: None,
        }
    }

    /// Set the WireGuard context for packet injection
    ///
    /// This enables VPN routing for tunnel app packets by injecting them into Wintun.
    /// The tunnel.rs outbound loop will then pick them up, encapsulate, and send to VPN.
    /// Must be called before configure() for packets to be routed through VPN.
    pub fn set_wireguard_context(&mut self, ctx: Arc<WireguardContext>) {
        log::info!("Setting Wintun injection context for split tunnel");
        // Extract session from context for parallel interceptor
        self.wintun_session = Some(Arc::clone(&ctx.session));
        self.wireguard_ctx = Some(ctx);
    }

    /// Create a WireGuard context from a Wintun session
    pub fn create_wireguard_context(session: Arc<wintun::Session>) -> Arc<WireguardContext> {
        Arc::new(WireguardContext {
            session,
            packets_injected: std::sync::atomic::AtomicU64::new(0),
        })
    }

    /// Set the VPN encryption context for direct WireGuard encryption
    ///
    /// This enables faster outbound path: workers encrypt directly and send via UDP,
    /// bypassing Wintun. Only applies to parallel mode.
    pub fn set_vpn_encrypt_context(&mut self, ctx: VpnEncryptContext) {
        if self.use_parallel {
            if let Some(ref mut interceptor) = self.parallel_interceptor {
                interceptor.set_vpn_encrypt_context(ctx);
            } else {
                log::warn!("Cannot set VPN encrypt context: parallel interceptor not created yet");
            }
        } else {
            log::info!("VPN encrypt context not used in legacy mode");
        }
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

        // Try to start the driver service
        if let Err(e) = Self::ensure_driver_service() {
            log::error!("Failed to ensure driver service: {}", e);
        } else {
            // Check again after service start
            if PacketInterceptor::check_driver_available() {
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
            if PacketInterceptor::check_driver_available() {
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
            std::env::current_exe()
                .ok()
                .and_then(|p| p.parent().map(|d| d.join("drivers").join("WinpkFilter-x64.msi"))),
            // Program Files installation
            Some(PathBuf::from(r"C:\Program Files\SwiftTunnel\drivers\WinpkFilter-x64.msi")),
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
                "/qn",      // Quiet, no UI
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
    fn ensure_driver_service() -> Result<(), String> {
        use windows::core::PCWSTR;
        use windows::Win32::System::Services::*;

        const SERVICE_NAME: &str = "NDISRD";

        // Get driver path
        let driver_path = Self::get_driver_path();

        unsafe {
            // Open Service Control Manager
            let scm = OpenSCManagerW(PCWSTR::null(), PCWSTR::null(), SC_MANAGER_ALL_ACCESS)
                .map_err(|e| format!("Failed to open SCM: {}", e))?;

            let service_name_wide: Vec<u16> =
                SERVICE_NAME.encode_utf16().chain(std::iter::once(0)).collect();

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
                        log::info!("Creating NDISRD service with driver: {}", driver_path.display());

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
        use windows::core::PCWSTR;
        use windows::Win32::System::Services::*;

        const SERVICE_NAME: &str = "NDISRD";

        unsafe {
            let scm = OpenSCManagerW(PCWSTR::null(), PCWSTR::null(), SC_MANAGER_ALL_ACCESS)
                .map_err(|e| format!("Failed to open SCM: {}", e))?;

            let service_name_wide: Vec<u16> =
                SERVICE_NAME.encode_utf16().chain(std::iter::once(0)).collect();

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
        if self.parallel_interceptor.is_some() || self.interceptor.is_some() {
            log::warn!("Split tunnel already open");
            return Ok(());
        }

        log::info!("Opening split tunnel driver (ndisapi, parallel={})...", self.use_parallel);

        // Create packet interceptor
        let tunnel_apps: Vec<String> = self
            .config
            .as_ref()
            .map(|c| c.tunnel_apps.iter().cloned().collect())
            .unwrap_or_default();

        if self.use_parallel {
            let interceptor = ParallelInterceptor::new(tunnel_apps);
            self.parallel_interceptor = Some(interceptor);
        } else {
            let interceptor = PacketInterceptor::new(tunnel_apps);
            self.interceptor = Some(interceptor);
        }

        self.state = DriverState::NotConfigured;

        log::info!("Split tunnel driver opened");
        Ok(())
    }

    /// Initialize the driver
    pub fn initialize(&mut self) -> VpnResult<()> {
        log::info!("Initializing split tunnel driver...");

        if self.use_parallel {
            let interceptor = self.parallel_interceptor.as_mut().ok_or_else(|| {
                VpnError::SplitTunnel("Driver not open".to_string())
            })?;
            interceptor.initialize()?;
        } else {
            let interceptor = self.interceptor.as_mut().ok_or_else(|| {
                VpnError::SplitTunnel("Driver not open".to_string())
            })?;
            interceptor.initialize()?;
        }

        self.state = DriverState::Initialized;
        log::info!("Split tunnel driver initialized");
        Ok(())
    }

    /// Get running tunnel app names
    pub fn get_running_tunnel_apps(&mut self) -> Vec<String> {
        if self.use_parallel {
            // For parallel mode, get from snapshot
            if let Some(ref interceptor) = self.parallel_interceptor {
                let snapshot = interceptor.get_snapshot();
                snapshot.pid_names.values()
                    .filter(|name| {
                        let name_lower = name.to_lowercase();
                        snapshot.tunnel_apps.iter().any(|app| {
                            name_lower.contains(app.trim_end_matches(".exe"))
                        })
                    })
                    .cloned()
                    .collect()
            } else {
                Vec::new()
            }
        } else {
            match &mut self.interceptor {
                Some(interceptor) => interceptor.get_running_tunnel_apps(),
                None => Vec::new(),
            }
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
            "Configuring split tunnel (parallel={}): {} apps to tunnel",
            self.use_parallel,
            config.tunnel_apps.len()
        );
        log::debug!("Tunnel apps: {:?}", config.tunnel_apps);

        if self.use_parallel {
            let interceptor = self.parallel_interceptor.as_mut().ok_or_else(|| {
                VpnError::SplitTunnel("Driver not open".to_string())
            })?;

            // Configure the interceptor
            interceptor.configure(
                "SwiftTunnel", // VPN adapter name
                config.tunnel_apps.iter().cloned().collect(),
            )?;

            // Set NAT IPs for inbound packet rewriting
            interceptor.set_nat_ips(&config.tunnel_ip, &config.internet_ip);

            // Pass Wintun session if available
            if let Some(ref session) = self.wintun_session {
                interceptor.set_wintun_session(Arc::clone(session));
                log::info!("Wintun session passed to parallel interceptor - VPN routing enabled");
            } else {
                log::warn!("No Wintun session - tunnel app packets will be logged but NOT routed through VPN");
            }

            // Start packet interception
            interceptor.start()?;
        } else {
            let interceptor = self.interceptor.as_mut().ok_or_else(|| {
                VpnError::SplitTunnel("Driver not open".to_string())
            })?;

            // Configure the interceptor
            interceptor.configure(
                "SwiftTunnel", // VPN adapter name
                config.tunnel_apps.iter().cloned().collect(),
            )?;

            // Pass WireGuard context to interceptor if available
            if let Some(ref ctx) = self.wireguard_ctx {
                interceptor.set_wireguard_context(Arc::clone(ctx));
                log::info!("WireGuard context passed to packet interceptor - VPN routing enabled");
            } else {
                log::warn!("No WireGuard context - tunnel app packets will be logged but NOT routed through VPN");
            }

            // Start packet interception
            interceptor.start()?;
        }

        self.config = Some(config);
        self.state = DriverState::Active;

        log::info!("Split tunnel configured and active");
        Ok(())
    }

    /// Refresh process exclusions
    pub fn refresh_exclusions(&mut self) -> VpnResult<bool> {
        if self.use_parallel {
            // Parallel mode: cache refresher runs automatically in background
            // Just check if tunnel apps are running
            let running = !self.get_running_tunnel_apps().is_empty();
            Ok(running)
        } else {
            let interceptor = self.interceptor.as_mut().ok_or_else(|| {
                VpnError::SplitTunnel("Driver not open".to_string())
            })?;
            interceptor.refresh()
        }
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
        if let Some(interceptor) = &mut self.interceptor {
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
        if let Some(mut interceptor) = self.interceptor.take() {
            interceptor.stop();
        }

        self.config = None;
        self.state = DriverState::NotAvailable;
        self.stop_flag.store(true, Ordering::SeqCst);
        self.wintun_session = None;

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
        if self.use_parallel {
            self.parallel_interceptor.as_ref().map(|p| p.get_throughput_stats())
        } else {
            self.interceptor.as_ref().map(|p| p.get_throughput_stats())
        }
    }

    /// Create an inbound handler for the WireGuard tunnel
    ///
    /// This handler receives decrypted packets from the tunnel and injects them
    /// to the physical adapter's MSTCP stack so the app receives them.
    /// Returns None if split tunnel is not active in parallel mode.
    pub fn create_inbound_handler(&self) -> Option<super::tunnel::InboundHandler> {
        if self.use_parallel {
            self.parallel_interceptor.as_ref().and_then(|p| p.create_inbound_handler())
        } else {
            // Legacy mode doesn't support inbound injection yet
            None
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
//  HELPER FUNCTIONS
// ═══════════════════════════════════════════════════════════════════════════════

/// Get default tunnel apps (Roblox by default)
pub fn get_default_tunnel_apps() -> Vec<String> {
    GamePreset::Roblox.process_names().iter().map(|s| s.to_string()).collect()
}

/// Find Roblox player path
pub fn find_roblox_path() -> Option<PathBuf> {
    let local_app_data = std::env::var("LOCALAPPDATA").ok()?;
    let roblox_dir = PathBuf::from(local_app_data).join("Roblox").join("Versions");

    if !roblox_dir.exists() {
        return None;
    }

    // Find the version folder with RobloxPlayerBeta.exe
    for entry in std::fs::read_dir(&roblox_dir).ok()? {
        let entry = entry.ok()?;
        let player_exe = entry.path().join("RobloxPlayerBeta.exe");
        if player_exe.exists() {
            return Some(player_exe);
        }
    }

    None
}

/// Find Roblox Studio path
pub fn find_roblox_studio_path() -> Option<PathBuf> {
    let local_app_data = std::env::var("LOCALAPPDATA").ok()?;
    let roblox_dir = PathBuf::from(local_app_data).join("Roblox").join("Versions");

    if !roblox_dir.exists() {
        return None;
    }

    // Find the version folder with RobloxStudioBeta.exe
    for entry in std::fs::read_dir(&roblox_dir).ok()? {
        let entry = entry.ok()?;
        let studio_exe = entry.path().join("RobloxStudioBeta.exe");
        if studio_exe.exists() {
            return Some(studio_exe);
        }
    }

    None
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
        let config = SplitTunnelConfig::new(
            vec!["robloxplayerbeta.exe".to_string()],
            "10.0.0.2".to_string(),
            "192.168.1.100".to_string(),
            12345,
        );
        assert!(config.tunnel_apps.contains("robloxplayerbeta.exe"));
    }

    #[test]
    fn test_driver_state() {
        let driver = SplitTunnelDriver::new();
        assert_eq!(*driver.state(), DriverState::NotAvailable);
    }
}
