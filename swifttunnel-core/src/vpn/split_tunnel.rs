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

use super::parallel_interceptor::{
    AdapterBindingPreference, ParallelInterceptor, QueueOverflowMode, SplitTunnelDiagnostics,
    ThroughputStats,
};
use super::{VpnError, VpnResult};
use crate::utils::normalize_guid_ascii_lowercase;
use std::collections::HashSet;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

const DRIVER_READY_POLL_INTERVAL: Duration = Duration::from_millis(500);
const DRIVER_SERVICE_START_TIMEOUT: Duration = Duration::from_secs(10);
const DRIVER_READY_TIMEOUT: Duration = Duration::from_secs(20);
const SERVICE_NAME: &str = "NDISRD";
const SERVICE_DISPLAY_NAME: &str = "Windows Packet Filter";

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
    /// Explicit adapter binding preference for manual mode or remembered Smart Auto choices.
    pub binding_preference: Option<AdapterBindingPreference>,
}

impl SplitTunnelConfig {
    pub fn new(
        tunnel_apps: Vec<String>,
        tunnel_interface_luid: u64,
        binding_preference: Option<AdapterBindingPreference>,
    ) -> Self {
        Self {
            tunnel_apps: tunnel_apps.into_iter().map(|s| s.to_lowercase()).collect(),
            tunnel_interface_luid,
            binding_preference: binding_preference.map(|mut preference| {
                preference.guid = normalize_guid_ascii_lowercase(&preference.guid)
                    .unwrap_or(preference.guid)
                    .to_string();
                preference
            }),
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

        match Self::repair_and_wait_until_available(DRIVER_SERVICE_START_TIMEOUT) {
            Ok(()) => {
                log::info!("Windows Packet Filter driver available after service repair/start");
                return true;
            }
            Err(e) => {
                log::error!("Failed to repair driver service before MSI install: {}", e);
            }
        }

        // Try to install from the bundled MSI.
        log::info!("Attempting to install WinpkFilter from bundled MSI...");
        if let Err(e) = Self::install_driver_from_msi() {
            log::warn!("Failed to install from bundled MSI: {}", e);
        } else {
            match Self::repair_and_wait_until_available(DRIVER_READY_TIMEOUT) {
                Ok(()) => {
                    log::info!("Windows Packet Filter driver available after MSI install");
                    return true;
                }
                Err(e) => {
                    log::warn!(
                        "Driver install succeeded, but readiness repair failed: {}",
                        e
                    );
                }
            }
        }

        log::error!("Windows Packet Filter driver not available");
        false
    }

    /// Try to install the driver from the bundled MSI.
    fn install_driver_from_msi() -> Result<(), String> {
        let msi_path = Self::find_driver_msi().ok_or_else(Self::driver_msi_not_found_message)?;

        log::info!("Installing WinpkFilter from: {}", msi_path.display());

        let output = std::process::Command::new("msiexec")
            .args(["/i", &msi_path.to_string_lossy(), "/qn", "/norestart"])
            .output()
            .map_err(|e| format!("Failed to run msiexec: {}", e))?;

        let code = output.status.code().unwrap_or(-1);
        if matches!(code, 0 | 1638 | 1641 | 3010) {
            if code == 1638 {
                log::info!("WinpkFilter already installed (different version)");
            } else {
                log::info!("WinpkFilter MSI installation completed with code {}", code);
            }
            return Ok(());
        }

        let stderr = String::from_utf8_lossy(&output.stderr);
        Err(format!("msiexec failed with code {}: {}", code, stderr))
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

    pub fn repair_and_wait_until_available(timeout: Duration) -> Result<(), String> {
        let deadline = Instant::now() + timeout;
        let mut last_error: Option<String> = None;
        let mut first_attempt = true;

        loop {
            let remaining = deadline.saturating_duration_since(Instant::now());
            if remaining.is_zero() {
                break;
            }

            if ParallelInterceptor::check_driver_available() {
                return Ok(());
            }

            let result = if first_attempt {
                Self::repair_driver_service_registration(remaining)
            } else {
                Self::ensure_driver_service(remaining)
            };
            first_attempt = false;

            if let Err(err) = result {
                log::warn!("NDISRD readiness repair attempt failed: {}", err);
                last_error = Some(err);
            }

            if ParallelInterceptor::check_driver_available() {
                return Ok(());
            }

            if Instant::now() >= deadline {
                break;
            }

            std::thread::sleep(DRIVER_READY_POLL_INTERVAL);
        }

        Err(last_error.unwrap_or_else(|| {
            format!(
                "Windows Packet Filter driver did not become available within {} seconds.",
                timeout.as_secs()
            )
        }))
    }

    fn repair_driver_service_registration(timeout: Duration) -> Result<(), String> {
        log::info!("Repairing NDISRD driver service registration");
        Self::cleanup_driver_service_for_uninstall()?;
        let sleep_for = DRIVER_READY_POLL_INTERVAL.min(timeout);
        if !sleep_for.is_zero() {
            std::thread::sleep(sleep_for);
        }

        let remaining = timeout.saturating_sub(sleep_for);
        if remaining.is_zero() {
            return Err("Timed out while repairing NDISRD service registration.".to_string());
        }

        Self::ensure_driver_service(remaining)
    }

    /// Extract Win32 error code from a `windows::core::Error`.
    ///
    /// The `windows` crate wraps Win32 errors as HRESULT values of the form
    /// `0x8007_XXXX`. This extracts the lower 16 bits (the Win32 code).
    fn win32_error_code(err: &windows::core::Error) -> u32 {
        let hr = err.code().0 as u32;
        if (hr & 0xFFFF_0000) == 0x8007_0000 {
            hr & 0xFFFF
        } else {
            hr
        }
    }

    /// Ensure the driver service exists and is started
    ///
    /// Requires administrator privileges to create or start the driver service.
    /// Handles common edge cases:
    /// - `ERROR_SERVICE_MARKED_FOR_DELETE` (1072): waits and retries
    /// - `ERROR_SERVICE_ALREADY_RUNNING` (1056): treats as success
    /// - `ERROR_SERVICE_DISABLED` (1058): re-enables and retries start
    /// - Stale binary path: detects and corrects via `ChangeServiceConfigW`
    fn ensure_driver_service(timeout: Duration) -> Result<(), String> {
        use windows::Win32::System::Services::*;
        use windows::core::PCWSTR;

        const ERROR_SERVICE_ALREADY_RUNNING: u32 = 1056;
        const ERROR_SERVICE_DISABLED: u32 = 1058;
        const ERROR_SERVICE_MARKED_FOR_DELETE: u32 = 1072;

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
            let wait_for_running = |service, wait_timeout: Duration| -> Result<(), String> {
                let effective_timeout = wait_timeout.min(DRIVER_SERVICE_START_TIMEOUT);
                if effective_timeout.is_zero() {
                    return Err(format!(
                        "Timed out waiting for {} service to reach RUNNING state.",
                        SERVICE_NAME
                    ));
                }

                let deadline = Instant::now() + effective_timeout;

                loop {
                    let mut status = SERVICE_STATUS::default();
                    QueryServiceStatus(service, &mut status).map_err(|e| {
                        format!("Failed to query {} service status: {}", SERVICE_NAME, e)
                    })?;

                    if status.dwCurrentState == SERVICE_RUNNING {
                        return Ok(());
                    }

                    if status.dwCurrentState != SERVICE_START_PENDING {
                        return Err(format!(
                            "{} service is not running (state {}).",
                            SERVICE_NAME, status.dwCurrentState.0
                        ));
                    }

                    if Instant::now() >= deadline {
                        return Err(format!(
                            "Timed out waiting for {} service to reach RUNNING state.",
                            SERVICE_NAME
                        ));
                    }

                    std::thread::sleep(Duration::from_millis(250));
                }
            };

            // Start the service, handling ERROR_SERVICE_ALREADY_RUNNING and
            // ERROR_SERVICE_DISABLED gracefully.
            let start_service_resilient = |service| -> Result<(), String> {
                match StartServiceW(service, None) {
                    Ok(()) => Ok(()),
                    Err(e) => {
                        let code = Self::win32_error_code(&e);

                        if code == ERROR_SERVICE_ALREADY_RUNNING {
                            log::info!("NDISRD service is already running");
                            return Ok(());
                        }

                        if code == ERROR_SERVICE_DISABLED {
                            log::warn!("NDISRD service is disabled; re-enabling to DEMAND_START");
                            // Re-enable the service and retry start.
                            let no_change_str = PCWSTR::null();
                            if let Err(ce) = ChangeServiceConfigW(
                                service,
                                ENUM_SERVICE_TYPE(SERVICE_NO_CHANGE),
                                SERVICE_DEMAND_START,
                                SERVICE_ERROR(SERVICE_NO_CHANGE),
                                no_change_str,
                                no_change_str,
                                None,
                                no_change_str,
                                no_change_str,
                                no_change_str,
                                no_change_str,
                            ) {
                                return Err(format!("Failed to re-enable NDISRD service: {}", ce));
                            }
                            // Retry start after re-enabling.
                            return StartServiceW(service, None).map_err(|e2| {
                                format!("Failed to start NDISRD service after re-enabling: {}", e2)
                            });
                        }

                        Err(format!("Failed to start NDISRD service: {}", e))
                    }
                }
            };

            // Open Service Control Manager
            let scm = OpenSCManagerW(PCWSTR::null(), PCWSTR::null(), SC_MANAGER_ALL_ACCESS)
                .map_err(|e| format!("Failed to open SCM: {}", e))?;

            let service_name_wide: Vec<u16> = SERVICE_NAME
                .encode_utf16()
                .chain(std::iter::once(0))
                .collect();

            // Try to open existing service, with retry for MARKED_FOR_DELETE
            let open_result = {
                let mut last_open_err = None;
                let mut opened = None;
                for attempt in 0..3u32 {
                    match OpenServiceW(scm, PCWSTR(service_name_wide.as_ptr()), SERVICE_ALL_ACCESS)
                    {
                        Ok(service) => {
                            opened = Some(service);
                            break;
                        }
                        Err(e) => {
                            let code = Self::win32_error_code(&e);
                            if code == ERROR_SERVICE_MARKED_FOR_DELETE && attempt < 2 {
                                log::warn!(
                                    "NDISRD service is marked for delete; waiting 2s before retry (attempt {}/3)",
                                    attempt + 1
                                );
                                std::thread::sleep(Duration::from_secs(2));
                                continue;
                            }
                            last_open_err = Some(e);
                            break;
                        }
                    }
                }
                match opened {
                    Some(s) => Ok(s),
                    None => Err(last_open_err),
                }
            };

            let result = match open_result {
                Ok(service) => {
                    log::info!("NDISRD service exists, checking status...");

                    let result = (|| -> Result<(), String> {
                        // Verify and fix the binary path if we know the correct driver location.
                        if let Some(expected_path) = &driver_path {
                            Self::verify_and_fix_service_binary_path(service, expected_path);
                        }

                        let mut status = SERVICE_STATUS::default();
                        QueryServiceStatus(service, &mut status)
                            .map_err(|e| format!("Failed to query NDISRD service status: {}", e))?;

                        if status.dwCurrentState == SERVICE_RUNNING {
                            log::info!("NDISRD service is running");
                            return Ok(());
                        }

                        if status.dwCurrentState != SERVICE_START_PENDING {
                            log::info!("Starting NDISRD service...");
                            start_service_resilient(service)?;
                        }

                        wait_for_running(service, timeout)?;
                        log::info!("NDISRD service is running");
                        Ok(())
                    })();
                    let _ = CloseServiceHandle(service);
                    result
                }
                Err(_) => {
                    log::info!("NDISRD service does not exist, creating...");

                    (|| -> Result<(), String> {
                        let driver_path = driver_path.as_ref().ok_or_else(|| {
                            "Driver file not found, cannot create NDISRD service".to_string()
                        })?;

                        log::info!(
                            "Creating NDISRD service with driver: {}",
                            driver_path.display()
                        );

                        let display_name_wide: Vec<u16> = SERVICE_DISPLAY_NAME
                            .encode_utf16()
                            .chain(std::iter::once(0))
                            .collect();
                        let binary_path_wide: Vec<u16> = driver_path
                            .to_string_lossy()
                            .encode_utf16()
                            .chain(std::iter::once(0))
                            .collect();

                        let create_result = CreateServiceW(
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
                        );

                        match create_result {
                            Ok(service) => {
                                let result = (|| -> Result<(), String> {
                                    log::info!("NDISRD service created, starting...");
                                    start_service_resilient(service)?;
                                    wait_for_running(service, timeout)?;
                                    Ok(())
                                })();
                                let _ = CloseServiceHandle(service);
                                result
                            }
                            Err(e) => {
                                let code = Self::win32_error_code(&e);
                                if code == ERROR_SERVICE_MARKED_FOR_DELETE {
                                    Err(format!(
                                        "Cannot create NDISRD service: previous instance is \
                                         still marked for deletion. A reboot may be required. ({})",
                                        e
                                    ))
                                } else {
                                    Err(format!("Failed to create NDISRD service: {}", e))
                                }
                            }
                        }
                    })()
                }
            };

            let _ = CloseServiceHandle(scm);
            result
        }
    }

    /// Check the service's binary path and update it if it points to the wrong location.
    ///
    /// This handles the case where a previous install left a stale service entry pointing
    /// to a deleted or moved driver binary.
    unsafe fn verify_and_fix_service_binary_path(
        service: windows::Win32::System::Services::SC_HANDLE,
        expected_path: &Path,
    ) {
        use windows::Win32::System::Services::*;
        use windows::core::PCWSTR;

        // Query the current service config to get the binary path.
        let mut bytes_needed = 0u32;
        let _ = QueryServiceConfigW(service, None, 0, &mut bytes_needed);
        if bytes_needed == 0 {
            return;
        }

        // Use Vec<u64> instead of Vec<u8> to guarantee pointer-width alignment,
        // which QUERY_SERVICE_CONFIGW requires (it contains pointer fields).
        let u64_len = (bytes_needed as usize + 7) / 8;
        let mut buf = vec![0u64; u64_len];
        let config_ptr = buf.as_mut_ptr() as *mut QUERY_SERVICE_CONFIGW;
        if QueryServiceConfigW(service, Some(config_ptr), bytes_needed, &mut bytes_needed).is_err()
        {
            log::warn!("Could not query NDISRD service config for binary path verification");
            return;
        }

        let config = &*config_ptr;
        let current_path_raw = config.lpBinaryPathName;
        if current_path_raw.is_null() {
            return;
        }

        let current_path_str = current_path_raw.to_string().unwrap_or_default();
        let expected_str = expected_path.to_string_lossy();

        if current_path_str.eq_ignore_ascii_case(&expected_str) {
            return;
        }

        if !expected_path.exists() {
            // Don't update to a path that doesn't exist.
            log::debug!(
                "NDISRD service binary path mismatch but expected path does not exist: current='{}', expected='{}'",
                current_path_str,
                expected_str
            );
            return;
        }

        log::warn!(
            "NDISRD service binary path mismatch: current='{}', expected='{}'; updating",
            current_path_str,
            expected_str
        );

        let new_path_wide: Vec<u16> = expected_str
            .encode_utf16()
            .chain(std::iter::once(0))
            .collect();
        let no_change_str = PCWSTR::null();
        if let Err(e) = ChangeServiceConfigW(
            service,
            ENUM_SERVICE_TYPE(SERVICE_NO_CHANGE),
            SERVICE_START_TYPE(SERVICE_NO_CHANGE),
            SERVICE_ERROR(SERVICE_NO_CHANGE),
            PCWSTR(new_path_wide.as_ptr()),
            no_change_str,
            None,
            no_change_str,
            no_change_str,
            no_change_str,
            no_change_str,
        ) {
            log::warn!("Failed to update NDISRD service binary path: {}", e);
        } else {
            log::info!("NDISRD service binary path updated to '{}'", expected_str);
        }
    }

    pub fn remove_driver_for_uninstall() -> Result<(), String> {
        Self::disable_winpkfilter_bindings_for_uninstall()?;

        let mut issues = Vec::new();

        if let Some(msi_path) = Self::find_driver_msi() {
            log::info!("Uninstalling WinpkFilter MSI from: {}", msi_path.display());

            match std::process::Command::new("msiexec")
                .args(["/x", &msi_path.to_string_lossy(), "/qn", "/norestart"])
                .output()
            {
                Ok(output) => {
                    let code = output.status.code().unwrap_or(-1);
                    if Self::driver_uninstall_success_exit_code(code) {
                        log::info!("WinpkFilter MSI uninstall completed with code {}", code);
                    } else {
                        let stderr = String::from_utf8_lossy(&output.stderr);
                        issues.push(format!(
                            "Driver MSI uninstall failed with code {}: {}",
                            code, stderr
                        ));
                    }
                }
                Err(e) => issues.push(format!("Failed to run driver MSI uninstall: {}", e)),
            }
        } else {
            log::warn!(
                "Bundled WinpkFilter MSI not found during uninstall; falling back to service cleanup only"
            );
        }

        if let Err(e) = Self::cleanup_driver_service_for_uninstall() {
            issues.push(e);
        }

        if issues.is_empty() {
            Ok(())
        } else {
            Err(issues.join("; "))
        }
    }

    fn driver_msi_not_found_message() -> String {
        "WinpkFilter-x64.msi not found. Please download from: https://github.com/wiresock/ndisapi/releases".to_string()
    }

    fn find_driver_msi() -> Option<PathBuf> {
        let msi_paths = [
            std::env::current_exe().ok().and_then(|path| {
                path.parent()
                    .map(|dir| dir.join("drivers").join("WinpkFilter-x64.msi"))
            }),
            std::env::current_exe().ok().and_then(|path| {
                path.parent().map(|dir| {
                    dir.join("resources")
                        .join("drivers")
                        .join("WinpkFilter-x64.msi")
                })
            }),
            std::env::current_exe().ok().and_then(|path| {
                path.parent()
                    .map(|dir| dir.join("resources").join("WinpkFilter-x64.msi"))
            }),
            Some(PathBuf::from(
                r"C:\Program Files\SwiftTunnel\drivers\WinpkFilter-x64.msi",
            )),
            Some(PathBuf::from(
                r"C:\Program Files\SwiftTunnel\resources\drivers\WinpkFilter-x64.msi",
            )),
        ];

        msi_paths.into_iter().flatten().find(|path| path.exists())
    }

    fn driver_uninstall_success_exit_code(code: i32) -> bool {
        matches!(code, 0 | 1605 | 1614 | 1641 | 3010)
    }

    fn build_winpkfilter_binding_cleanup_script() -> &'static str {
        r#"
        $ErrorActionPreference = 'Stop'
        $bindings = @(
            Get-NetAdapterBinding -ComponentID 'nt_ndisrd' -ErrorAction SilentlyContinue |
                Where-Object { $_.Enabled -eq $true } |
                Sort-Object -Property Name -Unique
        )

        if ($bindings.Count -eq 0) {
            Write-Output 'No enabled WinpkFilter bindings found during uninstall cleanup.'
            exit 0
        }

        $disabled = New-Object System.Collections.Generic.List[string]
        $failures = New-Object System.Collections.Generic.List[string]

        foreach ($binding in $bindings) {
            $adapterName = [string]$binding.Name
            if ([string]::IsNullOrWhiteSpace($adapterName)) {
                continue
            }

            try {
                Disable-NetAdapterBinding -Name $adapterName -ComponentID 'nt_ndisrd' -Confirm:$false -ErrorAction Stop | Out-Null
                Start-Sleep -Milliseconds 500
                $verification = Get-NetAdapterBinding -Name $adapterName -ComponentID 'nt_ndisrd' -ErrorAction SilentlyContinue |
                    Select-Object -First 1

                if ($verification -and $verification.Enabled) {
                    $failures.Add($adapterName + ': binding still enabled after Disable-NetAdapterBinding')
                    continue
                }

                $disabled.Add($adapterName)
            } catch {
                $failures.Add($adapterName + ': ' + $_.Exception.Message)
            }
        }

        if ($disabled.Count -gt 0) {
            Write-Output ('Disabled WinpkFilter binding on adapters: ' + ($disabled -join ', '))
        }

        if ($failures.Count -gt 0) {
            Write-Error ('Failed to disable WinpkFilter binding on adapters: ' + ($failures -join '; '))
            exit 1
        }
        "#
    }

    fn disable_winpkfilter_bindings_for_uninstall() -> Result<(), String> {
        log::info!("Disabling WinpkFilter adapter bindings before uninstall");

        let output = crate::hidden_command("powershell")
            .args([
                "-NoProfile",
                "-Command",
                Self::build_winpkfilter_binding_cleanup_script(),
            ])
            .output()
            .map_err(|e| format!("Failed to run WinpkFilter binding cleanup: {}", e))?;

        let stdout = String::from_utf8_lossy(&output.stdout).trim().to_string();
        let stderr = String::from_utf8_lossy(&output.stderr).trim().to_string();

        if output.status.success() {
            if stdout.is_empty() {
                log::info!("WinpkFilter binding cleanup completed");
            } else {
                log::info!("{}", stdout);
            }
            return Ok(());
        }

        let details = if !stderr.is_empty() {
            stderr
        } else if !stdout.is_empty() {
            stdout
        } else {
            format!(
                "PowerShell exited with code {}",
                output.status.code().unwrap_or(-1)
            )
        };

        Err(format!(
            "Failed to disable WinpkFilter bindings before uninstall: {}",
            details
        ))
    }

    /// Stop the driver service
    pub fn stop_driver_service() -> Result<(), String> {
        use windows::Win32::System::Services::*;
        use windows::core::PCWSTR;

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
        Self::ensure_driver_service(DRIVER_SERVICE_START_TIMEOUT)
    }

    /// Cleanup stale state from previous sessions
    pub fn cleanup_stale_state() {
        log::info!("Cleaning up stale split tunnel state...");
        // With ndisapi, there's no persistent state to clean up
        // The driver handles cleanup automatically
        log::info!("Stale state cleanup complete");
    }

    /// Stop and delete the NDISRD driver service from SCM for uninstall.
    ///
    /// This removes the kernel driver registration so no artifacts remain.
    /// Individual errors are ignored so the rest of uninstall can proceed.
    pub fn cleanup_driver_service_for_uninstall() -> Result<(), String> {
        use windows::Win32::System::Services::*;
        use windows::core::PCWSTR;

        log::info!("Cleaning up NDISRD driver service for uninstall");

        unsafe {
            let scm = match OpenSCManagerW(PCWSTR::null(), PCWSTR::null(), SC_MANAGER_ALL_ACCESS) {
                Ok(scm) => scm,
                Err(e) => {
                    let message = format!("Failed to open SCM for driver cleanup: {}", e);
                    log::warn!("{}", message);
                    return Err(message);
                }
            };

            let service_name_wide: Vec<u16> = SERVICE_NAME
                .encode_utf16()
                .chain(std::iter::once(0))
                .collect();

            match OpenServiceW(scm, PCWSTR(service_name_wide.as_ptr()), SERVICE_ALL_ACCESS) {
                Ok(service) => {
                    // Stop the service first (ignore error — may already be stopped)
                    let mut status = SERVICE_STATUS::default();
                    let _ = ControlService(service, SERVICE_CONTROL_STOP, &mut status);

                    // Delete the service from SCM
                    match DeleteService(service) {
                        Ok(_) => log::info!("NDISRD service deleted from SCM"),
                        Err(e) => {
                            let message = format!("Failed to delete NDISRD service: {}", e);
                            log::warn!("{}", message);
                            let _ = CloseServiceHandle(service);
                            let _ = CloseServiceHandle(scm);
                            return Err(message);
                        }
                    }

                    let _ = CloseServiceHandle(service);
                }
                Err(_) => {
                    log::debug!("NDISRD service not found (already removed or never installed)");
                }
            }

            let _ = CloseServiceHandle(scm);
        }

        log::info!("NDISRD driver service cleanup completed");
        Ok(())
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
        self.get_running_tunnel_processes()
            .into_iter()
            .map(|(_, name)| name)
            .collect()
    }

    /// Get running tunnel processes as `(pid, process_name)` pairs.
    pub fn get_running_tunnel_processes(&mut self) -> Vec<(u32, String)> {
        if let Some(ref interceptor) = self.parallel_interceptor {
            let snapshot = interceptor.get_snapshot();
            let mut processes: Vec<(u32, String)> = snapshot
                .tunnel_pids
                .iter()
                .filter_map(|pid| snapshot.pid_names.get(pid).map(|name| (*pid, name.clone())))
                .collect();
            processes.sort_by(|a, b| a.1.cmp(&b.1).then(a.0.cmp(&b.0)));
            processes
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
            config.binding_preference.clone(),
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

    /// Get diagnostic info for UI display.
    pub fn get_diagnostics(&self) -> Option<SplitTunnelDiagnostics> {
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

    pub fn register_udp_port_immediate(&self, local_port: u16) {
        if let Some(ref interceptor) = self.parallel_interceptor {
            interceptor.register_udp_port_immediate(local_port);
        } else {
            log::warn!("Cannot register UDP port: parallel interceptor not active");
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

    /// Enable or disable TCP API tunneling (proxy to ParallelInterceptor).
    pub fn set_api_tunneling_enabled(&self, enabled: bool) {
        if let Some(ref interceptor) = self.parallel_interceptor {
            interceptor.set_api_tunneling_enabled(enabled);
        }
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
        let config = SplitTunnelConfig::new(
            vec!["robloxplayerbeta.exe".to_string()],
            12345,
            Some(AdapterBindingPreference {
                guid: "{AAAAAAAA-BBBB-CCCC-DDDD-EEEEEEEEEEEE}".to_string(),
                source: super::super::parallel_interceptor::BindingPreferenceSource::Manual,
                network_signature: None,
            }),
        );
        assert!(config.tunnel_apps.contains("robloxplayerbeta.exe"));
        assert_eq!(
            config
                .binding_preference
                .as_ref()
                .map(|preference| preference.guid.as_str()),
            Some("aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee")
        );
    }

    #[test]
    fn test_driver_state() {
        let driver = SplitTunnelDriver::new();
        assert_eq!(*driver.state(), DriverState::NotAvailable);
    }

    #[test]
    fn test_binding_cleanup_script_disables_nt_ndisrd() {
        let script = SplitTunnelDriver::build_winpkfilter_binding_cleanup_script();
        assert!(script.contains("Disable-NetAdapterBinding"));
        assert!(script.contains("nt_ndisrd"));
    }
}
