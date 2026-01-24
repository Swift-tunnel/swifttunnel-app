//! Split Tunnel Driver (Stub)
//!
//! This is a stub implementation. Split tunnel functionality is not yet
//! implemented for the native DLL.

use std::collections::HashSet;
use std::path::PathBuf;
use crate::error::VpnError;

// ═══════════════════════════════════════════════════════════════════════════════
//  SPLIT TUNNEL CONFIGURATION
// ═══════════════════════════════════════════════════════════════════════════════

/// Split tunnel configuration
#[derive(Debug, Clone)]
pub struct SplitTunnelConfig {
    /// Apps that SHOULD use VPN - stored lowercase
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

    /// Legacy compatibility - convert to include_apps format
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
//  SPLIT TUNNEL DRIVER (STUB)
// ═══════════════════════════════════════════════════════════════════════════════

/// Split tunnel driver (stub - not implemented)
pub struct SplitTunnelDriver {
    /// Current configuration
    pub config: Option<SplitTunnelConfig>,
    /// Driver state
    state: DriverState,
}

unsafe impl Send for SplitTunnelDriver {}
unsafe impl Sync for SplitTunnelDriver {}

impl SplitTunnelDriver {
    pub fn new() -> Self {
        Self {
            config: None,
            state: DriverState::NotAvailable,
        }
    }

    /// Split tunnel is not available in this build
    pub fn is_available() -> bool {
        false
    }

    /// Cleanup stale state (no-op)
    pub fn cleanup_stale_state() {}

    /// Open driver connection (stub)
    pub fn open(&mut self) -> Result<(), VpnError> {
        log::warn!("Split tunnel not implemented in native DLL");
        Err(VpnError::SplitTunnel("Split tunnel not implemented".to_string()))
    }

    /// Configure split tunnel (stub)
    pub fn configure(&mut self, config: SplitTunnelConfig) -> Result<(), VpnError> {
        log::warn!("Split tunnel not implemented in native DLL");
        self.config = Some(config);
        Err(VpnError::SplitTunnel("Split tunnel not implemented".to_string()))
    }

    /// Get names of currently running tunnel apps (stub)
    pub fn get_running_tunnel_apps(&mut self) -> Vec<String> {
        Vec::new()
    }

    /// Refresh process detection (stub)
    pub fn refresh_processes(&mut self) -> Result<Vec<String>, VpnError> {
        Ok(Vec::new())
    }

    /// Clear configuration (stub)
    pub fn clear(&mut self) -> Result<(), VpnError> {
        self.config = None;
        self.state = DriverState::NotConfigured;
        Ok(())
    }

    /// Close the split tunnel driver (stub)
    pub fn close(&mut self) -> Result<(), VpnError> {
        self.clear()
    }

    /// Get driver state
    pub fn state(&self) -> &DriverState {
        &self.state
    }

    /// Get driver state for legacy compatibility
    pub fn get_driver_state(&self) -> Result<u64, VpnError> {
        Ok(0) // NotAvailable
    }
}

impl Default for SplitTunnelDriver {
    fn default() -> Self {
        Self::new()
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

/// Default apps to tunnel (Roblox processes)
pub const DEFAULT_TUNNEL_APPS: &[&str] = &[
    "robloxplayerbeta.exe",
    "robloxplayerlauncher.exe",
    "robloxstudiobeta.exe",
    "robloxstudiolauncherbeta.exe",
    "robloxstudiolauncher.exe",
];

/// Get default apps to tunnel (Roblox processes)
pub fn get_default_tunnel_apps() -> Vec<String> {
    DEFAULT_TUNNEL_APPS.iter().map(|s| s.to_string()).collect()
}

/// Find Roblox installation path
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
    fn test_driver_not_available() {
        assert!(!SplitTunnelDriver::is_available());
    }

    #[test]
    fn test_config_lowercase() {
        let config = SplitTunnelConfig::new(
            vec!["RobloxPlayerBeta.exe".to_string()],
            "10.0.0.1".to_string(),
            0,
        );

        assert!(config.tunnel_apps.contains("robloxplayerbeta.exe"));
        assert!(!config.tunnel_apps.contains("RobloxPlayerBeta.exe"));
    }
}
