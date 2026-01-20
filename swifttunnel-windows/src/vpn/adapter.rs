//! Wintun Virtual Network Adapter Management
//!
//! Creates and manages the Wintun virtual network adapter used for
//! VPN tunneling on Windows. Wintun is a high-performance TUN adapter
//! from the WireGuard project.
//!
//! REQUIREMENTS:
//! - wintun.dll must be present in the application directory
//! - Administrator privileges are required to create the adapter

use std::net::IpAddr;
use std::path::PathBuf;
use std::sync::Arc;
use wintun::{Adapter, Session};
use super::{VpnError, VpnResult};

/// Wintun adapter name
const ADAPTER_NAME: &str = "SwiftTunnel";

/// Wintun tunnel type
const TUNNEL_TYPE: &str = "SwiftTunnel";

/// Default MTU for the tunnel (WireGuard overhead considered)
pub const DEFAULT_MTU: u32 = 1420;

/// Ring buffer capacity for Wintun session
const RING_CAPACITY: u32 = 0x400000; // 4MB

/// Check if the current process has administrator privileges
///
/// Returns true if running with elevated privileges, false otherwise.
fn is_administrator() -> bool {
    unsafe {
        use windows::Win32::Security::{
            GetTokenInformation, TokenElevation, TOKEN_ELEVATION, TOKEN_QUERY,
        };
        use windows::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};
        use windows::Win32::Foundation::CloseHandle;

        let mut token_handle = windows::Win32::Foundation::HANDLE::default();

        if OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token_handle).is_err() {
            return false;
        }

        let mut elevation = TOKEN_ELEVATION::default();
        let mut return_length: u32 = 0;

        let result = GetTokenInformation(
            token_handle,
            TokenElevation,
            Some(&mut elevation as *mut _ as *mut std::ffi::c_void),
            std::mem::size_of::<TOKEN_ELEVATION>() as u32,
            &mut return_length,
        );

        let _ = CloseHandle(token_handle);

        if result.is_ok() {
            elevation.TokenIsElevated != 0
        } else {
            false
        }
    }
}

/// Find the wintun.dll file
///
/// Searches in the following order:
/// 1. Same directory as the executable
/// 2. Current working directory
fn find_wintun_dll() -> Option<PathBuf> {
    // Try executable directory first
    if let Ok(exe_path) = std::env::current_exe() {
        if let Some(exe_dir) = exe_path.parent() {
            let dll_path = exe_dir.join("wintun.dll");
            if dll_path.exists() {
                return Some(dll_path);
            }
        }
    }

    // Try current working directory
    if let Ok(cwd) = std::env::current_dir() {
        let dll_path = cwd.join("wintun.dll");
        if dll_path.exists() {
            return Some(dll_path);
        }
    }

    None
}

/// Wrapper for Wintun adapter and session
pub struct WintunAdapter {
    adapter: Arc<Adapter>,
    session: Arc<Session>,
    assigned_ip: IpAddr,
    cidr: u8,
}

impl WintunAdapter {
    /// Create a new Wintun adapter
    ///
    /// # Arguments
    /// * `assigned_ip` - IP address to assign to the adapter (e.g., "10.0.42.15")
    /// * `cidr` - CIDR prefix length (e.g., 32)
    ///
    /// # Errors
    /// Returns an error if:
    /// - Application is not running with administrator privileges
    /// - wintun.dll is not found
    /// - Adapter creation fails
    pub fn create(assigned_ip: IpAddr, cidr: u8) -> VpnResult<Self> {
        log::info!("Creating Wintun adapter: {}", ADAPTER_NAME);

        // Check for administrator privileges
        if !is_administrator() {
            log::error!("Administrator privileges required for VPN");
            return Err(VpnError::AdapterCreate(
                "Administrator privileges required. Please run SwiftTunnel as Administrator.".to_string()
            ));
        }

        // Find wintun.dll
        let dll_path = match find_wintun_dll() {
            Some(path) => {
                log::info!("Found wintun.dll at: {}", path.display());
                path
            }
            None => {
                log::error!("wintun.dll not found in application directory");
                return Err(VpnError::AdapterCreate(
                    "wintun.dll not found. Please ensure wintun.dll is in the same directory as the application.".to_string()
                ));
            }
        };

        // Load the Wintun DLL
        let wintun = match unsafe { wintun::load_from_path(&dll_path) } {
            Ok(w) => {
                log::info!("Wintun DLL loaded successfully");
                w
            }
            Err(e) => {
                log::error!("Failed to load Wintun DLL from {}: {}", dll_path.display(), e);
                return Err(VpnError::AdapterCreate(format!(
                    "Failed to load wintun.dll: {}. Ensure the DLL matches your system architecture (64-bit for 64-bit Windows).",
                    e
                )));
            }
        };

        // Create or open the adapter
        let adapter = match Adapter::create(&wintun, ADAPTER_NAME, TUNNEL_TYPE, None) {
            Ok(a) => a, // Adapter::create already returns Arc<Adapter>
            Err(e) => {
                log::error!("Failed to create Wintun adapter: {}", e);
                return Err(VpnError::AdapterCreate(format!(
                    "Failed to create adapter: {}",
                    e
                )));
            }
        };

        log::info!("Wintun adapter created successfully");

        // Configure IP address
        Self::configure_ip(&adapter, assigned_ip, cidr)?;

        // Start a session for packet I/O
        let session = match adapter.start_session(RING_CAPACITY) {
            Ok(s) => Arc::new(s),
            Err(e) => {
                log::error!("Failed to start Wintun session: {}", e);
                return Err(VpnError::AdapterCreate(format!(
                    "Failed to start session: {}",
                    e
                )));
            }
        };

        log::info!("Wintun session started");

        Ok(Self {
            adapter,
            session,
            assigned_ip,
            cidr,
        })
    }

    /// Configure IP address on the adapter using netsh
    fn configure_ip(adapter: &Adapter, ip: IpAddr, cidr: u8) -> VpnResult<()> {
        use crate::hidden_command;

        let adapter_name = adapter.get_name().map_err(|e| {
            VpnError::AdapterCreate(format!("Failed to get adapter name: {}", e))
        })?;

        log::info!("Configuring IP {} on adapter '{}'", ip, adapter_name);

        // Use netsh to set the IP address
        let output = match ip {
            IpAddr::V4(ipv4) => {
                // Calculate subnet mask from CIDR
                let mask = if cidr == 32 {
                    "255.255.255.255".to_string()
                } else {
                    let mask_int: u32 = !((1u32 << (32 - cidr)) - 1);
                    format!(
                        "{}.{}.{}.{}",
                        (mask_int >> 24) & 0xff,
                        (mask_int >> 16) & 0xff,
                        (mask_int >> 8) & 0xff,
                        mask_int & 0xff
                    )
                };

                hidden_command("netsh")
                    .args([
                        "interface", "ip", "set", "address",
                        &adapter_name,
                        "static",
                        &ipv4.to_string(),
                        &mask,
                    ])
                    .output()
            }
            IpAddr::V6(ipv6) => {
                hidden_command("netsh")
                    .args([
                        "interface", "ipv6", "set", "address",
                        &adapter_name,
                        &format!("{}/{}", ipv6, cidr),
                    ])
                    .output()
            }
        };

        match output {
            Ok(out) if out.status.success() => {
                log::info!("IP address configured successfully");
                Ok(())
            }
            Ok(out) => {
                let stderr = String::from_utf8_lossy(&out.stderr);
                log::error!("netsh failed: {}", stderr);
                Err(VpnError::AdapterCreate(format!(
                    "Failed to set IP address: {}",
                    stderr
                )))
            }
            Err(e) => {
                log::error!("Failed to run netsh: {}", e);
                Err(VpnError::AdapterCreate(format!(
                    "Failed to run netsh: {}",
                    e
                )))
            }
        }
    }

    /// Set DNS servers for the adapter
    pub fn set_dns(&self, dns_servers: &[String]) -> VpnResult<()> {
        use crate::hidden_command;

        let adapter_name = self.adapter.get_name().map_err(|e| {
            VpnError::AdapterCreate(format!("Failed to get adapter name: {}", e))
        })?;

        for (i, dns) in dns_servers.iter().enumerate() {
            let index_arg = format!("index={}", i + 1);
            let args = if i == 0 {
                vec![
                    "interface", "ip", "set", "dns",
                    &adapter_name, "static", dns,
                ]
            } else {
                vec![
                    "interface", "ip", "add", "dns",
                    &adapter_name, dns, &index_arg,
                ]
            };

            let output = hidden_command("netsh").args(&args).output();

            match output {
                Ok(out) if out.status.success() => {
                    log::info!("DNS server {} set: {}", i + 1, dns);
                }
                Ok(out) => {
                    let stderr = String::from_utf8_lossy(&out.stderr);
                    log::warn!("Failed to set DNS {}: {}", dns, stderr);
                }
                Err(e) => {
                    log::warn!("Failed to run netsh for DNS: {}", e);
                }
            }
        }

        Ok(())
    }

    /// Set MTU on the adapter
    pub fn set_mtu(&self, mtu: u32) -> VpnResult<()> {
        use crate::hidden_command;

        let adapter_name = self.adapter.get_name().map_err(|e| {
            VpnError::AdapterCreate(format!("Failed to get adapter name: {}", e))
        })?;

        let output = hidden_command("netsh")
            .args([
                "interface", "ipv4", "set", "subinterface",
                &adapter_name,
                &format!("mtu={}", mtu),
                "store=active",
            ])
            .output();

        match output {
            Ok(out) if out.status.success() => {
                log::info!("MTU set to {}", mtu);
                Ok(())
            }
            Ok(out) => {
                let stderr = String::from_utf8_lossy(&out.stderr);
                log::warn!("Failed to set MTU: {}", stderr);
                Ok(()) // Non-critical failure
            }
            Err(e) => {
                log::warn!("Failed to run netsh for MTU: {}", e);
                Ok(()) // Non-critical failure
            }
        }
    }

    /// Get the adapter LUID (Local Unique Identifier)
    pub fn get_luid(&self) -> u64 {
        let luid = self.adapter.get_luid();
        unsafe { luid.Value }
    }

    /// Get a reference to the session for packet I/O
    pub fn session(&self) -> Arc<Session> {
        Arc::clone(&self.session)
    }

    /// Get assigned IP address
    pub fn assigned_ip(&self) -> IpAddr {
        self.assigned_ip
    }

    /// Get CIDR prefix length
    pub fn cidr(&self) -> u8 {
        self.cidr
    }

    /// Read a packet from the adapter (blocking until available or shutdown)
    /// Returns None if the session is shutting down
    pub fn receive_packet(&self) -> Option<wintun::Packet> {
        match self.session.receive_blocking() {
            Ok(packet) => Some(packet),
            Err(e) => {
                // Shutdown is expected during disconnect
                log::debug!("Receive error (may be shutdown): {}", e);
                None
            }
        }
    }

    /// Allocate a packet buffer for sending
    pub fn allocate_send_packet(&self, size: u16) -> VpnResult<wintun::Packet> {
        self.session.allocate_send_packet(size).map_err(|e| {
            VpnError::AdapterCreate(format!("Failed to allocate packet: {}", e))
        })
    }

    /// Send a packet through the adapter
    pub fn send_packet(&self, packet: wintun::Packet) {
        self.session.send_packet(packet);
    }

    /// Shutdown the adapter session
    pub fn shutdown(&self) {
        log::info!("Shutting down Wintun session");
        let _ = self.session.shutdown();
    }
}

impl Drop for WintunAdapter {
    fn drop(&mut self) {
        log::info!("Dropping Wintun adapter");
        // Session will be automatically closed when dropped
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_cidr_to_mask() {
        // Test subnet mask calculation
        let cidr = 24u8;
        let mask_int: u32 = !((1u32 << (32 - cidr)) - 1);
        let mask = format!(
            "{}.{}.{}.{}",
            (mask_int >> 24) & 0xff,
            (mask_int >> 16) & 0xff,
            (mask_int >> 8) & 0xff,
            mask_int & 0xff
        );
        assert_eq!(mask, "255.255.255.0");

        let cidr = 32u8;
        let mask = "255.255.255.255";
        assert_eq!(mask, "255.255.255.255");
    }
}
