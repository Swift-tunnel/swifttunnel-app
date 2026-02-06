//! macOS TUN Adapter Management (utun)
//!
//! Creates and manages a utun virtual network interface on macOS for
//! VPN tunneling. Uses tun-rs crate for the TUN device, and ifconfig
//! commands for IP configuration.
//!
//! REQUIREMENTS:
//! - Root (sudo) or admin privileges are required to create utun interfaces
//! - macOS 10.10+ for utun support

use std::net::IpAddr;
use std::sync::Arc;
use tun_rs::DeviceBuilder;
use super::{VpnError, VpnResult};

/// Adapter name prefix (macOS auto-assigns utunN)
const ADAPTER_DESCRIPTION: &str = "SwiftTunnel";

/// Default MTU for the tunnel (WireGuard overhead considered)
pub const DEFAULT_MTU: u32 = 1420;

/// Check if the current process has root privileges
///
/// Returns true if running as root (UID 0), false otherwise.
fn is_root() -> bool {
    unsafe { libc::geteuid() == 0 }
}

/// Convert CIDR prefix to subnet mask string
fn cidr_to_mask(cidr: u8) -> String {
    if cidr == 32 {
        "255.255.255.255".to_string()
    } else if cidr == 0 {
        "0.0.0.0".to_string()
    } else {
        let mask_int: u32 = !((1u32 << (32 - cidr)) - 1);
        format!(
            "{}.{}.{}.{}",
            (mask_int >> 24) & 0xff,
            (mask_int >> 16) & 0xff,
            (mask_int >> 8) & 0xff,
            mask_int & 0xff
        )
    }
}

/// macOS utun adapter wrapper
///
/// Uses tun-rs to create a utun interface, then configures IP/routes
/// via ifconfig commands. The tun device provides a file descriptor
/// for reading/writing IP packets.
pub struct UtunAdapter {
    device: Arc<tun_rs::AsyncDevice>,
    interface_name: String,
    assigned_ip: IpAddr,
    cidr: u8,
}

impl UtunAdapter {
    /// Create a new utun adapter
    ///
    /// # Arguments
    /// * `assigned_ip` - IP address to assign to the adapter (e.g., "10.0.42.15")
    /// * `cidr` - CIDR prefix length (e.g., 32)
    ///
    /// # Errors
    /// Returns an error if:
    /// - Application is not running with root privileges
    /// - utun creation fails
    /// - IP configuration fails
    pub fn create(assigned_ip: IpAddr, cidr: u8) -> VpnResult<Self> {
        log::info!("Creating utun adapter ({})", ADAPTER_DESCRIPTION);

        // Check for root privileges
        if !is_root() {
            log::error!("Root privileges required for VPN");
            return Err(VpnError::AdapterCreate(
                "Root privileges required. Please run SwiftTunnel with sudo.".to_string()
            ));
        }

        // Create TUN device using tun-rs
        let device = DeviceBuilder::new()
            .mtu(DEFAULT_MTU as u16)
            .build_async()
            .map_err(|e| {
                log::error!("Failed to create utun device: {}", e);
                VpnError::AdapterCreate(format!("Failed to create utun device: {}", e))
            })?;

        // Get the assigned interface name (e.g., "utun3")
        let interface_name = device.name().map_err(|e| {
            VpnError::AdapterCreate(format!("Failed to get interface name: {}", e))
        })?;

        log::info!("utun adapter created: {}", interface_name);

        // Configure IP address using ifconfig
        Self::configure_ip(&interface_name, assigned_ip, cidr)?;

        Ok(Self {
            device: Arc::new(device),
            interface_name,
            assigned_ip,
            cidr,
        })
    }

    /// Configure IP address on the utun interface using ifconfig
    fn configure_ip(interface_name: &str, ip: IpAddr, cidr: u8) -> VpnResult<()> {
        log::info!("Configuring IP {} on interface '{}'", ip, interface_name);

        let output = match ip {
            IpAddr::V4(ipv4) => {
                // For point-to-point utun, we set the local and destination addresses
                // ifconfig utunN inet <local_ip> <dest_ip> netmask <mask>
                let mask = cidr_to_mask(cidr);

                // For /32, use the same IP as both local and remote (point-to-point)
                let dest_ip = ipv4.to_string();

                std::process::Command::new("ifconfig")
                    .args([
                        interface_name,
                        "inet",
                        &ipv4.to_string(),
                        &dest_ip,
                        "netmask",
                        &mask,
                    ])
                    .output()
            }
            IpAddr::V6(ipv6) => {
                std::process::Command::new("ifconfig")
                    .args([
                        interface_name,
                        "inet6",
                        &format!("{}/{}", ipv6, cidr),
                    ])
                    .output()
            }
        };

        match output {
            Ok(out) if out.status.success() => {
                log::info!("IP address configured successfully on {}", interface_name);
                Ok(())
            }
            Ok(out) => {
                let stderr = String::from_utf8_lossy(&out.stderr);
                log::error!("ifconfig failed: {}", stderr);
                Err(VpnError::AdapterCreate(format!(
                    "Failed to set IP address: {}",
                    stderr
                )))
            }
            Err(e) => {
                log::error!("Failed to run ifconfig: {}", e);
                Err(VpnError::AdapterCreate(format!(
                    "Failed to run ifconfig: {}",
                    e
                )))
            }
        }
    }

    /// Set MTU on the adapter
    pub fn set_mtu(&self, mtu: u32) -> VpnResult<()> {
        let output = std::process::Command::new("ifconfig")
            .args([
                &self.interface_name,
                "mtu",
                &mtu.to_string(),
            ])
            .output();

        match output {
            Ok(out) if out.status.success() => {
                log::info!("MTU set to {} on {}", mtu, self.interface_name);
                Ok(())
            }
            Ok(out) => {
                let stderr = String::from_utf8_lossy(&out.stderr);
                log::warn!("Failed to set MTU: {}", stderr);
                Ok(()) // Non-critical failure
            }
            Err(e) => {
                log::warn!("Failed to run ifconfig for MTU: {}", e);
                Ok(()) // Non-critical failure
            }
        }
    }

    /// Set DNS servers by writing to /etc/resolver/
    ///
    /// On macOS, per-interface DNS is configured via /etc/resolver/ directory
    /// rather than netsh. We create a resolver config for the VPN domain.
    pub fn set_dns(&self, dns_servers: &[String]) -> VpnResult<()> {
        if dns_servers.is_empty() {
            return Ok(());
        }

        // Use scutil to set DNS for the VPN interface
        // This is the proper macOS way to configure DNS dynamically
        let dns_config = format!(
            "d.init\nd.add ServerAddresses * {}\nd.add InterfaceName {}\nset State:/Network/Service/SwiftTunnel/DNS\n",
            dns_servers.join(" "),
            self.interface_name,
        );

        let output = std::process::Command::new("scutil")
            .stdin(std::process::Stdio::piped())
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped())
            .spawn()
            .and_then(|mut child| {
                use std::io::Write;
                if let Some(ref mut stdin) = child.stdin {
                    stdin.write_all(dns_config.as_bytes())?;
                }
                child.wait_with_output()
            });

        match output {
            Ok(out) if out.status.success() => {
                log::info!("DNS servers set: {:?}", dns_servers);
                Ok(())
            }
            Ok(out) => {
                let stderr = String::from_utf8_lossy(&out.stderr);
                log::warn!("Failed to set DNS: {}", stderr);
                Ok(()) // Non-critical
            }
            Err(e) => {
                log::warn!("Failed to run scutil for DNS: {}", e);
                Ok(()) // Non-critical
            }
        }
    }

    /// Get the utun interface name (e.g., "utun3")
    pub fn interface_name(&self) -> &str {
        &self.interface_name
    }

    /// Get a reference to the async tun device for packet I/O
    pub fn device(&self) -> Arc<tun_rs::AsyncDevice> {
        Arc::clone(&self.device)
    }

    /// Get assigned IP address
    pub fn assigned_ip(&self) -> IpAddr {
        self.assigned_ip
    }

    /// Get CIDR prefix length
    pub fn cidr(&self) -> u8 {
        self.cidr
    }

    /// Bring the interface down (cleanup)
    pub fn shutdown(&self) {
        log::info!("Shutting down utun adapter: {}", self.interface_name);

        // Remove DNS configuration
        let _ = std::process::Command::new("scutil")
            .stdin(std::process::Stdio::piped())
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .spawn()
            .and_then(|mut child| {
                use std::io::Write;
                if let Some(ref mut stdin) = child.stdin {
                    stdin.write_all(b"remove State:/Network/Service/SwiftTunnel/DNS\n")?;
                }
                child.wait_with_output()
            });

        // Bring interface down
        let _ = std::process::Command::new("ifconfig")
            .args([&self.interface_name, "down"])
            .output();
    }
}

impl Drop for UtunAdapter {
    fn drop(&mut self) {
        log::info!("Dropping utun adapter: {}", self.interface_name);
        self.shutdown();
        // tun-rs device is automatically closed when dropped
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_cidr_to_mask() {
        assert_eq!(cidr_to_mask(32), "255.255.255.255");
        assert_eq!(cidr_to_mask(24), "255.255.255.0");
        assert_eq!(cidr_to_mask(16), "255.255.0.0");
        assert_eq!(cidr_to_mask(8), "255.0.0.0");
        assert_eq!(cidr_to_mask(0), "0.0.0.0");
    }

    #[test]
    fn test_is_root_returns_bool() {
        // Just verify it doesn't panic
        let _result = is_root();
    }
}
