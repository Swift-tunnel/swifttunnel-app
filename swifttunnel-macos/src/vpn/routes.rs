//! Route Management for VPN Tunneling on macOS
//!
//! Manages macOS routing table entries to direct traffic through the VPN tunnel.
//!
//! Key routes needed:
//! 1. VPN server route through real gateway (prevents routing loop)
//!
//! Split tunneling (ONLY mode - like ExitLag):
//! - Uses process-based routing via BPF + pf (macOS equivalent of ndisapi)
//! - Intercepts ALL packets and routes by process ownership
//! - Only specified game apps use VPN, everything else bypasses
//! - NO default route is added (no full tunnel mode)
//!
//! ## macOS Routing
//!
//! Uses `route` command and `default-net` crate instead of Windows IP Helper API.
//! Default gateway detection via parsing `route -n get default` output.

use super::{VpnError, VpnResult};
use std::net::Ipv4Addr;

/// Get the local IP address of the internet-facing interface (default gateway interface)
///
/// This is needed for split tunneling - the split tunnel driver needs to know
/// the real internet interface IP to redirect excluded app traffic there.
///
/// Uses the `default-net` crate for cross-platform gateway detection.
pub fn get_internet_interface_ip() -> VpnResult<Ipv4Addr> {
    log::debug!("Getting internet interface IP...");

    // Try default-net crate first (cleanest approach)
    match get_internet_ip_default_net() {
        Ok(ip) => {
            log::info!("Internet interface IP (default-net): {}", ip);
            return Ok(ip);
        }
        Err(e) => {
            log::warn!("default-net failed: {}, falling back to ifconfig", e);
        }
    }

    // Fallback: parse route and ifconfig output
    get_internet_ip_from_route()
}

/// Get internet IP using default-net crate
fn get_internet_ip_default_net() -> VpnResult<Ipv4Addr> {
    // Use get_default_interface() which directly returns the interface with the default route
    match default_net::get_default_interface() {
        Ok(iface) => {
            for addr in &iface.ipv4 {
                let ip = addr.addr;
                if !ip.is_loopback() && !ip.is_link_local() {
                    return Ok(ip);
                }
            }
            Err(VpnError::Route("Default interface has no usable IPv4 address".to_string()))
        }
        Err(e) => {
            // Fallback: search all interfaces for one with a gateway
            let interfaces = default_net::get_interfaces();
            for iface in &interfaces {
                if iface.gateway.is_some() {
                    for addr in &iface.ipv4 {
                        let ip = addr.addr;
                        if !ip.is_loopback() && !ip.is_link_local() {
                            return Ok(ip);
                        }
                    }
                }
            }
            Err(VpnError::Route(format!("No internet interface found: {}", e)))
        }
    }
}

/// Fallback: get internet IP by parsing route output to find the interface,
/// then get the IP from ifconfig for that interface
fn get_internet_ip_from_route() -> VpnResult<Ipv4Addr> {
    // Get the interface name for the default route
    let output = std::process::Command::new("route")
        .args(["-n", "get", "default"])
        .output()
        .map_err(|e| VpnError::Route(format!("Failed to run route: {}", e)))?;

    if !output.status.success() {
        return Err(VpnError::Route("route -n get default failed".to_string()));
    }

    let route_output = String::from_utf8_lossy(&output.stdout);

    // Parse "interface: en0" from the output
    let interface = route_output
        .lines()
        .find(|line| line.trim().starts_with("interface:"))
        .and_then(|line| line.split(':').nth(1))
        .map(|s| s.trim().to_string())
        .ok_or_else(|| VpnError::Route("Could not find interface in route output".to_string()))?;

    log::debug!("Default route interface: {}", interface);

    // Use nix::ifaddrs to get the IP for this interface
    let addrs = nix::ifaddrs::getifaddrs()
        .map_err(|e| VpnError::Route(format!("Failed to get interface addresses: {}", e)))?;

    for addr in addrs {
        if addr.interface_name == interface {
            if let Some(sockaddr) = addr.address {
                if let Some(inet) = sockaddr.as_sockaddr_in() {
                    let ip_u32: u32 = inet.ip().into();
                    let ip = Ipv4Addr::from(u32::from_be(ip_u32));
                    if !ip.is_loopback() && !ip.is_link_local() {
                        log::info!("Internet interface IP (ifaddrs): {} on {}", ip, interface);
                        return Ok(ip);
                    }
                }
            }
        }
    }

    Err(VpnError::Route(format!(
        "No IPv4 address found for interface {}",
        interface
    )))
}

/// Get the current default gateway from the system
///
/// Parses `route -n get default` output on macOS.
pub fn get_default_gateway() -> VpnResult<Ipv4Addr> {
    log::debug!("Getting default gateway from system...");

    // Try default-net crate first
    match get_default_gateway_default_net() {
        Ok(gw) => {
            log::info!("Default gateway (default-net): {}", gw);
            return Ok(gw);
        }
        Err(e) => {
            log::warn!("default-net gateway lookup failed: {}, falling back to route command", e);
        }
    }

    // Fallback to parsing route command
    get_default_gateway_from_route()
}

/// Get default gateway using default-net crate
fn get_default_gateway_default_net() -> VpnResult<Ipv4Addr> {
    let gateway = default_net::get_default_gateway()
        .map_err(|e| VpnError::Route(format!("default-net gateway error: {}", e)))?;

    let ip = gateway.ip_addr;
    match ip {
        std::net::IpAddr::V4(v4) => Ok(v4),
        std::net::IpAddr::V6(_) => Err(VpnError::Route("Default gateway is IPv6, expected IPv4".to_string())),
    }
}

/// Fallback: parse `route -n get default` for gateway
fn get_default_gateway_from_route() -> VpnResult<Ipv4Addr> {
    let output = std::process::Command::new("route")
        .args(["-n", "get", "default"])
        .output()
        .map_err(|e| VpnError::Route(format!("Failed to run route: {}", e)))?;

    if !output.status.success() {
        return Err(VpnError::Route(
            "Failed to get default gateway from system".to_string(),
        ));
    }

    let route_output = String::from_utf8_lossy(&output.stdout);

    // Parse "gateway: 192.168.1.1" from the output
    let gateway_str = route_output
        .lines()
        .find(|line| line.trim().starts_with("gateway:"))
        .and_then(|line| line.split(':').nth(1))
        .map(|s| s.trim().to_string())
        .ok_or_else(|| VpnError::Route("No gateway found in route output".to_string()))?;

    gateway_str
        .parse()
        .map_err(|e| VpnError::Route(format!("Invalid gateway IP '{}': {}", gateway_str, e)))
}

/// Get the interface name for a given IP address
///
/// Searches through network interfaces to find which one has the specified IP.
pub fn get_interface_for_ip(ip: Ipv4Addr) -> VpnResult<String> {
    let addrs = nix::ifaddrs::getifaddrs()
        .map_err(|e| VpnError::Route(format!("Failed to get interface addresses: {}", e)))?;

    for addr in addrs {
        if let Some(sockaddr) = addr.address {
            if let Some(inet) = sockaddr.as_sockaddr_in() {
                let ip_u32: u32 = inet.ip().into();
                let iface_ip = Ipv4Addr::from(u32::from_be(ip_u32));
                if iface_ip == ip {
                    return Ok(addr.interface_name.clone());
                }
            }
        }
    }

    Err(VpnError::Route(format!("No interface found with IP {}", ip)))
}

/// Get the interface index for a network adapter by name
///
/// On macOS, uses `nix::ifaddrs` and `nix::libc::if_nametoindex` to find the interface.
pub fn get_interface_index(adapter_name: &str) -> VpnResult<u32> {
    let c_name = std::ffi::CString::new(adapter_name).map_err(|e| {
        VpnError::Route(format!("Invalid interface name '{}': {}", adapter_name, e))
    })?;

    let index = unsafe { libc::if_nametoindex(c_name.as_ptr()) };

    if index == 0 {
        Err(VpnError::Route(format!(
            "Interface '{}' not found",
            adapter_name
        )))
    } else {
        Ok(index)
    }
}

/// Route manager for VPN traffic routing on macOS
///
/// Only manages VPN server route - split tunneling via BPF/pf handles app routing.
pub struct RouteManager {
    /// VPN server IP (needs route through real gateway)
    vpn_server_ip: Ipv4Addr,
    /// Original default gateway before VPN
    original_gateway: Option<Ipv4Addr>,
    /// The utun interface name (e.g., "utun3")
    utun_interface: String,
    /// Whether routes have been applied
    routes_applied: bool,
}

impl RouteManager {
    /// Create a new route manager
    pub fn new(vpn_server_ip: Ipv4Addr, utun_interface: String) -> Self {
        Self {
            vpn_server_ip,
            original_gateway: None,
            utun_interface,
            routes_applied: false,
        }
    }

    /// Apply routes for VPN tunneling
    ///
    /// Split tunnel mode (only mode - like ExitLag):
    /// 1. Route VPN server IP through the original gateway (prevents loop)
    /// 2. NO default route added - BPF/pf handles per-app routing
    pub fn apply_routes(&mut self) -> VpnResult<()> {
        if self.routes_applied {
            log::warn!("Routes already applied, skipping");
            return Ok(());
        }

        log::info!("Applying VPN routes...");

        // Step 1: Get the current default gateway
        let gateway = get_default_gateway()?;
        log::info!("Original default gateway: {}", gateway);
        self.original_gateway = Some(gateway);

        // Step 2: Add route for VPN server through original gateway
        // This prevents a routing loop (VPN packets need to go through real internet)
        log::info!(
            "Adding route for VPN server {} through gateway {}",
            self.vpn_server_ip,
            gateway
        );

        let server_route = std::process::Command::new("route")
            .args([
                "-n", "add",
                "-host",
                &self.vpn_server_ip.to_string(),
                &gateway.to_string(),
            ])
            .output();

        match server_route {
            Ok(out) if out.status.success() => {
                log::info!("VPN server route added successfully");
            }
            Ok(out) => {
                let stderr = String::from_utf8_lossy(&out.stderr);
                log::warn!("VPN server route may already exist: {}", stderr);
                // Continue anyway - route might already exist
            }
            Err(e) => {
                log::warn!("Failed to add VPN server route (continuing): {}", e);
            }
        }

        // Split tunnel mode (only mode - like ExitLag):
        // - NO default route is added
        // - BPF/pf intercepts packets at the network layer
        // - For tunnel apps, we route through utun
        // - For bypass apps, we pass directly to the physical interface
        log::info!("Split tunnel mode: no default VPN route (only selected apps use VPN)");

        self.routes_applied = true;
        log::info!("VPN routes applied successfully");
        Ok(())
    }

    /// Remove VPN routes and restore original routing
    pub fn remove_routes(&mut self) -> VpnResult<()> {
        if !self.routes_applied {
            log::debug!("No routes to remove");
            return Ok(());
        }

        log::info!("Removing VPN routes...");

        // Remove VPN server specific route
        let remove_server = std::process::Command::new("route")
            .args([
                "-n", "delete",
                "-host",
                &self.vpn_server_ip.to_string(),
            ])
            .output();

        match remove_server {
            Ok(out) if out.status.success() => {
                log::info!("VPN server route removed");
            }
            Ok(out) => {
                let stderr = String::from_utf8_lossy(&out.stderr);
                log::warn!("Failed to remove server route (may not exist): {}", stderr);
            }
            Err(e) => {
                log::warn!("Failed to run route delete for server: {}", e);
            }
        }

        self.routes_applied = false;
        log::info!("VPN routes removed");
        Ok(())
    }

    /// Check if routes are currently applied
    pub fn is_applied(&self) -> bool {
        self.routes_applied
    }

    /// Get the utun interface name
    pub fn utun_interface(&self) -> &str {
        &self.utun_interface
    }
}

impl Drop for RouteManager {
    fn drop(&mut self) {
        // Best-effort cleanup on drop
        if self.routes_applied {
            log::info!("RouteManager dropping - cleaning up routes");
            let _ = self.remove_routes();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_route_manager_creation() {
        let rm = RouteManager::new("1.2.3.4".parse().unwrap(), "utun5".to_string());
        assert!(!rm.is_applied());
        assert_eq!(rm.utun_interface(), "utun5");
    }
}
