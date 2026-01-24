//! Route Management for VPN Tunneling
//!
//! Manages Windows routing table entries to direct traffic through the VPN tunnel.
//!
//! Key routes needed:
//! 1. VPN server route through real gateway (prevents routing loop)
//!
//! Split tunneling (ONLY mode - like ExitLag):
//! - Uses process-based routing via ndisapi
//! - Intercepts ALL packets and routes by process ownership
//! - Only specified game apps use VPN, everything else bypasses
//! - NO default route is added (no full tunnel mode)

use super::{VpnError, VpnResult};
use crate::hidden_command;
use std::net::Ipv4Addr;

/// Get the local IP address of the internet interface (default gateway interface)
///
/// This is needed for split tunneling - the driver needs to know the real
/// internet interface IP to redirect excluded app traffic there.
pub fn get_internet_interface_ip() -> VpnResult<Ipv4Addr> {
    log::debug!("Getting internet interface IP...");

    // Get the IP address of the interface that has the default route
    // This uses PowerShell to find the local IP on the interface with the default gateway
    let output = hidden_command("powershell")
        .args([
            "-NoProfile",
            "-Command",
            r#"
            $route = Get-NetRoute -DestinationPrefix 0.0.0.0/0 | Where-Object { $_.NextHop -ne '0.0.0.0' } | Select-Object -First 1
            if ($route) {
                $addr = Get-NetIPAddress -InterfaceIndex $route.InterfaceIndex -AddressFamily IPv4 | Select-Object -First 1
                if ($addr) { $addr.IPAddress }
            }
            "#,
        ])
        .output()
        .map_err(|e| VpnError::Route(format!("Failed to run PowerShell: {}", e)))?;

    if !output.status.success() {
        return Err(VpnError::Route(
            "Failed to get internet interface IP".to_string(),
        ));
    }

    let ip_str = String::from_utf8_lossy(&output.stdout).trim().to_string();

    if ip_str.is_empty() {
        return Err(VpnError::Route(
            "No internet interface IP found".to_string(),
        ));
    }

    let ip = ip_str
        .parse()
        .map_err(|e| VpnError::Route(format!("Invalid internet IP '{}': {}", ip_str, e)))?;

    log::info!("Internet interface IP: {}", ip);
    Ok(ip)
}


/// Route manager for VPN traffic routing
///
/// Only manages VPN server route - split tunneling via ndisapi handles app routing.
pub struct RouteManager {
    /// VPN server IP (needs route through real gateway)
    vpn_server_ip: Ipv4Addr,
    /// Original default gateway before VPN
    original_gateway: Option<Ipv4Addr>,
    /// VPN interface index
    interface_index: u32,
    /// Whether routes have been applied
    routes_applied: bool,
}

impl RouteManager {
    /// Create a new route manager
    pub fn new(vpn_server_ip: Ipv4Addr, interface_index: u32) -> Self {
        Self {
            vpn_server_ip,
            original_gateway: None,
            interface_index,
            routes_applied: false,
        }
    }

    /// Get the current default gateway from the system
    fn get_default_gateway() -> VpnResult<Ipv4Addr> {
        log::debug!("Getting default gateway from system...");

        // Use PowerShell to get the default gateway
        let output = hidden_command("powershell")
            .args([
                "-NoProfile",
                "-Command",
                "(Get-NetRoute -DestinationPrefix 0.0.0.0/0 | Where-Object { $_.NextHop -ne '0.0.0.0' } | Select-Object -First 1).NextHop",
            ])
            .output()
            .map_err(|e| VpnError::Route(format!("Failed to run PowerShell: {}", e)))?;

        if !output.status.success() {
            return Err(VpnError::Route(
                "Failed to get default gateway from system".to_string(),
            ));
        }

        let gateway_str = String::from_utf8_lossy(&output.stdout).trim().to_string();

        if gateway_str.is_empty() {
            return Err(VpnError::Route(
                "No default gateway found on system".to_string(),
            ));
        }

        gateway_str
            .parse()
            .map_err(|e| VpnError::Route(format!("Invalid gateway IP '{}': {}", gateway_str, e)))
    }

    /// Apply routes for VPN tunneling
    ///
    /// Split tunnel mode (only mode - like ExitLag):
    /// 1. Route VPN server IP through the original gateway (prevents loop)
    /// 2. NO default route added - ndisapi handles per-app routing
    pub fn apply_routes(&mut self) -> VpnResult<()> {
        if self.routes_applied {
            log::warn!("Routes already applied, skipping");
            return Ok(());
        }

        log::info!("Applying VPN routes...");

        // Step 1: Get the current default gateway
        let gateway = Self::get_default_gateway()?;
        log::info!("Original default gateway: {}", gateway);
        self.original_gateway = Some(gateway);

        // Step 2: Add route for VPN server through original gateway
        // This prevents a routing loop (VPN packets need to go through real internet)
        log::info!(
            "Adding route for VPN server {} through gateway {}",
            self.vpn_server_ip,
            gateway
        );

        let server_route = hidden_command("route")
            .args([
                "add",
                &self.vpn_server_ip.to_string(),
                "mask",
                "255.255.255.255",
                &gateway.to_string(),
                "metric",
                "1",
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
        // - ndisapi intercepts packets on the physical adapter
        // - For tunnel apps, we NAT and encrypt with WireGuard
        // - For bypass apps, we pass directly to physical adapter
        log::info!("Split tunnel mode: no default VPN route (only selected apps use VPN)");

        self.routes_applied = true;
        log::info!("VPN routes applied successfully");
        Ok(())
    }

    /// Remove VPN routes and restore original routing
    pub fn remove_routes(&mut self) -> VpnResult<()> {
        if !self.routes_applied {
            log::debug!("No base routes to remove");
            return Ok(());
        }

        log::info!("Removing VPN routes...");

        // Split tunnel mode: no default route was added, only remove server route

        // Remove VPN server specific route
        let remove_server = hidden_command("route")
            .args([
                "delete",
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

/// Get the interface index for a network adapter by name
pub fn get_interface_index(adapter_name: &str) -> VpnResult<u32> {
    let output = hidden_command("powershell")
        .args([
            "-NoProfile",
            "-Command",
            &format!(
                "(Get-NetAdapter -Name '{}' -ErrorAction SilentlyContinue).ifIndex",
                adapter_name
            ),
        ])
        .output()
        .map_err(|e| VpnError::Route(format!("Failed to get interface index: {}", e)))?;

    if !output.status.success() {
        return Err(VpnError::Route(format!(
            "Failed to get interface index for '{}'",
            adapter_name
        )));
    }

    let index_str = String::from_utf8_lossy(&output.stdout).trim().to_string();

    if index_str.is_empty() {
        return Err(VpnError::Route(format!(
            "Adapter '{}' not found",
            adapter_name
        )));
    }

    index_str
        .parse()
        .map_err(|e| VpnError::Route(format!("Invalid interface index '{}': {}", index_str, e)))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_route_manager_creation() {
        let rm = RouteManager::new("1.2.3.4".parse().unwrap(), 1);
        assert!(!rm.is_applied());
    }
}
