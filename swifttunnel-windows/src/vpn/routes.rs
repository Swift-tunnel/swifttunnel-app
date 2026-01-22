//! Route Management for VPN Tunneling
//!
//! Manages Windows routing table entries to direct traffic through the VPN tunnel.
//! This is CRITICAL for the VPN to actually work - without proper routes, traffic
//! won't flow through the tunnel even if it's established.
//!
//! Key routes needed:
//! 1. VPN server route through real gateway (prevents routing loop)
//! 2. Default route (0.0.0.0/0) through VPN interface (captures all traffic)
//!
//! For split tunneling, we use route-based approach:
//! - Add default route through VPN for full tunnel mode
//! - For split tunnel, could add specific game server IP ranges instead

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
pub struct RouteManager {
    /// VPN server IP (needs route through real gateway)
    vpn_server_ip: Ipv4Addr,
    /// Original default gateway before VPN
    original_gateway: Option<Ipv4Addr>,
    /// VPN interface index
    interface_index: u32,
    /// Whether routes have been applied
    routes_applied: bool,
    /// Split tunnel mode - don't add default route, only tunnel app traffic uses VPN
    split_tunnel_mode: bool,
}

impl RouteManager {
    /// Create a new route manager
    pub fn new(vpn_server_ip: Ipv4Addr, interface_index: u32) -> Self {
        Self {
            vpn_server_ip,
            original_gateway: None,
            interface_index,
            routes_applied: false,
            split_tunnel_mode: false,
        }
    }

    /// Enable split tunnel mode (only tunnel app traffic uses VPN)
    /// In this mode, we don't add the default route - only the VPN server route
    pub fn set_split_tunnel_mode(&mut self, enabled: bool) {
        self.split_tunnel_mode = enabled;
        log::info!("Split tunnel mode: {}", if enabled { "enabled" } else { "disabled" });
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
    /// This sets up the routing table to:
    /// 1. Route VPN server IP through the original gateway (prevents loop)
    /// 2. Route all other traffic (0.0.0.0/0) through VPN interface
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

        // Step 3: Add default route through VPN interface
        // NOTE: Even in split tunnel mode, we need this route because:
        // - ndisapi intercepts packets on the physical adapter
        // - For tunnel apps, we NAT and inject packets into Wintun
        // - The OS then needs to route these Wintun packets BACK through Wintun (to WireGuard)
        // - Without this route, packets injected to Wintun go back out the physical adapter!
        // - Bypass app traffic is handled by ndisapi passing directly to physical adapter
        //   (never enters OS routing), so the VPN route doesn't affect them.
        if false && self.split_tunnel_mode {
            // DISABLED: We actually need the default route even in split tunnel mode
            log::info!("Split tunnel mode: skipping default VPN route (only tunnel app traffic will use VPN)");
        } else {
            // We use 10.0.0.1 as gateway (standard VPN internal gateway) with low metric
            log::info!(
                "Adding default route through VPN interface (index: {})",
                self.interface_index
            );

            let default_route = hidden_command("route")
                .args([
                    "add",
                    "0.0.0.0",
                    "mask",
                    "0.0.0.0",
                    "10.0.0.1",  // VPN internal gateway
                    "metric",
                    "5",  // Lower metric = higher priority
                    "if",
                    &self.interface_index.to_string(),
                ])
                .output();

            match default_route {
                Ok(out) if out.status.success() => {
                    log::info!("Default route through VPN added successfully");
                }
                Ok(out) => {
                    let stderr = String::from_utf8_lossy(&out.stderr);
                    log::warn!("Default route warning: {}", stderr);
                    // Continue - might work anyway
                }
                Err(e) => {
                    return Err(VpnError::Route(format!(
                        "Failed to add default route: {}",
                        e
                    )));
                }
            }
        }

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

        // Remove default route through VPN
        // NOTE: We now add the default route even in split tunnel mode (see apply_routes)
        if true || !self.split_tunnel_mode {
            let remove_default = hidden_command("route")
                .args([
                    "delete",
                    "0.0.0.0",
                    "mask",
                    "0.0.0.0",
                    "10.0.0.1",
                ])
                .output();

            match remove_default {
                Ok(out) if out.status.success() => {
                    log::info!("Default VPN route removed");
                }
                Ok(out) => {
                    let stderr = String::from_utf8_lossy(&out.stderr);
                    log::warn!("Failed to remove default route (may not exist): {}", stderr);
                }
                Err(e) => {
                    log::warn!("Failed to run route delete: {}", e);
                }
            }
        } else {
            log::info!("Split tunnel mode: no default route to remove");
        }

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
