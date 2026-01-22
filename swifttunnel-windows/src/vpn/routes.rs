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
//! For split tunneling, we support TWO modes:
//! - **Process-based** (ndisapi): Intercepts ALL packets, routes by process ownership
//!   - Higher latency due to packet interception overhead
//! - **Route-based** (NEW): Adds game server IP routes, kernel handles routing
//!   - ZERO overhead - same performance as no split tunnel!
//!   - Only works for games with known server IPs (Roblox, Valorant, etc.)

use super::{VpnError, VpnResult};
use crate::hidden_command;
use std::net::Ipv4Addr;

/// Roblox IP ranges for route-based split tunneling
/// These cover all Roblox game servers globally
pub const ROBLOX_IP_RANGES: &[&str] = &[
    "128.116.0.0/17",     // Main Roblox range
    "209.206.40.0/21",
    "23.173.192.0/24",
    "141.193.3.0/24",
    "204.9.184.0/24",
    "204.13.168.0/24",
    "204.13.169.0/24",
    "204.13.170.0/24",
    "204.13.171.0/24",
    "204.13.172.0/24",
    "204.13.173.0/24",
    "205.201.62.0/24",
    "103.140.28.0/23",
    "103.142.220.0/24",
    "103.142.221.0/24",
    "23.34.81.0/24",
    "23.214.169.0/24",
];

/// Valorant / Riot Games IP ranges
pub const VALORANT_IP_RANGES: &[&str] = &[
    "104.160.128.0/19",
    "151.106.240.0/20",
    "162.249.72.0/21",
    "192.64.168.0/21",
    "45.250.208.0/22",
    "103.219.128.0/22",
    "103.240.224.0/22",
    "43.229.64.0/22",
    "45.7.36.0/22",
    "185.40.64.0/22",
];

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

/// Split tunnel mode determines how traffic is routed
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SplitTunnelMode {
    /// No split tunnel - all traffic through VPN
    Disabled,
    /// Process-based: ndisapi intercepts packets, routes by process (higher latency)
    ProcessBased,
    /// Route-based: kernel routes game IPs through VPN (ZERO overhead!)
    RouteBased,
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
    /// Game routes added (for cleanup)
    game_routes: Vec<String>,
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
            game_routes: Vec::new(),
        }
    }

    /// Enable split tunnel mode (only tunnel app traffic uses VPN)
    /// In this mode, we don't add the default route - only the VPN server route
    pub fn set_split_tunnel_mode(&mut self, enabled: bool) {
        self.split_tunnel_mode = enabled;
        log::info!("Split tunnel mode: {}", if enabled { "enabled" } else { "disabled" });
    }

    /// Add game-specific routes for route-based split tunneling
    ///
    /// This is the ZERO-OVERHEAD split tunnel mode!
    /// Routes for game IPs go through Wintun, kernel handles routing.
    /// No packet interception, no process lookup, no latency overhead.
    pub fn add_game_routes(&mut self, game: &str) -> VpnResult<()> {
        let ranges = match game.to_lowercase().as_str() {
            "roblox" => ROBLOX_IP_RANGES,
            "valorant" => VALORANT_IP_RANGES,
            _ => return Err(VpnError::Route(format!("Unknown game: {}", game))),
        };

        log::info!("Adding {} route-based split tunnel routes for {}", ranges.len(), game);

        let mut added = 0;
        for cidr in ranges {
            if self.add_cidr_route(cidr).is_ok() {
                self.game_routes.push(cidr.to_string());
                added += 1;
            }
        }

        log::info!("Added {}/{} routes for {} (route-based split tunnel)", added, ranges.len(), game);
        Ok(())
    }

    /// Add a single CIDR route through the VPN interface
    fn add_cidr_route(&self, cidr: &str) -> VpnResult<()> {
        // Parse CIDR notation (e.g., "128.116.0.0/17")
        let parts: Vec<&str> = cidr.split('/').collect();
        if parts.len() != 2 {
            return Err(VpnError::Route(format!("Invalid CIDR: {}", cidr)));
        }

        let network = parts[0];
        let prefix_len: u8 = parts[1].parse()
            .map_err(|_| VpnError::Route(format!("Invalid prefix length: {}", parts[1])))?;

        // Convert prefix length to subnet mask
        let mask = if prefix_len == 0 {
            0u32
        } else {
            !((1u32 << (32 - prefix_len)) - 1)
        };
        let mask_str = format!(
            "{}.{}.{}.{}",
            (mask >> 24) & 0xFF,
            (mask >> 16) & 0xFF,
            (mask >> 8) & 0xFF,
            mask & 0xFF
        );

        // Add route through VPN interface
        let output = hidden_command("route")
            .args([
                "add",
                network,
                "mask",
                &mask_str,
                "10.0.0.1",  // VPN internal gateway
                "metric",
                "5",
                "if",
                &self.interface_index.to_string(),
            ])
            .output()
            .map_err(|e| VpnError::Route(format!("Failed to add route: {}", e)))?;

        if output.status.success() {
            log::debug!("Added route: {} -> VPN", cidr);
            Ok(())
        } else {
            let stderr = String::from_utf8_lossy(&output.stderr);
            // Route might already exist - that's OK
            if stderr.contains("already exists") || stderr.contains("object already exists") {
                log::debug!("Route already exists: {}", cidr);
                Ok(())
            } else {
                log::warn!("Failed to add route {}: {}", cidr, stderr);
                Err(VpnError::Route(format!("Failed to add route {}", cidr)))
            }
        }
    }

    /// Remove all game routes
    pub fn remove_game_routes(&mut self) {
        if self.game_routes.is_empty() {
            return;
        }

        log::info!("Removing {} game routes", self.game_routes.len());

        for cidr in &self.game_routes {
            let parts: Vec<&str> = cidr.split('/').collect();
            if parts.len() != 2 {
                continue;
            }
            let network = parts[0];

            let _ = hidden_command("route")
                .args(["delete", network])
                .output();
        }

        self.game_routes.clear();
        log::info!("Game routes removed");
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

        // Step 3: Add default route through VPN interface (skip in split tunnel mode)
        // NOTE: In split tunnel mode, we DON'T add the default route because:
        // - ndisapi intercepts packets on the physical adapter
        // - For tunnel apps, we NAT and directly encrypt with WireGuard (bypass Wintun)
        // - For bypass apps, we pass directly to physical adapter
        // - If we added a VPN route, ALL traffic would go to Wintun and bypass ndisapi!
        if self.split_tunnel_mode {
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
        // Always try to remove game routes
        self.remove_game_routes();

        if !self.routes_applied {
            log::debug!("No base routes to remove");
            return Ok(());
        }

        log::info!("Removing VPN routes...");

        // Remove default route through VPN (only if not in split tunnel mode)
        if !self.split_tunnel_mode {
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
