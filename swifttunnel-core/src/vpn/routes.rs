//! Internet Interface IP Detection
//!
//! Detects the local IP address of the default internet interface using
//! the Windows IP Helper API (GetIpForwardTable, GetIpAddrTable).
//! Falls back to PowerShell on older systems.
//!
//! Used by the VPN connection manager to identify the physical adapter.

use super::{VpnError, VpnResult};
use crate::hidden_command;
use std::net::Ipv4Addr;

/// Get the local IP address of the internet interface (default gateway interface)
///
/// This is needed for split tunneling - the driver needs to know the real
/// internet interface IP to redirect excluded app traffic there.
///
/// Uses native Windows IP Helper API to avoid locale-dependent PowerShell parsing.
pub fn get_internet_interface_ip() -> VpnResult<Ipv4Addr> {
    log::debug!("Getting internet interface IP...");

    // Try native API first
    match get_internet_interface_ip_native() {
        Ok(ip) => {
            log::info!("Internet interface IP (native): {}", ip);
            return Ok(ip);
        }
        Err(e) => {
            log::warn!("Native API failed: {}, falling back to PowerShell", e);
        }
    }

    // Fallback to PowerShell for older Windows versions
    get_internet_interface_ip_powershell()
}

/// Native Windows API implementation using IP Helper
#[cfg(windows)]
fn get_internet_interface_ip_native() -> VpnResult<Ipv4Addr> {
    use windows::Win32::NetworkManagement::IpHelper::{
        GetIpAddrTable, GetIpForwardTable, MIB_IPADDRTABLE, MIB_IPFORWARDTABLE,
    };

    unsafe {
        // Step 1: Get the routing table to find the default route's interface index
        let mut size: u32 = 0;
        let _ = GetIpForwardTable(None, &mut size, false);

        if size == 0 {
            return Err(VpnError::Route(
                "GetIpForwardTable returned size 0".to_string(),
            ));
        }

        let mut buffer: Vec<u8> = vec![0u8; size as usize];
        let table = buffer.as_mut_ptr() as *mut MIB_IPFORWARDTABLE;

        let result = GetIpForwardTable(Some(table), &mut size, false);
        if result != 0 {
            return Err(VpnError::Route(format!(
                "GetIpForwardTable failed: {}",
                result
            )));
        }

        let num_entries = (*table).dwNumEntries as usize;
        let entries = std::slice::from_raw_parts((*table).table.as_ptr(), num_entries);

        // Find the default route (destination 0.0.0.0 with non-zero next hop)
        let default_route = entries
            .iter()
            .find(|row| row.dwForwardDest == 0 && row.dwForwardNextHop != 0);

        let interface_index = match default_route {
            Some(row) => row.dwForwardIfIndex,
            None => return Err(VpnError::Route("No default route found".to_string())),
        };

        log::debug!("Default route interface index: {}", interface_index);

        // Step 2: Get the IP address table to find the IP for this interface
        let mut addr_size: u32 = 0;
        let _ = GetIpAddrTable(None, &mut addr_size, false);

        if addr_size == 0 {
            return Err(VpnError::Route(
                "GetIpAddrTable returned size 0".to_string(),
            ));
        }

        let mut addr_buffer: Vec<u8> = vec![0u8; addr_size as usize];
        let addr_table = addr_buffer.as_mut_ptr() as *mut MIB_IPADDRTABLE;

        let result = GetIpAddrTable(Some(addr_table), &mut addr_size, false);
        if result != 0 {
            return Err(VpnError::Route(format!(
                "GetIpAddrTable failed: {}",
                result
            )));
        }

        let num_addrs = (*addr_table).dwNumEntries as usize;
        let addrs = std::slice::from_raw_parts((*addr_table).table.as_ptr(), num_addrs);

        // Find the IP address for our interface
        let ip_entry = addrs.iter().find(|entry| entry.dwIndex == interface_index);

        match ip_entry {
            Some(entry) => {
                // dwAddr is stored in network byte order (big-endian) in memory.
                // On little-endian Windows, reading it as u32 reverses the bytes.
                // We need to swap back to get the correct value for Ipv4Addr::from().
                let ip = Ipv4Addr::from(entry.dwAddr.to_be());
                Ok(ip)
            }
            None => Err(VpnError::Route(format!(
                "No IP address found for interface index {}",
                interface_index
            ))),
        }
    }
}

#[cfg(not(windows))]
fn get_internet_interface_ip_native() -> VpnResult<Ipv4Addr> {
    Err(VpnError::Route(
        "Native API not available on non-Windows".to_string(),
    ))
}

/// PowerShell fallback for older Windows versions
fn get_internet_interface_ip_powershell() -> VpnResult<Ipv4Addr> {
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

    log::info!("Internet interface IP (PowerShell): {}", ip);
    Ok(ip)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_get_internet_interface_ip() {
        let result = get_internet_interface_ip();

        #[cfg(not(windows))]
        {
            // Non-Windows: native API unavailable, PowerShell fallback also fails
            assert!(result.is_err());
        }

        #[cfg(windows)]
        {
            // Windows: should succeed on any machine with a default gateway
            assert!(result.is_ok(), "Expected Ok, got: {:?}", result);
            let ip = result.unwrap();
            // Must not be unspecified or loopback
            assert!(!ip.is_unspecified(), "IP should not be 0.0.0.0");
            assert!(!ip.is_loopback(), "IP should not be 127.x.x.x");
        }
    }
}
