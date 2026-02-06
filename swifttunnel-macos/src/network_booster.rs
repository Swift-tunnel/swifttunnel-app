use crate::structs::*;
use crate::utils::hidden_command;
use log::{info, warn};

pub struct NetworkBooster {
    original_dns: Option<(String, String)>,
    original_mtu: Option<u32>,
    active_interface: Option<String>,
}

impl NetworkBooster {
    pub fn new() -> Self {
        Self {
            original_dns: None,
            original_mtu: None,
            active_interface: None,
        }
    }

    /// Apply network optimizations
    pub fn apply_optimizations(&mut self, config: &NetworkConfig) -> Result<()> {
        info!("Applying network optimizations");

        if config.optimize_dns {
            self.optimize_dns(config)?;
        }

        if config.optimize_mtu {
            self.optimize_mtu()?;
        }

        // Note: On macOS, we don't have registry-based Nagle disable or network throttling
        // TCP_NODELAY is set per-socket in the VPN code, not system-wide
        if config.disable_nagle {
            info!("TCP_NODELAY: applied per-socket in VPN tunnel (no system-wide toggle on macOS)");
        }

        if config.disable_network_throttling {
            info!("Network throttling: macOS does not have a system-wide throttle setting");
        }

        // No registry-based QoS on macOS; DSCP is set per-socket
        if config.gaming_qos {
            info!("Gaming QoS: DSCP marking applied per-socket on macOS (no system-wide policy needed)");
        }

        Ok(())
    }

    /// Optimize DNS settings
    fn optimize_dns(&mut self, config: &NetworkConfig) -> Result<()> {
        info!("Optimizing DNS settings");

        let interface_name = self.get_active_network_interface()?;
        self.active_interface = Some(interface_name.clone());

        // Backup current DNS
        self.backup_dns_settings(&interface_name)?;

        // Set custom DNS
        if let (Some(primary), Some(secondary)) = (&config.custom_dns_primary, &config.custom_dns_secondary) {
            self.set_dns(&interface_name, primary, secondary)?;
        }

        Ok(())
    }

    /// Get the active network interface (e.g., "Wi-Fi", "Ethernet")
    ///
    /// Uses `route get default` to find the default gateway interface,
    /// then maps the BSD interface name (en0) to the networksetup service name.
    fn get_active_network_interface(&self) -> Result<String> {
        // Get the default route interface
        let output = hidden_command("route")
            .args(["-n", "get", "default"])
            .output()?;

        let output_str = String::from_utf8_lossy(&output.stdout);

        // Parse "interface: en0" from output
        let bsd_name = output_str.lines()
            .find(|line| line.trim().starts_with("interface:"))
            .and_then(|line| line.split(':').nth(1))
            .map(|s| s.trim().to_string())
            .ok_or_else(|| anyhow::anyhow!("Could not determine default network interface"))?;

        // Map BSD name to networksetup service name
        let service_name = self.bsd_to_service_name(&bsd_name)?;

        info!("Active network interface: {} ({})", service_name, bsd_name);
        Ok(service_name)
    }

    /// Map a BSD interface name (en0, en1) to a networksetup service name (Wi-Fi, Ethernet)
    fn bsd_to_service_name(&self, bsd_name: &str) -> Result<String> {
        let output = hidden_command("networksetup")
            .args(["-listallhardwareports"])
            .output()?;

        let output_str = String::from_utf8_lossy(&output.stdout);

        // Parse output format:
        // Hardware Port: Wi-Fi
        // Device: en0
        let mut current_service: Option<String> = None;

        for line in output_str.lines() {
            let line = line.trim();
            if let Some(name) = line.strip_prefix("Hardware Port: ") {
                current_service = Some(name.to_string());
            } else if let Some(device) = line.strip_prefix("Device: ") {
                if device.trim() == bsd_name {
                    if let Some(service) = current_service {
                        return Ok(service);
                    }
                }
                current_service = None;
            }
        }

        // Fallback: try common names
        if bsd_name == "en0" {
            Ok("Wi-Fi".to_string())
        } else {
            Err(anyhow::anyhow!("Could not find service name for interface {}", bsd_name))
        }
    }

    /// Backup current DNS settings
    fn backup_dns_settings(&mut self, interface: &str) -> Result<()> {
        let output = hidden_command("networksetup")
            .args(["-getdnsservers", interface])
            .output()?;

        let dns_output = String::from_utf8_lossy(&output.stdout);
        let dns_output = dns_output.trim();

        // If DNS is set to DHCP, output will say "There aren't any DNS Servers set..."
        if !dns_output.contains("aren't any") && !dns_output.is_empty() {
            let servers: Vec<&str> = dns_output.lines().collect();
            if servers.len() >= 2 {
                self.original_dns = Some((servers[0].to_string(), servers[1].to_string()));
            } else if servers.len() == 1 {
                self.original_dns = Some((servers[0].to_string(), String::new()));
            }
        }
        // If no DNS is set (DHCP), original_dns stays None, and we'll restore to "empty" (DHCP)

        Ok(())
    }

    /// Set DNS servers using networksetup
    fn set_dns(&self, interface: &str, primary: &str, secondary: &str) -> Result<()> {
        info!("Setting DNS to {} and {} on {}", primary, secondary, interface);

        let output = hidden_command("networksetup")
            .args(["-setdnsservers", interface, primary, secondary])
            .output()?;

        if output.status.success() {
            info!("DNS updated successfully");
        } else {
            let stderr = String::from_utf8_lossy(&output.stderr);
            warn!("Failed to update DNS (may require admin): {}", stderr);
        }

        Ok(())
    }

    /// Flush DNS cache on macOS
    pub fn flush_dns_cache(&self) -> Result<()> {
        info!("Flushing DNS cache");

        let output = hidden_command("dscacheutil")
            .arg("-flushcache")
            .output()?;

        // Also send HUP to mDNSResponder
        let _ = hidden_command("killall")
            .args(["-HUP", "mDNSResponder"])
            .output();

        if output.status.success() {
            info!("DNS cache flushed successfully");
            Ok(())
        } else {
            Err(anyhow::anyhow!("Failed to flush DNS cache"))
        }
    }

    /// Test network latency to Roblox servers
    pub fn test_latency(&self) -> Result<u32> {
        info!("Testing latency to Roblox servers");

        let output = hidden_command("ping")
            .args(["-c", "4", "www.roblox.com"])
            .output()?;

        let output_str = String::from_utf8_lossy(&output.stdout);

        // Parse macOS ping output: "round-trip min/avg/max/stddev = 1.234/5.678/9.012/1.234 ms"
        for line in output_str.lines() {
            if line.contains("avg") || line.contains("round-trip") {
                if let Some(stats_part) = line.split('=').nth(1) {
                    let parts: Vec<&str> = stats_part.trim().split('/').collect();
                    if parts.len() >= 2 {
                        // parts[1] is the average
                        if let Ok(avg) = parts[1].trim().parse::<f64>() {
                            return Ok(avg.round() as u32);
                        }
                    }
                }
            }
        }

        Ok(0)
    }

    /// Optimize MTU for the active network interface
    fn optimize_mtu(&mut self) -> Result<()> {
        info!("Optimizing MTU for active network interface");

        // Get the BSD interface name for ifconfig
        let output = hidden_command("route")
            .args(["-n", "get", "default"])
            .output()?;

        let output_str = String::from_utf8_lossy(&output.stdout);
        let bsd_name = output_str.lines()
            .find(|line| line.trim().starts_with("interface:"))
            .and_then(|line| line.split(':').nth(1))
            .map(|s| s.trim().to_string())
            .ok_or_else(|| anyhow::anyhow!("Could not determine default interface"))?;

        // Backup current MTU
        if let Ok(current_mtu) = self.get_current_mtu(&bsd_name) {
            self.original_mtu = Some(current_mtu);
            info!("Current MTU: {}", current_mtu);
        }

        // Find optimal MTU
        match self.find_optimal_mtu() {
            Ok(optimal_mtu) => {
                info!("Found optimal MTU: {}", optimal_mtu);
                if let Err(e) = self.apply_mtu(&bsd_name, optimal_mtu) {
                    warn!("Failed to apply MTU: {}", e);
                } else {
                    info!("MTU optimized to {} for interface '{}'", optimal_mtu, bsd_name);
                }
            }
            Err(e) => {
                warn!("Failed to find optimal MTU: {}", e);
            }
        }

        Ok(())
    }

    /// Get the current MTU for a BSD interface
    fn get_current_mtu(&self, bsd_name: &str) -> Result<u32> {
        let output = hidden_command("ifconfig")
            .arg(bsd_name)
            .output()?;

        let output_str = String::from_utf8_lossy(&output.stdout);

        // Parse "mtu 1500" from ifconfig output
        for part in output_str.split_whitespace() {
            if let Ok(mtu) = part.parse::<u32>() {
                // The mtu value follows the "mtu" keyword
                if output_str.contains(&format!("mtu {}", mtu)) {
                    return Ok(mtu);
                }
            }
        }

        Err(anyhow::anyhow!("Could not parse MTU from ifconfig output"))
    }

    /// Find the optimal MTU using ping with Don't Fragment flag
    pub fn find_optimal_mtu(&self) -> Result<u32> {
        info!("Finding optimal MTU...");

        let target = "8.8.8.8";
        let header_overhead = 28; // IP + ICMP headers

        let mut test_size: u32 = 1472;
        let min_size: u32 = 576 - header_overhead;

        while test_size >= min_size {
            // macOS ping: -D sets Don't Fragment, -s sets packet size, -c 1 for single packet
            let output = hidden_command("ping")
                .args([
                    "-D",                           // Don't Fragment
                    "-s", &test_size.to_string(),   // Packet size
                    "-c", "1",                      // Send 1 packet
                    "-W", "1000",                   // 1 second timeout
                    target,
                ])
                .output()?;

            let output_str = String::from_utf8_lossy(&output.stdout);
            let stderr_str = String::from_utf8_lossy(&output.stderr);

            // Check if ping succeeded (got a reply)
            if output_str.contains("bytes from") &&
               !stderr_str.contains("Message too long") &&
               !stderr_str.contains("frag needed") {
                let optimal_mtu = test_size + header_overhead;
                info!("Found optimal MTU: {} (test size: {})", optimal_mtu, test_size);
                return Ok(optimal_mtu);
            }

            test_size = test_size.saturating_sub(10);
        }

        warn!("Could not determine optimal MTU, using safe default of 1400");
        Ok(1400)
    }

    /// Apply MTU to a BSD network interface using ifconfig
    fn apply_mtu(&self, bsd_name: &str, mtu: u32) -> Result<()> {
        info!("Applying MTU {} to interface '{}'", mtu, bsd_name);

        let output = hidden_command("ifconfig")
            .args([bsd_name, "mtu", &mtu.to_string()])
            .output()?;

        if output.status.success() {
            info!("MTU set successfully");
            Ok(())
        } else {
            let stderr = String::from_utf8_lossy(&output.stderr);
            Err(anyhow::anyhow!("Failed to set MTU: {} (may require root)", stderr))
        }
    }

    /// Restore original MTU setting
    pub fn restore_mtu(&self) -> Result<()> {
        if let Some(original_mtu) = self.original_mtu {
            info!("Restoring original MTU: {}", original_mtu);

            // Get the BSD interface again
            let output = hidden_command("route")
                .args(["-n", "get", "default"])
                .output()?;

            let output_str = String::from_utf8_lossy(&output.stdout);
            if let Some(bsd_name) = output_str.lines()
                .find(|line| line.trim().starts_with("interface:"))
                .and_then(|line| line.split(':').nth(1))
                .map(|s| s.trim().to_string())
            {
                self.apply_mtu(&bsd_name, original_mtu)?;
            }
        }
        Ok(())
    }

    /// Restore original DNS settings
    pub fn restore(&mut self) -> Result<()> {
        info!("Restoring original network settings");

        if let Some(interface) = self.active_interface.take() {
            if let Some((primary, secondary)) = &self.original_dns {
                if primary.is_empty() && secondary.is_empty() {
                    // Restore to DHCP DNS
                    let _ = hidden_command("networksetup")
                        .args(["-setdnsservers", &interface, "empty"])
                        .output();
                } else if secondary.is_empty() {
                    self.set_dns(&interface, primary, "")?;
                } else {
                    self.set_dns(&interface, primary, secondary)?;
                }
            } else {
                // No original DNS saved = was using DHCP. Restore to DHCP.
                info!("Restoring DNS to DHCP defaults");
                let _ = hidden_command("networksetup")
                    .args(["-setdnsservers", &interface, "empty"])
                    .output();
            }
        }

        // Restore original MTU
        let _ = self.restore_mtu();

        Ok(())
    }
}

impl Default for NetworkBooster {
    fn default() -> Self {
        Self::new()
    }
}
