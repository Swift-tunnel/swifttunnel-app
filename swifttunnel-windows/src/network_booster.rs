use crate::structs::*;
use crate::hidden_command;
use log::{info, warn};
use std::process::Command;

pub struct NetworkBooster {
    original_dns: Option<(String, String)>,
    original_mtu: Option<u32>,
}

impl NetworkBooster {
    pub fn new() -> Self {
        Self {
            original_dns: None,
            original_mtu: None,
        }
    }

    /// Apply network optimizations
    pub fn apply_optimizations(&mut self, config: &NetworkConfig) -> Result<()> {
        info!("Applying network optimizations");

        if config.optimize_dns {
            self.optimize_dns(config)?;
        }

        if config.prioritize_roblox_traffic {
            self.prioritize_game_traffic()?;
        }

        // Hook for external network booster integration
        if config.enable_network_boost {
            self.enable_external_network_boost()?;
        }

        // Tier 1 (Safe) Network Boosts
        if config.disable_nagle {
            self.disable_nagle_algorithm()?;
        }

        if config.disable_network_throttling {
            self.disable_network_throttling()?;
        }

        if config.optimize_mtu {
            self.optimize_mtu()?;
        }

        Ok(())
    }

    /// Optimize DNS settings
    fn optimize_dns(&mut self, config: &NetworkConfig) -> Result<()> {
        info!("Optimizing DNS settings");

        let interface_name = self.get_active_network_interface()?;

        // Backup current DNS
        self.backup_dns_settings(&interface_name)?;

        // Set custom DNS
        if let (Some(primary), Some(secondary)) = (&config.custom_dns_primary, &config.custom_dns_secondary) {
            self.set_dns(&interface_name, primary, secondary)?;
        }

        Ok(())
    }

    /// Get active network interface name
    fn get_active_network_interface(&self) -> Result<String> {
        let output = hidden_command("powershell")
            .args(&[
                "-Command",
                "Get-NetAdapter | Where-Object {$_.Status -eq 'Up'} | Select-Object -First 1 -ExpandProperty Name"
            ])
            .output()?;

        let interface = String::from_utf8_lossy(&output.stdout).trim().to_string();

        if interface.is_empty() {
            return Err(anyhow::anyhow!("No active network interface found"));
        }

        Ok(interface)
    }

    /// Backup current DNS settings
    fn backup_dns_settings(&mut self, interface: &str) -> Result<()> {
        let output = hidden_command("powershell")
            .args(&[
                "-Command",
                &format!(
                    "Get-DnsClientServerAddress -InterfaceAlias '{}' -AddressFamily IPv4 | Select-Object -ExpandProperty ServerAddresses",
                    interface
                )
            ])
            .output()?;

        let dns_servers = String::from_utf8_lossy(&output.stdout);
        let servers: Vec<&str> = dns_servers.lines().collect();

        if servers.len() >= 2 {
            self.original_dns = Some((servers[0].to_string(), servers[1].to_string()));
        }

        Ok(())
    }

    /// Set DNS servers
    fn set_dns(&self, interface: &str, primary: &str, secondary: &str) -> Result<()> {
        info!("Setting DNS to {} and {}", primary, secondary);

        let output = hidden_command("powershell")
            .args(&[
                "-Command",
                &format!(
                    "Set-DnsClientServerAddress -InterfaceAlias '{}' -ServerAddresses ('{}','{}')",
                    interface, primary, secondary
                )
            ])
            .output()?;

        if output.status.success() {
            info!("DNS updated successfully");
            Ok(())
        } else {
            warn!("Failed to update DNS (may require admin privileges)");
            Ok(())
        }
    }

    /// Prioritize game traffic using QoS
    fn prioritize_game_traffic(&self) -> Result<()> {
        info!("Prioritizing Roblox game traffic");

        // Use Windows QoS to prioritize Roblox traffic
        let output = hidden_command("powershell")
            .args(&[
                "-Command",
                "New-NetQosPolicy -Name 'RobloxPriority' -AppPathNameMatchCondition 'RobloxPlayerBeta.exe' -NetworkProfile All -PriorityValue8021Action 7 -ErrorAction SilentlyContinue"
            ])
            .output()?;

        if output.status.success() {
            info!("QoS policy created for Roblox");
        } else {
            warn!("Failed to create QoS policy (may already exist or need admin)");
        }

        Ok(())
    }

    /// Enable external network boost (integration point for SwiftTunnel)
    fn enable_external_network_boost(&self) -> Result<()> {
        info!("Enabling external network boost integration");

        // This is a placeholder for integrating with your existing network booster
        // You would call your SwiftTunnel API or executable here

        // Example: Start your network booster process
        // let output = Command::new("SwiftTunnel.exe")
        //     .args(&["--enable", "--game", "roblox"])
        //     .spawn()?;

        // For now, just log that we would enable it
        info!("Network boost integration point - connect your SwiftTunnel here");

        Ok(())
    }

    /// Flush DNS cache
    pub fn flush_dns_cache(&self) -> Result<()> {
        info!("Flushing DNS cache");

        let output = hidden_command("ipconfig")
            .arg("/flushdns")
            .output()?;

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

        // Ping a common Roblox server
        let output = hidden_command("ping")
            .args(&["-n", "4", "www.roblox.com"])
            .output()?;

        let output_str = String::from_utf8_lossy(&output.stdout);

        // Parse average ping from output
        for line in output_str.lines() {
            if line.contains("Average") || line.contains("平均") {
                // Extract ping value (example: "Average = 45ms")
                let parts: Vec<&str> = line.split('=').collect();
                if parts.len() > 1 {
                    let ping_str = parts[1].trim().replace("ms", "");
                    if let Ok(ping) = ping_str.parse::<u32>() {
                        return Ok(ping);
                    }
                }
            }
        }

        // If we couldn't parse, return a default value
        Ok(0)
    }

    // ===== TIER 1 (SAFE) NETWORK BOOSTS =====

    /// Disable Nagle's algorithm for lower latency on small packets
    /// Nagle's algorithm batches small packets to reduce overhead, but adds latency
    /// This is especially beneficial for games that send many small packets
    fn disable_nagle_algorithm(&self) -> Result<()> {
        info!("Disabling Nagle's algorithm for all adapters");

        // Get all network adapter GUIDs
        let output = hidden_command("powershell")
            .args(&[
                "-Command",
                "Get-NetAdapter | Select-Object -ExpandProperty InterfaceGuid"
            ])
            .output();

        match output {
            Ok(result) => {
                let guids = String::from_utf8_lossy(&result.stdout);
                for guid in guids.lines() {
                    let guid = guid.trim();
                    if guid.is_empty() {
                        continue;
                    }

                    // Set TcpAckFrequency = 1 (acknowledge every packet immediately)
                    let key_path = format!(
                        r"HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces\{}",
                        guid
                    );

                    // TcpAckFrequency = 1
                    let _ = hidden_command("reg")
                        .args([
                            "add",
                            &key_path,
                            "/v",
                            "TcpAckFrequency",
                            "/t",
                            "REG_DWORD",
                            "/d",
                            "1",
                            "/f"
                        ])
                        .output();

                    // TCPNoDelay = 1 (disable Nagle)
                    let _ = hidden_command("reg")
                        .args([
                            "add",
                            &key_path,
                            "/v",
                            "TCPNoDelay",
                            "/t",
                            "REG_DWORD",
                            "/d",
                            "1",
                            "/f"
                        ])
                        .output();
                }
                info!("Nagle's algorithm disabled on all adapters");
            }
            Err(e) => {
                warn!("Failed to get adapter GUIDs: {}", e);
            }
        }

        Ok(())
    }

    /// Disable Windows network throttling for full bandwidth to games
    /// Windows throttles network for multimedia apps, this gives games full bandwidth
    fn disable_network_throttling(&self) -> Result<()> {
        info!("Disabling Windows network throttling");

        // Disable network throttling (0xFFFFFFFF = disabled)
        let output = hidden_command("reg")
            .args([
                "add",
                r"HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile",
                "/v",
                "NetworkThrottlingIndex",
                "/t",
                "REG_DWORD",
                "/d",
                "4294967295", // 0xFFFFFFFF
                "/f"
            ])
            .output();

        match output {
            Ok(result) => {
                if result.status.success() {
                    info!("Network throttling disabled");
                } else {
                    warn!("Failed to disable network throttling (may need admin)");
                }
            }
            Err(e) => {
                warn!("Failed to set network throttling: {}", e);
            }
        }

        // Also set SystemResponsiveness to 0 (0% reserved for background tasks)
        let output = hidden_command("reg")
            .args([
                "add",
                r"HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile",
                "/v",
                "SystemResponsiveness",
                "/t",
                "REG_DWORD",
                "/d",
                "0",
                "/f"
            ])
            .output();

        if let Err(e) = output {
            warn!("Failed to set SystemResponsiveness: {}", e);
        }

        Ok(())
    }

    /// Optimize MTU for the active network interface
    /// Finds the optimal MTU that doesn't cause fragmentation and applies it
    fn optimize_mtu(&mut self) -> Result<()> {
        info!("Optimizing MTU for active network interface");

        let interface_name = self.get_active_network_interface()?;

        // Backup current MTU
        if let Ok(current_mtu) = self.get_current_mtu(&interface_name) {
            self.original_mtu = Some(current_mtu);
            info!("Current MTU: {}", current_mtu);
        }

        // Find optimal MTU
        match self.find_optimal_mtu() {
            Ok(optimal_mtu) => {
                info!("Found optimal MTU: {}", optimal_mtu);

                // Apply the optimal MTU
                if let Err(e) = self.apply_mtu(&interface_name, optimal_mtu) {
                    warn!("Failed to apply MTU: {}", e);
                } else {
                    info!("MTU optimized to {} for interface '{}'", optimal_mtu, interface_name);
                }
            }
            Err(e) => {
                warn!("Failed to find optimal MTU: {}", e);
            }
        }

        Ok(())
    }

    /// Get the current MTU for an interface
    fn get_current_mtu(&self, interface: &str) -> Result<u32> {
        let output = hidden_command("powershell")
            .args(&[
                "-Command",
                &format!(
                    "Get-NetIPInterface -InterfaceAlias '{}' -AddressFamily IPv4 | Select-Object -ExpandProperty NlMtu",
                    interface
                )
            ])
            .output()?;

        let mtu_str = String::from_utf8_lossy(&output.stdout).trim().to_string();
        mtu_str.parse::<u32>().map_err(|e| anyhow::anyhow!("Failed to parse MTU: {}", e))
    }

    /// Find the optimal MTU using ping with Don't Fragment flag
    /// Tests from 1500 down to find the largest packet size that doesn't fragment
    pub fn find_optimal_mtu(&self) -> Result<u32> {
        info!("Finding optimal MTU...");

        // Use Google DNS as a reliable target
        let target = "8.8.8.8";

        // Standard Ethernet MTU is 1500
        // IP header is 20 bytes, ICMP header is 8 bytes
        // So we test data sizes and add 28 to get MTU
        let header_overhead = 28;

        // Start at 1472 (1500 - 28) and work down
        let mut test_size: u32 = 1472;
        let min_size: u32 = 576 - header_overhead; // Minimum MTU is 576

        while test_size >= min_size {
            // Use ping with -f flag (Don't Fragment) and -l flag (packet size)
            let output = hidden_command("ping")
                .args(&[
                    "-n", "1",      // Send 1 packet
                    "-f",           // Don't Fragment flag
                    "-l", &test_size.to_string(), // Packet size
                    "-w", "1000",   // 1 second timeout
                    target
                ])
                .output()?;

            let output_str = String::from_utf8_lossy(&output.stdout);
            let output_lower = output_str.to_lowercase();

            // Check if ping succeeded without fragmentation
            // If we see "Reply from" without "needs to be fragmented" or "Packet needs to be fragmented"
            if output_str.contains("Reply from") &&
               !output_lower.contains("fragment") &&
               !output_lower.contains("too big") {
                // Found a working size, optimal MTU is test_size + header_overhead
                let optimal_mtu = test_size + header_overhead;
                info!("Found optimal MTU: {} (test size: {})", optimal_mtu, test_size);
                return Ok(optimal_mtu);
            }

            // Reduce test size by 10 and try again
            test_size = test_size.saturating_sub(10);
        }

        // If we couldn't find optimal, return safe default
        warn!("Could not determine optimal MTU, using safe default of 1400");
        Ok(1400)
    }

    /// Apply MTU to a network interface
    fn apply_mtu(&self, interface: &str, mtu: u32) -> Result<()> {
        info!("Applying MTU {} to interface '{}'", mtu, interface);

        // Use netsh to set MTU
        let output = hidden_command("netsh")
            .args(&[
                "interface", "ipv4", "set", "subinterface",
                interface,
                &format!("mtu={}", mtu),
                "store=persistent"
            ])
            .output()?;

        if output.status.success() {
            info!("MTU set successfully");
            Ok(())
        } else {
            let stderr = String::from_utf8_lossy(&output.stderr);
            Err(anyhow::anyhow!("Failed to set MTU: {}", stderr))
        }
    }

    /// Restore original MTU setting
    pub fn restore_mtu(&self) -> Result<()> {
        if let Some(original_mtu) = self.original_mtu {
            info!("Restoring original MTU: {}", original_mtu);
            let interface_name = self.get_active_network_interface()?;
            self.apply_mtu(&interface_name, original_mtu)?;
        }
        Ok(())
    }

    /// Restore original DNS settings
    pub fn restore(&self) -> Result<()> {
        info!("Restoring original network settings");

        if let Some((primary, secondary)) = &self.original_dns {
            let interface_name = self.get_active_network_interface()?;
            self.set_dns(&interface_name, primary, secondary)?;
        }

        // Restore original MTU
        let _ = self.restore_mtu();

        // Remove QoS policy
        let _ = hidden_command("powershell")
            .args(&[
                "-Command",
                "Remove-NetQosPolicy -Name 'RobloxPriority' -Confirm:$false -ErrorAction SilentlyContinue"
            ])
            .output();

        Ok(())
    }
}

impl Default for NetworkBooster {
    fn default() -> Self {
        Self::new()
    }
}
