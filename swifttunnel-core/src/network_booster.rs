use crate::hidden_command;
use crate::structs::*;
use log::{info, warn};

const LEGACY_ROBLOX_PRIORITY_POLICY: &str = "RobloxPriority";
const ROBLOX_QOS_EXECUTABLES: [&str; 4] = [
    "RobloxPlayerBeta.exe",
    "RobloxStudioBeta.exe",
    "RobloxCrashHandler.exe",
    "Windows10Universal.exe",
];
const RELAY_QOS_EXECUTABLES: [&str; 2] = ["SwiftTunnel.exe", "swifttunnel-desktop.exe"];

#[derive(Clone, Debug, PartialEq, Eq)]
struct OriginalMtu {
    interface: String,
    mtu: u32,
}

pub struct NetworkBooster {
    original_mtu: Option<OriginalMtu>,
    qos_enabled: bool,
}

impl NetworkBooster {
    pub fn new() -> Self {
        Self {
            original_mtu: None,
            qos_enabled: false,
        }
    }

    /// Apply network optimizations
    ///
    /// Individual optimizations are non-fatal: if one fails (e.g. no active
    /// network adapter for MTU), the remaining optimizations still run.
    pub fn apply_optimizations(&mut self, config: &NetworkConfig) -> Result<()> {
        self.reconcile_optimizations(config)
    }

    /// Reconcile network optimizations to exactly match the provided config.
    ///
    /// This makes per-toggle behavior deterministic without relying on a global
    /// "boost on/off" switch.
    pub fn reconcile_optimizations(&mut self, config: &NetworkConfig) -> Result<()> {
        info!("Reconciling network optimizations");

        if config.prioritize_roblox_traffic {
            if let Err(e) = self.prioritize_game_traffic() {
                warn!("Could not prioritize game traffic: {}", e);
            }
        } else if let Err(e) = self.remove_prioritize_game_traffic() {
            warn!("Could not remove Roblox priority QoS policy: {}", e);
        }

        // Tier 1 (Safe) Network Boosts
        if config.disable_nagle {
            if let Err(e) = self.disable_nagle_algorithm() {
                warn!("Could not disable Nagle's algorithm: {}", e);
            }
        } else if let Err(e) = self.restore_nagle_algorithm() {
            warn!("Could not restore Nagle's algorithm defaults: {}", e);
        }

        if config.disable_network_throttling {
            if let Err(e) = self.disable_network_throttling() {
                warn!("Could not disable network throttling: {}", e);
            }
        } else if let Err(e) = self.restore_network_throttling() {
            warn!("Could not restore network throttling defaults: {}", e);
        }

        if config.optimize_mtu {
            if let Err(e) = self.optimize_mtu() {
                warn!("Could not optimize MTU: {}", e);
            }
        } else if let Err(e) = self.restore_mtu() {
            warn!("Could not restore original MTU: {}", e);
        }

        if config.gaming_qos {
            if let Err(e) = self.enable_gaming_qos() {
                warn!("Could not enable gaming QoS: {}", e);
            }
        } else if let Err(e) = self.disable_gaming_qos() {
            warn!("Could not disable gaming QoS: {}", e);
        }

        Ok(())
    }

    fn parse_first_line(output: &[u8], error_message: &str) -> Result<String> {
        let value = String::from_utf8_lossy(output)
            .lines()
            .map(str::trim)
            .find(|line| !line.is_empty())
            .unwrap_or_default()
            .to_string();

        if value.is_empty() {
            return Err(anyhow::anyhow!("{}", error_message));
        }

        Ok(value)
    }

    /// Get the default-route network interface name.
    ///
    /// This avoids selecting an arbitrary "Up" adapter (e.g. virtual NIC) that is not
    /// actually carrying traffic to the internet.
    fn get_active_network_interface(&self) -> Result<String> {
        let output = hidden_command("powershell")
            .args(&[
                "-Command",
                "$ErrorActionPreference = 'Stop'; \
                 $route = Get-NetRoute -AddressFamily IPv4 -DestinationPrefix '0.0.0.0/0' \
                     | Sort-Object -Property @{Expression = {$_.RouteMetric + $_.InterfaceMetric}; Ascending = $true} \
                     | Select-Object -First 1; \
                 if ($null -eq $route) { \
                     $route = Get-NetRoute -AddressFamily IPv6 -DestinationPrefix '::/0' \
                         | Sort-Object -Property @{Expression = {$_.RouteMetric + $_.InterfaceMetric}; Ascending = $true} \
                         | Select-Object -First 1; \
                 } \
                 if ($null -eq $route) { throw 'No default route interface found'; } \
                 Get-NetAdapter -InterfaceIndex $route.ifIndex | Select-Object -First 1 -ExpandProperty Name"
            ])
            .output()?;

        Self::parse_first_line(&output.stdout, "No active network interface found")
    }

    fn list_adapter_guids(&self) -> Vec<String> {
        match hidden_command("powershell")
            .args(&[
                "-Command",
                "Get-NetAdapter | Select-Object -ExpandProperty InterfaceGuid",
            ])
            .output()
        {
            Ok(output) => String::from_utf8_lossy(&output.stdout)
                .lines()
                .map(str::trim)
                .filter(|line| !line.is_empty())
                .map(ToOwned::to_owned)
                .collect(),
            Err(e) => {
                warn!("Failed to get adapter GUIDs: {}", e);
                Vec::new()
            }
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

    fn remove_prioritize_game_traffic(&self) -> Result<()> {
        let output = hidden_command("powershell")
            .args(&[
                "-Command",
                &format!(
                    "Remove-NetQosPolicy -Name '{}' -Confirm:$false -ErrorAction SilentlyContinue",
                    LEGACY_ROBLOX_PRIORITY_POLICY
                ),
            ])
            .output()?;

        if !output.status.success() {
            warn!("Failed to remove legacy RobloxPriority QoS policy");
        }
        Ok(())
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

        for guid in self.list_adapter_guids() {
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
                    "/f",
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
                    "/f",
                ])
                .output();
        }
        info!("Nagle's algorithm disabled on all adapters");

        Ok(())
    }

    fn restore_nagle_algorithm(&self) -> Result<()> {
        info!("Restoring Nagle settings to adapter defaults");
        for guid in self.list_adapter_guids() {
            let key_path = format!(
                r"HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces\{}",
                guid
            );

            // Delete custom overrides so Windows defaults apply.
            let _ = hidden_command("reg")
                .args(["delete", &key_path, "/v", "TcpAckFrequency", "/f"])
                .output();
            let _ = hidden_command("reg")
                .args(["delete", &key_path, "/v", "TCPNoDelay", "/f"])
                .output();
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
                "/f",
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
                "/f",
            ])
            .output();

        if let Err(e) = output {
            warn!("Failed to set SystemResponsiveness: {}", e);
        }

        Ok(())
    }

    fn restore_network_throttling(&self) -> Result<()> {
        info!("Restoring Windows network throttling defaults");

        let _ = hidden_command("reg")
            .args([
                "add",
                r"HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile",
                "/v",
                "NetworkThrottlingIndex",
                "/t",
                "REG_DWORD",
                "/d",
                "10",
                "/f",
            ])
            .output()?;

        let _ = hidden_command("reg")
            .args([
                "add",
                r"HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile",
                "/v",
                "SystemResponsiveness",
                "/t",
                "REG_DWORD",
                "/d",
                "20",
                "/f",
            ])
            .output()?;

        Ok(())
    }

    /// Optimize MTU for the active network interface
    /// Finds the optimal MTU that doesn't cause fragmentation and applies it
    fn optimize_mtu(&mut self) -> Result<()> {
        info!("Optimizing MTU for active network interface");

        let interface_name = self.get_active_network_interface()?;

        // Backup current MTU only once so we can restore to the true pre-optimization value.
        if self.original_mtu.is_none() {
            if let Ok(current_mtu) = self.get_current_mtu(&interface_name) {
                self.original_mtu = Some(OriginalMtu {
                    interface: interface_name.clone(),
                    mtu: current_mtu,
                });
                info!("Current MTU: {}", current_mtu);
            }
        }

        // Find optimal MTU
        match self.find_optimal_mtu() {
            Ok(optimal_mtu) => {
                info!("Found optimal MTU: {}", optimal_mtu);

                // Apply the optimal MTU
                if let Err(e) = self.apply_mtu(&interface_name, optimal_mtu) {
                    warn!("Failed to apply MTU: {}", e);
                } else {
                    info!(
                        "MTU optimized to {} for interface '{}'",
                        optimal_mtu, interface_name
                    );
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

        let mtu_str = Self::parse_first_line(&output.stdout, "Failed to query MTU")?;
        mtu_str
            .parse::<u32>()
            .map_err(|e| anyhow::anyhow!("Failed to parse MTU from '{}': {}", mtu_str, e))
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
                    "-n",
                    "1",  // Send 1 packet
                    "-f", // Don't Fragment flag
                    "-l",
                    &test_size.to_string(), // Packet size
                    "-w",
                    "1000", // 1 second timeout
                    target,
                ])
                .output()?;

            let output_str = String::from_utf8_lossy(&output.stdout);
            let output_lower = output_str.to_lowercase();

            // Check if ping succeeded without fragmentation
            // If we see "Reply from" without "needs to be fragmented" or "Packet needs to be fragmented"
            if output_str.contains("Reply from")
                && !output_lower.contains("fragment")
                && !output_lower.contains("too big")
            {
                // Found a working size, optimal MTU is test_size + header_overhead
                let optimal_mtu = test_size + header_overhead;
                info!(
                    "Found optimal MTU: {} (test size: {})",
                    optimal_mtu, test_size
                );
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
                "interface",
                "ipv4",
                "set",
                "subinterface",
                interface,
                &format!("mtu={}", mtu),
                "store=persistent",
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
    pub fn restore_mtu(&mut self) -> Result<()> {
        if let Some(snapshot) = self.original_mtu.clone() {
            info!(
                "Restoring original MTU {} on interface '{}'",
                snapshot.mtu, snapshot.interface
            );
            self.apply_mtu(&snapshot.interface, snapshot.mtu)?;
            self.original_mtu = None;
        }
        Ok(())
    }

    // ===== GAMING QOS =====

    /// Enable Gaming QoS - marks Roblox and relay UDP packets with DSCP EF (46)
    /// This uses Windows QoS Policy via registry to mark packets without needing socket ownership
    pub fn enable_gaming_qos(&mut self) -> Result<()> {
        info!("Enabling Gaming QoS with DSCP EF (46) priority");

        // Step 1: Enable DSCP tagging in Windows (required for QoS policies to work)
        // Create QoS key under Tcpip if it doesn't exist, then set "Do not use NLA" = 1
        let output = hidden_command("reg")
            .args([
                "add",
                r"HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\QoS",
                "/v",
                "Do not use NLA",
                "/t",
                "REG_DWORD",
                "/d",
                "1",
                "/f",
            ])
            .output();

        match &output {
            Ok(result) => {
                if result.status.success() {
                    info!("DSCP tagging enabled in registry");
                } else {
                    warn!("Failed to enable DSCP tagging (may need admin)");
                }
            }
            Err(e) => {
                warn!("Failed to set DSCP registry key: {}", e);
            }
        }

        // Step 2: Also disable the UserTOSSetting override
        let _ = hidden_command("reg")
            .args([
                "add",
                r"HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters",
                "/v",
                "DisableUserTOSSetting",
                "/t",
                "REG_DWORD",
                "/d",
                "0",
                "/f",
            ])
            .output();

        // Step 3: Create QoS policies for Roblox and tunnel relay app traffic.
        // DSCP 46 = 101110 binary = highest priority for low-latency traffic.
        let write_policy = |policy_name: String, exe: &str, protocol: &str, remote_port: &str| {
            let policy_path = format!(
                r"HKLM\SOFTWARE\Policies\Microsoft\Windows\QoS\{}",
                policy_name
            );

            let _ = hidden_command("reg")
                .args([
                    "add",
                    &policy_path,
                    "/v",
                    "Version",
                    "/t",
                    "REG_SZ",
                    "/d",
                    "1.0",
                    "/f",
                ])
                .output();
            let _ = hidden_command("reg")
                .args([
                    "add",
                    &policy_path,
                    "/v",
                    "Application Name",
                    "/t",
                    "REG_SZ",
                    "/d",
                    exe,
                    "/f",
                ])
                .output();
            let _ = hidden_command("reg")
                .args([
                    "add",
                    &policy_path,
                    "/v",
                    "Protocol",
                    "/t",
                    "REG_SZ",
                    "/d",
                    protocol,
                    "/f",
                ])
                .output();
            let _ = hidden_command("reg")
                .args([
                    "add",
                    &policy_path,
                    "/v",
                    "DSCP Value",
                    "/t",
                    "REG_SZ",
                    "/d",
                    "46",
                    "/f",
                ])
                .output();
            let _ = hidden_command("reg")
                .args([
                    "add",
                    &policy_path,
                    "/v",
                    "Throttle Rate",
                    "/t",
                    "REG_SZ",
                    "/d",
                    "-1",
                    "/f",
                ])
                .output();
            let _ = hidden_command("reg")
                .args([
                    "add",
                    &policy_path,
                    "/v",
                    "Local Port",
                    "/t",
                    "REG_SZ",
                    "/d",
                    "*",
                    "/f",
                ])
                .output();
            let _ = hidden_command("reg")
                .args([
                    "add",
                    &policy_path,
                    "/v",
                    "Local IP",
                    "/t",
                    "REG_SZ",
                    "/d",
                    "*",
                    "/f",
                ])
                .output();
            let _ = hidden_command("reg")
                .args([
                    "add",
                    &policy_path,
                    "/v",
                    "Local IP Prefix Length",
                    "/t",
                    "REG_SZ",
                    "/d",
                    "*",
                    "/f",
                ])
                .output();
            let _ = hidden_command("reg")
                .args([
                    "add",
                    &policy_path,
                    "/v",
                    "Remote Port",
                    "/t",
                    "REG_SZ",
                    "/d",
                    remote_port,
                    "/f",
                ])
                .output();
            let _ = hidden_command("reg")
                .args([
                    "add",
                    &policy_path,
                    "/v",
                    "Remote IP",
                    "/t",
                    "REG_SZ",
                    "/d",
                    "*",
                    "/f",
                ])
                .output();
            let _ = hidden_command("reg")
                .args([
                    "add",
                    &policy_path,
                    "/v",
                    "Remote IP Prefix Length",
                    "/t",
                    "REG_SZ",
                    "/d",
                    "*",
                    "/f",
                ])
                .output();
        };

        for exe in ROBLOX_QOS_EXECUTABLES {
            let policy_name = format!("SwiftTunnel_QoS_{}", exe.replace(".exe", ""));
            write_policy(policy_name, exe, "*", "*");
            info!("Created QoS policy for {}", exe);
        }

        // Fallback for tunnel traffic: app process packets to relay port 51821.
        for exe in RELAY_QOS_EXECUTABLES {
            let policy_name = format!("SwiftTunnel_QoS_Relay_{}", exe.replace(".exe", ""));
            write_policy(policy_name, exe, "UDP", "51821");
            info!("Created relay QoS policy for {}", exe);
        }

        self.qos_enabled = true;
        info!("Gaming QoS enabled - Roblox + relay traffic marked with DSCP 46 (EF)");
        Ok(())
    }

    /// Disable Gaming QoS - removes the QoS policies
    pub fn disable_gaming_qos(&mut self) -> Result<()> {
        info!("Disabling Gaming QoS");

        for exe in ROBLOX_QOS_EXECUTABLES {
            let policy_name = format!("SwiftTunnel_QoS_{}", exe.replace(".exe", ""));
            let policy_path = format!(
                r"HKLM\SOFTWARE\Policies\Microsoft\Windows\QoS\{}",
                policy_name
            );

            // Delete the policy key
            let _ = hidden_command("reg")
                .args(["delete", &policy_path, "/f"])
                .output();
        }

        for exe in RELAY_QOS_EXECUTABLES {
            let policy_name = format!("SwiftTunnel_QoS_Relay_{}", exe.replace(".exe", ""));
            let policy_path = format!(
                r"HKLM\SOFTWARE\Policies\Microsoft\Windows\QoS\{}",
                policy_name
            );
            let _ = hidden_command("reg")
                .args(["delete", &policy_path, "/f"])
                .output();
        }

        self.qos_enabled = false;
        info!("Gaming QoS disabled");
        Ok(())
    }

    /// Check if Gaming QoS is currently enabled
    pub fn is_qos_enabled(&self) -> bool {
        self.qos_enabled
    }

    /// Restore original DNS settings
    pub fn restore(&mut self) -> Result<()> {
        info!("Restoring original network settings");

        // Restore original MTU and low-latency registry overrides.
        let _ = self.restore_mtu();
        let _ = self.restore_nagle_algorithm();
        let _ = self.restore_network_throttling();

        // Remove old QoS policy (legacy)
        let _ = self.remove_prioritize_game_traffic();
        let _ = self.disable_gaming_qos();

        Ok(())
    }
}

impl Default for NetworkBooster {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_first_line_returns_trimmed_first_value() {
        let output = b"\n  Ethernet  \nWi-Fi\n";
        let parsed = NetworkBooster::parse_first_line(output, "missing").unwrap();
        assert_eq!(parsed, "Ethernet");
    }

    #[test]
    fn parse_first_line_errors_when_empty() {
        let output = b"  \n\t\n";
        let parsed = NetworkBooster::parse_first_line(output, "missing");
        assert!(parsed.is_err());
    }

    /// Verify apply_optimizations returns Ok even when individual optimizations
    /// fail (e.g. no active network adapter, no PowerShell, non-Windows host).
    /// Before the fix, a single failure (like optimize_mtu -> "No active network
    /// interface found") would abort the entire boost toggle via `?`.
    #[test]
    fn apply_optimizations_succeeds_despite_individual_failures() {
        let mut booster = NetworkBooster::new();
        let config = NetworkConfig {
            prioritize_roblox_traffic: true,
            disable_nagle: true,
            disable_network_throttling: true,
            optimize_mtu: true,
            gaming_qos: true,
            ..Default::default()
        };

        // On non-Windows (CI) or without admin, every sub-optimization will
        // fail — but apply_optimizations must still return Ok(()).
        let result = booster.apply_optimizations(&config);
        assert!(
            result.is_ok(),
            "apply_optimizations should not abort on individual failures: {:?}",
            result.err()
        );
    }

    #[test]
    fn apply_optimizations_with_nothing_enabled() {
        let mut booster = NetworkBooster::new();
        let config = NetworkConfig {
            prioritize_roblox_traffic: false,
            disable_nagle: false,
            disable_network_throttling: false,
            optimize_mtu: false,
            gaming_qos: false,
            ..Default::default()
        };

        let result = booster.apply_optimizations(&config);
        assert!(result.is_ok());
    }

    #[cfg(not(windows))]
    #[test]
    fn restore_mtu_keeps_snapshot_when_apply_fails() {
        let mut booster = NetworkBooster::new();
        booster.original_mtu = Some(OriginalMtu {
            interface: "Ethernet".to_string(),
            mtu: 1492,
        });

        let result = booster.restore_mtu();
        assert!(result.is_err());
        assert!(booster.original_mtu.is_some());
    }
}
