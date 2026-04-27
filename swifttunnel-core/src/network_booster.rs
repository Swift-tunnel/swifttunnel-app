use crate::firewall_fixer::FirewallFixer;
use crate::hidden_command;
use crate::structs::*;
use log::{info, warn};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::PathBuf;

const LEGACY_ROBLOX_PRIORITY_POLICY: &str = "RobloxPriority";
const ROBLOX_QOS_EXECUTABLES: [&str; 4] = [
    "RobloxPlayerBeta.exe",
    "RobloxStudioBeta.exe",
    "RobloxCrashHandler.exe",
    "Windows10Universal.exe",
];
const RELAY_QOS_EXECUTABLES: [&str; 2] = ["SwiftTunnel.exe", "swifttunnel-desktop.exe"];
const NETWORK_SYSTEM_PROFILE_KEY: &str =
    r"HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile";
const REG_VALUE_TCP_ACK_FREQUENCY: &str = "TcpAckFrequency";
const REG_VALUE_TCP_NO_DELAY: &str = "TCPNoDelay";
const REG_VALUE_NETWORK_THROTTLING_INDEX: &str = "NetworkThrottlingIndex";
const REG_VALUE_SYSTEM_RESPONSIVENESS: &str = "SystemResponsiveness";
const TCPIP_QOS_KEY: &str = r"HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\QoS";
const TCPIP_PARAMETERS_KEY: &str = r"HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters";
const REG_VALUE_DO_NOT_USE_NLA: &str = "Do not use NLA";
const REG_VALUE_DISABLE_USER_TOS_SETTING: &str = "DisableUserTOSSetting";

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
struct NagleRegistrySnapshot {
    tcp_ack_frequency: Option<u32>,
    tcp_no_delay: Option<u32>,
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
struct NetworkThrottlingSnapshot {
    network_throttling_index: Option<u32>,
    system_responsiveness: Option<u32>,
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
struct QosRegistrySnapshot {
    do_not_use_nla: Option<u32>,
    disable_user_tos_setting: Option<u32>,
}

/// On-disk snapshot of pre-modification values for crash/uninstall recovery.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
struct PersistentSnapshot {
    nagle_registry_snapshot: HashMap<String, NagleRegistrySnapshot>,
    network_throttling_snapshot: Option<NetworkThrottlingSnapshot>,
    #[serde(default)]
    qos_registry_snapshot: Option<QosRegistrySnapshot>,
}

const SNAPSHOT_FILE: &str = "network_snapshots.json";

fn snapshot_path() -> Option<PathBuf> {
    dirs::config_dir().map(|p| p.join("SwiftTunnel").join(SNAPSHOT_FILE))
}

pub struct NetworkBooster {
    qos_enabled: bool,
    nagle_registry_snapshot: HashMap<String, NagleRegistrySnapshot>,
    network_throttling_snapshot: Option<NetworkThrottlingSnapshot>,
    qos_registry_snapshot: Option<QosRegistrySnapshot>,
    firewall_fixer: FirewallFixer,
}

pub struct NetworkApplyOutcome {
    pub applied_config: NetworkConfig,
    pub warnings: Vec<String>,
}

impl NetworkBooster {
    pub fn new() -> Self {
        Self {
            qos_enabled: false,
            nagle_registry_snapshot: HashMap::new(),
            network_throttling_snapshot: None,
            qos_registry_snapshot: None,
            firewall_fixer: FirewallFixer::new(),
        }
    }

    /// Apply network optimizations
    ///
    /// Individual optimizations are non-fatal: if one fails, the remaining
    /// optimizations still run.
    pub fn apply_optimizations(&mut self, config: &NetworkConfig) -> Result<()> {
        self.reconcile_optimizations(config)
    }

    /// Reconcile network optimizations to exactly match the provided config.
    ///
    /// This makes per-toggle behavior deterministic without relying on a global
    /// "boost on/off" switch.
    pub fn reconcile_optimizations(&mut self, config: &NetworkConfig) -> Result<()> {
        info!("Reconciling network optimizations");
        let outcome = self.reconcile_optimizations_checked(config);
        if !outcome.warnings.is_empty() {
            warn!(
                "Network optimizations applied with warnings: {}",
                outcome.warnings.join("; ")
            );
        }
        Ok(())
    }

    /// Reconcile network optimizations and report which toggles actually applied.
    ///
    /// This is used by the desktop UI so a toggle only persists as "on" after
    /// the backing registry/QoS operation succeeds.
    pub fn reconcile_optimizations_checked(
        &mut self,
        config: &NetworkConfig,
    ) -> NetworkApplyOutcome {
        info!("Reconciling network optimizations");

        let mut applied_config = config.clone();
        let mut warnings = Vec::new();

        if config.prioritize_roblox_traffic {
            if let Err(e) = self.prioritize_game_traffic() {
                applied_config.prioritize_roblox_traffic = false;
                warnings.push(format!("Prioritize Roblox traffic: {}", e));
            }
        } else if let Err(e) = self.remove_prioritize_game_traffic() {
            warnings.push(format!("Remove Roblox priority QoS policy: {}", e));
        }

        // Tier 1 (Safe) Network Boosts
        if config.disable_nagle {
            if let Err(e) = self.disable_nagle_algorithm() {
                applied_config.disable_nagle = false;
                warnings.push(format!("Disable Nagle's algorithm: {}", e));
            }
        } else if let Err(e) = self.restore_nagle_algorithm() {
            warnings.push(format!("Restore Nagle's algorithm defaults: {}", e));
        }

        if config.disable_network_throttling {
            if let Err(e) = self.disable_network_throttling() {
                applied_config.disable_network_throttling = false;
                warnings.push(format!("Disable network throttling: {}", e));
            }
        } else if let Err(e) = self.restore_network_throttling() {
            warnings.push(format!("Restore network throttling defaults: {}", e));
        }

        if config.gaming_qos {
            if let Err(e) = self.enable_gaming_qos() {
                applied_config.gaming_qos = false;
                warnings.push(format!("Enable gaming QoS: {}", e));
            }
        } else if let Err(e) = self.disable_gaming_qos() {
            warnings.push(format!("Disable gaming QoS: {}", e));
        }

        if config.firewall_fix {
            if let Err(e) = self.firewall_fixer.apply() {
                applied_config.firewall_fix = false;
                warnings.push(format!("Apply Roblox firewall fix: {}", e));
            }
        } else if let Err(e) = self.firewall_fixer.restore() {
            warnings.push(format!("Restore Roblox firewall rules: {}", e));
        }

        self.persist_snapshot();

        let effective_config = self.effective_network_config(&applied_config);
        if applied_config.disable_nagle && !effective_config.disable_nagle {
            warnings.push("Disable Nagle's algorithm did not verify after apply".to_string());
        }
        if applied_config.disable_network_throttling && !effective_config.disable_network_throttling
        {
            warnings.push("Disable network throttling did not verify after apply".to_string());
        }
        if applied_config.gaming_qos && !effective_config.gaming_qos {
            warnings.push("Gaming QoS did not verify after apply".to_string());
        }
        if applied_config.prioritize_roblox_traffic && !effective_config.prioritize_roblox_traffic {
            warnings.push("Roblox priority QoS did not verify after apply".to_string());
        }

        NetworkApplyOutcome {
            applied_config: effective_config,
            warnings,
        }
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
    pub(crate) fn get_active_network_interface(&self) -> Result<String> {
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

    pub(crate) fn list_adapter_guids(&self) -> Vec<String> {
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

    fn parse_registry_dword(token: &str) -> Option<u32> {
        let raw = token.trim();
        if raw.is_empty() {
            return None;
        }

        if let Some(hex) = raw.strip_prefix("0x") {
            return u32::from_str_radix(hex, 16).ok();
        }

        raw.parse::<u32>().ok()
    }

    fn query_registry_dword(key_path: &str, value_name: &str) -> Option<u32> {
        let output = hidden_command("reg")
            .args(["query", key_path, "/v", value_name])
            .output()
            .ok()?;

        if !output.status.success() {
            return None;
        }

        let output_str = String::from_utf8_lossy(&output.stdout);
        for line in output_str.lines() {
            if !line.contains(value_name) || !line.contains("REG_DWORD") {
                continue;
            }

            if let Some(value_token) = line.split_whitespace().last() {
                if let Some(parsed) = Self::parse_registry_dword(value_token) {
                    return Some(parsed);
                }
            }
        }

        None
    }

    fn registry_key_exists(key_path: &str) -> bool {
        hidden_command("reg")
            .args(["query", key_path])
            .output()
            .map(|output| output.status.success())
            .unwrap_or(false)
    }

    fn qos_policy_exists(policy_name: &str) -> bool {
        let policy_path = format!(
            r"HKLM\SOFTWARE\Policies\Microsoft\Windows\QoS\{}",
            policy_name
        );
        Self::registry_key_exists(&policy_path)
    }

    pub fn effective_network_config(&self, desired: &NetworkConfig) -> NetworkConfig {
        let mut effective = desired.clone();

        if desired.disable_nagle {
            let adapter_guids = self.list_adapter_guids();
            effective.disable_nagle = !adapter_guids.is_empty()
                && adapter_guids.iter().all(|guid| {
                    let key_path = format!(
                        r"HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces\{}",
                        guid
                    );
                    Self::query_registry_dword(&key_path, REG_VALUE_TCP_ACK_FREQUENCY) == Some(1)
                        && Self::query_registry_dword(&key_path, REG_VALUE_TCP_NO_DELAY) == Some(1)
                });
        }

        if desired.disable_network_throttling {
            effective.disable_network_throttling = Self::query_registry_dword(
                NETWORK_SYSTEM_PROFILE_KEY,
                REG_VALUE_NETWORK_THROTTLING_INDEX,
            ) == Some(u32::MAX)
                && Self::query_registry_dword(
                    NETWORK_SYSTEM_PROFILE_KEY,
                    REG_VALUE_SYSTEM_RESPONSIVENESS,
                ) == Some(0);
        }

        if desired.gaming_qos {
            let dscp_enabled = Self::query_registry_dword(
                r"HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\QoS",
                "Do not use NLA",
            ) == Some(1);
            let roblox_policies_present = ROBLOX_QOS_EXECUTABLES.iter().all(|exe| {
                let policy_name = format!("SwiftTunnel_QoS_{}", exe.replace(".exe", ""));
                Self::qos_policy_exists(&policy_name)
            });
            let relay_policies_present = RELAY_QOS_EXECUTABLES.iter().all(|exe| {
                let policy_name = format!("SwiftTunnel_QoS_Relay_{}", exe.replace(".exe", ""));
                Self::qos_policy_exists(&policy_name)
            });
            effective.gaming_qos =
                dscp_enabled && roblox_policies_present && relay_policies_present;
        }

        if desired.prioritize_roblox_traffic {
            effective.prioritize_roblox_traffic =
                Self::qos_policy_exists(LEGACY_ROBLOX_PRIORITY_POLICY);
        }

        effective
    }

    fn set_registry_dword(key_path: &str, value_name: &str, value: u32) -> Result<()> {
        let value_str = value.to_string();
        let output = hidden_command("reg")
            .args([
                "add",
                key_path,
                "/v",
                value_name,
                "/t",
                "REG_DWORD",
                "/d",
                &value_str,
                "/f",
            ])
            .output();

        match output {
            Ok(result) => {
                if !result.status.success() {
                    return Err(anyhow::anyhow!(
                        "failed to set {}\\{} to {}",
                        key_path,
                        value_name,
                        value
                    ));
                }
            }
            Err(e) => {
                return Err(anyhow::anyhow!(
                    "failed to set {}\\{} to {}: {}",
                    key_path,
                    value_name,
                    value,
                    e
                ));
            }
        }

        match Self::query_registry_dword(key_path, value_name) {
            Some(actual) if actual == value => Ok(()),
            Some(actual) => Err(anyhow::anyhow!(
                "{}\\{} was {}, expected {}",
                key_path,
                value_name,
                actual,
                value
            )),
            None => Err(anyhow::anyhow!(
                "{}\\{} was not readable after write",
                key_path,
                value_name
            )),
        }
    }

    fn restore_registry_dword(key_path: &str, value_name: &str, value: Option<u32>) -> Result<()> {
        match value {
            Some(saved) => Self::set_registry_dword(key_path, value_name, saved),
            None => {
                let _ = hidden_command("reg")
                    .args(["delete", key_path, "/v", value_name, "/f"])
                    .output();
                if Self::query_registry_dword(key_path, value_name).is_none() {
                    Ok(())
                } else {
                    Err(anyhow::anyhow!(
                        "failed to restore {}\\{} to absent",
                        key_path,
                        value_name
                    ))
                }
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
            return Err(anyhow::anyhow!(
                "failed to create QoS policy (Administrator may be required)"
            ));
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
            return Err(anyhow::anyhow!(
                "failed to remove legacy RobloxPriority QoS policy"
            ));
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
    fn disable_nagle_algorithm(&mut self) -> Result<()> {
        info!("Disabling Nagle's algorithm for all adapters");

        let adapter_guids = self.list_adapter_guids();
        if adapter_guids.is_empty() {
            return Err(anyhow::anyhow!("no network adapters found"));
        }

        for guid in adapter_guids {
            let key_path = format!(
                r"HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces\{}",
                guid
            );
            self.nagle_registry_snapshot
                .entry(guid)
                .or_insert_with(|| NagleRegistrySnapshot {
                    tcp_ack_frequency: Self::query_registry_dword(
                        &key_path,
                        REG_VALUE_TCP_ACK_FREQUENCY,
                    ),
                    tcp_no_delay: Self::query_registry_dword(&key_path, REG_VALUE_TCP_NO_DELAY),
                });

            // TcpAckFrequency = 1
            Self::set_registry_dword(&key_path, REG_VALUE_TCP_ACK_FREQUENCY, 1)?;

            // TCPNoDelay = 1 (disable Nagle)
            Self::set_registry_dword(&key_path, REG_VALUE_TCP_NO_DELAY, 1)?;
        }
        info!("Nagle's algorithm disabled on all adapters");

        Ok(())
    }

    fn restore_nagle_algorithm(&mut self) -> Result<()> {
        info!("Restoring Nagle settings to adapter snapshots");

        if self.nagle_registry_snapshot.is_empty() {
            info!("No Nagle snapshot captured in this session; skipping restore");
            return Ok(());
        }

        for (guid, snapshot) in self.nagle_registry_snapshot.clone() {
            let key_path = format!(
                r"HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces\{}",
                guid
            );

            Self::restore_registry_dword(
                &key_path,
                REG_VALUE_TCP_ACK_FREQUENCY,
                snapshot.tcp_ack_frequency,
            )?;
            Self::restore_registry_dword(&key_path, REG_VALUE_TCP_NO_DELAY, snapshot.tcp_no_delay)?;
        }

        self.nagle_registry_snapshot.clear();
        Ok(())
    }

    /// Disable Windows network throttling for full bandwidth to games
    /// Windows throttles network for multimedia apps, this gives games full bandwidth
    fn disable_network_throttling(&mut self) -> Result<()> {
        info!("Disabling Windows network throttling");

        if self.network_throttling_snapshot.is_none() {
            self.network_throttling_snapshot = Some(NetworkThrottlingSnapshot {
                network_throttling_index: Self::query_registry_dword(
                    NETWORK_SYSTEM_PROFILE_KEY,
                    REG_VALUE_NETWORK_THROTTLING_INDEX,
                ),
                system_responsiveness: Self::query_registry_dword(
                    NETWORK_SYSTEM_PROFILE_KEY,
                    REG_VALUE_SYSTEM_RESPONSIVENESS,
                ),
            });
        }

        // Disable network throttling (0xFFFFFFFF = disabled)
        Self::set_registry_dword(
            NETWORK_SYSTEM_PROFILE_KEY,
            REG_VALUE_NETWORK_THROTTLING_INDEX,
            u32::MAX, // 0xFFFFFFFF
        )?;
        info!("Network throttling disabled");

        // Also set SystemResponsiveness to 0 (0% reserved for background tasks)
        Self::set_registry_dword(
            NETWORK_SYSTEM_PROFILE_KEY,
            REG_VALUE_SYSTEM_RESPONSIVENESS,
            0,
        )?;

        Ok(())
    }

    fn restore_network_throttling(&mut self) -> Result<()> {
        info!("Restoring Windows network throttling from snapshot");

        let Some(snapshot) = self.network_throttling_snapshot.clone() else {
            info!("No network throttling snapshot captured in this session; skipping restore");
            return Ok(());
        };

        Self::restore_registry_dword(
            NETWORK_SYSTEM_PROFILE_KEY,
            REG_VALUE_NETWORK_THROTTLING_INDEX,
            snapshot.network_throttling_index,
        )?;
        Self::restore_registry_dword(
            NETWORK_SYSTEM_PROFILE_KEY,
            REG_VALUE_SYSTEM_RESPONSIVENESS,
            snapshot.system_responsiveness,
        )?;

        self.network_throttling_snapshot = None;
        Ok(())
    }

    // ===== GAMING QOS =====

    /// Enable Gaming QoS - marks Roblox and relay UDP packets with DSCP EF (46)
    /// This uses Windows QoS Policy via registry to mark packets without needing socket ownership
    pub fn enable_gaming_qos(&mut self) -> Result<()> {
        info!("Enabling Gaming QoS with DSCP EF (46) priority");

        let run_reg_add = |args: &[&str], label: &str| -> Result<()> {
            let output = hidden_command("reg").args(args).output()?;
            if !output.status.success() {
                return Err(anyhow::anyhow!("failed to write {}", label));
            }
            Ok(())
        };

        if self.qos_registry_snapshot.is_none() {
            self.qos_registry_snapshot = Some(QosRegistrySnapshot {
                do_not_use_nla: Self::query_registry_dword(TCPIP_QOS_KEY, REG_VALUE_DO_NOT_USE_NLA),
                disable_user_tos_setting: Self::query_registry_dword(
                    TCPIP_PARAMETERS_KEY,
                    REG_VALUE_DISABLE_USER_TOS_SETTING,
                ),
            });
        }

        // Step 1: Enable DSCP tagging in Windows (required for QoS policies to work)
        // Create QoS key under Tcpip if it doesn't exist, then set "Do not use NLA" = 1
        run_reg_add(
            &[
                "add",
                TCPIP_QOS_KEY,
                "/v",
                REG_VALUE_DO_NOT_USE_NLA,
                "/t",
                "REG_DWORD",
                "/d",
                "1",
                "/f",
            ],
            "DSCP tagging registry key",
        )?;
        info!("DSCP tagging enabled in registry");

        // Step 2: Also disable the UserTOSSetting override
        run_reg_add(
            &[
                "add",
                TCPIP_PARAMETERS_KEY,
                "/v",
                REG_VALUE_DISABLE_USER_TOS_SETTING,
                "/t",
                "REG_DWORD",
                "/d",
                "0",
                "/f",
            ],
            "UserTOSSetting registry key",
        )?;

        // Step 3: Create QoS policies for Roblox and tunnel relay app traffic.
        // DSCP 46 = 101110 binary = highest priority for low-latency traffic.
        let write_policy =
            |policy_name: String, exe: &str, protocol: &str, remote_port: &str| -> Result<()> {
                let policy_path = format!(
                    r"HKLM\SOFTWARE\Policies\Microsoft\Windows\QoS\{}",
                    policy_name
                );

                run_reg_add(
                    &[
                        "add",
                        &policy_path,
                        "/v",
                        "Version",
                        "/t",
                        "REG_SZ",
                        "/d",
                        "1.0",
                        "/f",
                    ],
                    "QoS policy Version",
                )?;
                run_reg_add(
                    &[
                        "add",
                        &policy_path,
                        "/v",
                        "Application Name",
                        "/t",
                        "REG_SZ",
                        "/d",
                        exe,
                        "/f",
                    ],
                    "QoS policy Application Name",
                )?;
                run_reg_add(
                    &[
                        "add",
                        &policy_path,
                        "/v",
                        "Protocol",
                        "/t",
                        "REG_SZ",
                        "/d",
                        protocol,
                        "/f",
                    ],
                    "QoS policy Protocol",
                )?;
                run_reg_add(
                    &[
                        "add",
                        &policy_path,
                        "/v",
                        "DSCP Value",
                        "/t",
                        "REG_SZ",
                        "/d",
                        "46",
                        "/f",
                    ],
                    "QoS policy DSCP Value",
                )?;
                run_reg_add(
                    &[
                        "add",
                        &policy_path,
                        "/v",
                        "Throttle Rate",
                        "/t",
                        "REG_SZ",
                        "/d",
                        "-1",
                        "/f",
                    ],
                    "QoS policy Throttle Rate",
                )?;
                run_reg_add(
                    &[
                        "add",
                        &policy_path,
                        "/v",
                        "Local Port",
                        "/t",
                        "REG_SZ",
                        "/d",
                        "*",
                        "/f",
                    ],
                    "QoS policy Local Port",
                )?;
                run_reg_add(
                    &[
                        "add",
                        &policy_path,
                        "/v",
                        "Local IP",
                        "/t",
                        "REG_SZ",
                        "/d",
                        "*",
                        "/f",
                    ],
                    "QoS policy Local IP",
                )?;
                run_reg_add(
                    &[
                        "add",
                        &policy_path,
                        "/v",
                        "Local IP Prefix Length",
                        "/t",
                        "REG_SZ",
                        "/d",
                        "*",
                        "/f",
                    ],
                    "QoS policy Local IP Prefix Length",
                )?;
                run_reg_add(
                    &[
                        "add",
                        &policy_path,
                        "/v",
                        "Remote Port",
                        "/t",
                        "REG_SZ",
                        "/d",
                        remote_port,
                        "/f",
                    ],
                    "QoS policy Remote Port",
                )?;
                run_reg_add(
                    &[
                        "add",
                        &policy_path,
                        "/v",
                        "Remote IP",
                        "/t",
                        "REG_SZ",
                        "/d",
                        "*",
                        "/f",
                    ],
                    "QoS policy Remote IP",
                )?;
                run_reg_add(
                    &[
                        "add",
                        &policy_path,
                        "/v",
                        "Remote IP Prefix Length",
                        "/t",
                        "REG_SZ",
                        "/d",
                        "*",
                        "/f",
                    ],
                    "QoS policy Remote IP Prefix Length",
                )?;
                Ok(())
            };

        for exe in ROBLOX_QOS_EXECUTABLES {
            let policy_name = format!("SwiftTunnel_QoS_{}", exe.replace(".exe", ""));
            write_policy(policy_name, exe, "*", "*")?;
            info!("Created QoS policy for {}", exe);
        }

        // Fallback for tunnel traffic: app process packets to relay port 51821.
        for exe in RELAY_QOS_EXECUTABLES {
            let policy_name = format!("SwiftTunnel_QoS_Relay_{}", exe.replace(".exe", ""));
            write_policy(policy_name, exe, "UDP", "51821")?;
            info!("Created relay QoS policy for {}", exe);
        }

        self.qos_enabled = true;
        info!("Gaming QoS enabled - Roblox + relay traffic marked with DSCP 46 (EF)");
        Ok(())
    }

    /// Disable Gaming QoS - removes the QoS policies and DSCP registry keys
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

        if let Some(snapshot) = self.qos_registry_snapshot.clone() {
            Self::restore_registry_dword(
                TCPIP_QOS_KEY,
                REG_VALUE_DO_NOT_USE_NLA,
                snapshot.do_not_use_nla,
            )?;
            Self::restore_registry_dword(
                TCPIP_PARAMETERS_KEY,
                REG_VALUE_DISABLE_USER_TOS_SETTING,
                snapshot.disable_user_tos_setting,
            )?;
            self.qos_registry_snapshot = None;
        } else {
            info!(
                "No Gaming QoS registry snapshot captured; leaving global DSCP/TOS values unchanged"
            );
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

        let mut errors = Vec::new();

        // Restore low-latency registry overrides.
        if let Err(e) = self.restore_nagle_algorithm() {
            errors.push(format!("Nagle registry restore: {}", e));
        }
        if let Err(e) = self.restore_network_throttling() {
            errors.push(format!("network throttling registry restore: {}", e));
        }

        // Remove old QoS policy (legacy)
        if let Err(e) = self.remove_prioritize_game_traffic() {
            warn!("Legacy QoS policy removal failed during restore: {}", e);
        }
        if let Err(e) = self.disable_gaming_qos() {
            errors.push(format!("Gaming QoS restore: {}", e));
        }

        // Remove firewall rules
        if let Err(e) = self.firewall_fixer.restore() {
            errors.push(format!("firewall rule restore: {}", e));
        }

        if !errors.is_empty() {
            return Err(anyhow::anyhow!(
                "Network restore incomplete: {}",
                errors.join("; ")
            ));
        }

        Self::clear_snapshot();

        Ok(())
    }

    /// Save pre-modification values to disk for crash/uninstall recovery.
    fn persist_snapshot(&self) {
        let Some(path) = snapshot_path() else {
            return;
        };
        let snapshot = PersistentSnapshot {
            nagle_registry_snapshot: self.nagle_registry_snapshot.clone(),
            network_throttling_snapshot: self.network_throttling_snapshot.clone(),
            qos_registry_snapshot: self.qos_registry_snapshot.clone(),
        };
        if let Some(parent) = path.parent() {
            let _ = std::fs::create_dir_all(parent);
        }
        match serde_json::to_string_pretty(&snapshot) {
            Ok(json) => {
                if let Err(e) = std::fs::write(&path, json) {
                    warn!("Failed to persist network snapshot: {e}");
                }
            }
            Err(e) => warn!("Failed to serialize network snapshot: {e}"),
        }
    }

    /// Remove the on-disk snapshot file.
    fn clear_snapshot() {
        if let Some(path) = snapshot_path() {
            let _ = std::fs::remove_file(path);
        }
    }

    /// Recover from a persisted snapshot (call on startup).
    ///
    /// If a snapshot file exists, it means the previous session didn't get to
    /// `restore()`. Load the saved originals and restore them.
    pub fn recover_from_snapshot(&mut self) {
        let Some(path) = snapshot_path() else {
            return;
        };
        let content = match std::fs::read_to_string(&path) {
            Ok(c) => c,
            Err(_) => return, // no snapshot on disk
        };
        let snapshot: PersistentSnapshot = match serde_json::from_str(&content) {
            Ok(s) => s,
            Err(e) => {
                warn!("Failed to parse network snapshot, removing: {e}");
                let _ = std::fs::remove_file(&path);
                return;
            }
        };

        info!("Recovering network settings from persisted snapshot");

        if self.nagle_registry_snapshot.is_empty() {
            self.nagle_registry_snapshot = snapshot.nagle_registry_snapshot;
        }
        if self.network_throttling_snapshot.is_none() {
            self.network_throttling_snapshot = snapshot.network_throttling_snapshot;
        }
        if self.qos_registry_snapshot.is_none() {
            self.qos_registry_snapshot = snapshot.qos_registry_snapshot;
        }

        let _ = self.restore();
    }
}

/// Stateless cleanup of ALL SwiftTunnel system modifications.
///
/// Does not rely on in-memory snapshots — scans the system for known
/// SwiftTunnel artifacts and removes them. Used by `--cleanup` (NSIS
/// uninstaller) and the `system_cleanup` Tauri command.
pub fn cleanup_all_system_state() -> Result<()> {
    info!("Running full stateless system cleanup");

    let mut booster = NetworkBooster::new();
    booster.recover_from_snapshot();

    // 1. Remove hosts file entries
    if let Err(e) = crate::roblox_proxy::hosts::remove_overrides() {
        warn!("Cleanup: failed to remove hosts overrides: {e}");
    }

    // 2. Delete SwiftTunnel QoS registry policies
    for exe in ROBLOX_QOS_EXECUTABLES {
        let policy_name = format!("SwiftTunnel_QoS_{}", exe.replace(".exe", ""));
        let policy_path = format!(
            r"HKLM\SOFTWARE\Policies\Microsoft\Windows\QoS\{}",
            policy_name
        );
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

    info!(
        "Cleanup: leaving global TCP/QoS registry values untouched unless a persisted SwiftTunnel snapshot restored them"
    );

    // 3. Remove firewall rules.
    let mut firewall = FirewallFixer::new();
    let _ = firewall.restore();

    // 4. Delete legacy RobloxPriority QoS policy
    let _ = hidden_command("powershell")
        .args([
            "-Command",
            &format!(
                "Remove-NetQosPolicy -Name '{}' -Confirm:$false -ErrorAction SilentlyContinue",
                LEGACY_ROBLOX_PRIORITY_POLICY
            ),
        ])
        .output();

    // 8. Remove the snapshot file itself
    NetworkBooster::clear_snapshot();

    // 9. Restore system optimizer settings (MMCSS, Game Bar, fullscreen opts, Game Mode, power plan)
    crate::system_optimizer::cleanup_for_uninstall();

    // 10. Recover TSO/IPv6 adapter settings if they were left disabled by a crash
    crate::vpn::recover_tso_on_startup();
    crate::vpn::recover_ipv6_on_startup();

    // 11. Remove stale WFP block filters left by older non-dynamic sessions.
    crate::vpn::wfp_block::cleanup_stale();

    // 12. Reset any adapter left in WinpkFilter tunnel mode.
    crate::vpn::SplitTunnelDriver::cleanup_stale_state();

    // 13. Remove the WinpkFilter driver package and NDISRD service during
    // uninstall/explicit cleanup so the app does not leave kernel artifacts
    // behind. Best-effort: if this fails we log it and continue rather than
    // aborting the uninstall. Blocking uninstall entirely leaves the user
    // permanently stuck (often the reason they are uninstalling in the first
    // place), which is worse than a stale driver that a subsequent install
    // will replace.
    if let Err(e) = crate::vpn::split_tunnel::SplitTunnelDriver::remove_driver_for_uninstall() {
        warn!("Cleanup: driver removal failed (non-fatal): {}", e);
    }

    // 14. Remove Roblox FFlag entries from ClientAppSettings.json
    crate::roblox_optimizer::RobloxOptimizer::cleanup_for_uninstall();

    // 15. Delete autostart Run key
    let _ = hidden_command("reg")
        .args([
            "delete",
            r"HKCU\Software\Microsoft\Windows\CurrentVersion\Run",
            "/v",
            "SwiftTunnel",
            "/f",
        ])
        .output();

    info!("Full system cleanup completed");
    Ok(())
}

/// Reset MTU to 1500 on all active network adapters.
///
/// The removed MTU optimizer used `store=persistent` which permanently changed
/// WiFi adapter MTU values, causing Roblox connection timeouts on some drivers.
fn reset_mtu_all_adapters() {
    let adapters: Vec<String> = match hidden_command("powershell")
        .args([
            "-Command",
            "Get-NetAdapter | Where-Object { $_.Status -eq 'Up' } | Select-Object -ExpandProperty Name",
        ])
        .output()
    {
        Ok(output) => String::from_utf8_lossy(&output.stdout)
            .lines()
            .map(str::trim)
            .filter(|l| !l.is_empty())
            .map(ToOwned::to_owned)
            .collect(),
        Err(_) => Vec::new(),
    };
    for iface in &adapters {
        let _ = hidden_command("netsh")
            .args([
                "interface",
                "ipv4",
                "set",
                "subinterface",
                iface,
                "mtu=1500",
                "store=persistent",
            ])
            .output();
    }
}

pub fn fix_mtu_on_upgrade() {
    info!("Legacy MTU repair is disabled by default to avoid overwriting user adapter settings");
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

    #[test]
    fn parse_registry_dword_supports_hex_and_decimal() {
        assert_eq!(NetworkBooster::parse_registry_dword("0x1"), Some(1));
        assert_eq!(
            NetworkBooster::parse_registry_dword("4294967295"),
            Some(u32::MAX)
        );
        assert_eq!(NetworkBooster::parse_registry_dword(""), None);
        assert_eq!(NetworkBooster::parse_registry_dword("invalid"), None);
    }

    #[test]
    fn persistent_snapshot_accepts_pre_qos_snapshot_files() {
        let snapshot: PersistentSnapshot = serde_json::from_str(
            r#"{
              "nagle_registry_snapshot": {},
              "network_throttling_snapshot": null
            }"#,
        )
        .expect("old snapshot without QoS fields should still load");

        assert!(snapshot.qos_registry_snapshot.is_none());
    }

    /// Verify apply_optimizations returns Ok even when individual optimizations
    /// fail (e.g. no PowerShell, non-Windows host).
    #[test]
    #[cfg_attr(
        target_os = "windows",
        ignore = "mutates real system network settings on elevated Windows runners"
    )]
    fn apply_optimizations_succeeds_despite_individual_failures() {
        let mut booster = NetworkBooster::new();
        let config = NetworkConfig {
            prioritize_roblox_traffic: true,
            disable_nagle: true,
            disable_network_throttling: true,
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
    #[cfg_attr(
        target_os = "windows",
        ignore = "mutates real system network settings on elevated Windows runners"
    )]
    fn apply_optimizations_with_nothing_enabled() {
        let mut booster = NetworkBooster::new();
        let config = NetworkConfig {
            prioritize_roblox_traffic: false,
            disable_nagle: false,
            disable_network_throttling: false,
            gaming_qos: false,
            ..Default::default()
        };

        let result = booster.apply_optimizations(&config);
        assert!(result.is_ok());
    }
}
