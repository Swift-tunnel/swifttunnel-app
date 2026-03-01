use crate::hidden_command;
use crate::structs::*;
use log::{info, warn};
use std::path::PathBuf;

const ROBLOX_EXECUTABLES: [&str; 4] = [
    "RobloxPlayerBeta.exe",
    "RobloxStudioBeta.exe",
    "RobloxCrashHandler.exe",
    "Windows10Universal.exe",
];

const FIREWALL_RULE_PREFIX: &str = "SwiftTunnel - Roblox";

pub struct FirewallFixer {
    rules_applied: bool,
}

impl FirewallFixer {
    pub fn new() -> Self {
        Self {
            rules_applied: false,
        }
    }

    /// Apply firewall fixes: add allow rules for Roblox, flush DNS, reset Winsock, clear ARP.
    pub fn apply(&mut self) -> Result<()> {
        if self.rules_applied {
            info!("Firewall fix already applied, skipping");
            return Ok(());
        }

        info!("Applying Roblox firewall fix");

        // 1. Find all Roblox executables and add firewall allow rules
        let executables = find_roblox_executables();

        if executables.is_empty() {
            warn!("No Roblox executables found in %LOCALAPPDATA%\\Roblox\\Versions\\");
        }

        for (exe_name, full_path) in &executables {
            let path_str = full_path.to_string_lossy();

            // Outbound allow rule
            let rule_name_out = format!("{} {} Out", FIREWALL_RULE_PREFIX, exe_name);
            let output = hidden_command("netsh")
                .args([
                    "advfirewall",
                    "firewall",
                    "add",
                    "rule",
                    &format!("name={}", rule_name_out),
                    "dir=out",
                    "action=allow",
                    &format!("program={}", path_str),
                    "enable=yes",
                ])
                .output();

            match output {
                Ok(result) if result.status.success() => {
                    info!("Added outbound firewall rule for {}", exe_name);
                }
                Ok(result) => {
                    let stderr = String::from_utf8_lossy(&result.stderr);
                    warn!(
                        "Failed to add outbound firewall rule for {}: {}",
                        exe_name, stderr
                    );
                }
                Err(e) => {
                    warn!(
                        "Failed to add outbound firewall rule for {}: {}",
                        exe_name, e
                    );
                }
            }

            // Inbound allow rule
            let rule_name_in = format!("{} {} In", FIREWALL_RULE_PREFIX, exe_name);
            let output = hidden_command("netsh")
                .args([
                    "advfirewall",
                    "firewall",
                    "add",
                    "rule",
                    &format!("name={}", rule_name_in),
                    "dir=in",
                    "action=allow",
                    &format!("program={}", path_str),
                    "enable=yes",
                ])
                .output();

            match output {
                Ok(result) if result.status.success() => {
                    info!("Added inbound firewall rule for {}", exe_name);
                }
                Ok(result) => {
                    let stderr = String::from_utf8_lossy(&result.stderr);
                    warn!(
                        "Failed to add inbound firewall rule for {}: {}",
                        exe_name, stderr
                    );
                }
                Err(e) => {
                    warn!(
                        "Failed to add inbound firewall rule for {}: {}",
                        exe_name, e
                    );
                }
            }
        }

        // 2. Flush DNS cache
        let output = hidden_command("ipconfig").args(["/flushdns"]).output();
        match output {
            Ok(result) if result.status.success() => {
                info!("DNS cache flushed");
            }
            Ok(_) => {
                warn!("Failed to flush DNS cache");
            }
            Err(e) => {
                warn!("Failed to flush DNS cache: {}", e);
            }
        }

        // 3. Reset Winsock catalog
        let output = hidden_command("netsh").args(["winsock", "reset"]).output();
        match output {
            Ok(result) if result.status.success() => {
                info!("Winsock catalog reset (reboot required for full effect)");
                warn!("Winsock reset requires a system reboot to fully take effect");
            }
            Ok(_) => {
                warn!("Failed to reset Winsock catalog");
            }
            Err(e) => {
                warn!("Failed to reset Winsock catalog: {}", e);
            }
        }

        // 4. Flush ARP cache
        let output = hidden_command("netsh")
            .args(["interface", "ip", "delete", "arpcache"])
            .output();
        match output {
            Ok(result) if result.status.success() => {
                info!("ARP cache flushed");
            }
            Ok(_) => {
                warn!("Failed to flush ARP cache");
            }
            Err(e) => {
                warn!("Failed to flush ARP cache: {}", e);
            }
        }

        self.rules_applied = true;
        info!("Roblox firewall fix applied successfully");
        Ok(())
    }

    /// Restore: remove all SwiftTunnel Roblox firewall rules.
    pub fn restore(&mut self) -> Result<()> {
        if !self.rules_applied {
            info!("No firewall rules to restore");
            return Ok(());
        }

        info!("Removing SwiftTunnel Roblox firewall rules");

        let executables = find_roblox_executables();

        for (exe_name, _) in &executables {
            // Remove outbound rule
            let rule_name_out = format!("{} {} Out", FIREWALL_RULE_PREFIX, exe_name);
            let _ = hidden_command("netsh")
                .args([
                    "advfirewall",
                    "firewall",
                    "delete",
                    "rule",
                    &format!("name={}", rule_name_out),
                    "dir=out",
                ])
                .output();

            // Remove inbound rule
            let rule_name_in = format!("{} {} In", FIREWALL_RULE_PREFIX, exe_name);
            let _ = hidden_command("netsh")
                .args([
                    "advfirewall",
                    "firewall",
                    "delete",
                    "rule",
                    &format!("name={}", rule_name_in),
                    "dir=in",
                ])
                .output();

            info!("Removed firewall rules for {}", exe_name);
        }

        self.rules_applied = false;
        info!("SwiftTunnel Roblox firewall rules removed");
        Ok(())
    }
}

impl Default for FirewallFixer {
    fn default() -> Self {
        Self::new()
    }
}

/// Scan `%LOCALAPPDATA%\Roblox\Versions\` for known Roblox executables.
///
/// Returns `Vec<(exe_name, full_path)>` for each executable found.
fn find_roblox_executables() -> Vec<(String, PathBuf)> {
    let local_app_data = match std::env::var("LOCALAPPDATA") {
        Ok(path) => PathBuf::from(path),
        Err(_) => {
            warn!("LOCALAPPDATA environment variable not set");
            return Vec::new();
        }
    };

    let versions_dir = local_app_data.join("Roblox").join("Versions");

    if !versions_dir.exists() {
        warn!(
            "Roblox versions directory not found: {}",
            versions_dir.display()
        );
        return Vec::new();
    }

    let mut found = Vec::new();

    let entries = match std::fs::read_dir(&versions_dir) {
        Ok(entries) => entries,
        Err(e) => {
            warn!("Failed to read Roblox versions directory: {}", e);
            return Vec::new();
        }
    };

    for entry in entries.flatten() {
        let path = entry.path();
        if !path.is_dir() {
            continue;
        }

        for exe_name in &ROBLOX_EXECUTABLES {
            let exe_path = path.join(exe_name);
            if exe_path.exists() {
                found.push((exe_name.to_string(), exe_path));
            }
        }
    }

    info!("Found {} Roblox executables", found.len());
    found
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn firewall_fixer_default_not_applied() {
        let fixer = FirewallFixer::new();
        assert!(!fixer.rules_applied);
    }

    #[test]
    fn find_roblox_executables_does_not_panic() {
        // Should not panic even if Roblox is not installed
        let exes = find_roblox_executables();
        // On non-Windows or without Roblox, this will be empty
        assert!(exes.len() <= 100); // Sanity bound
    }

    #[test]
    fn restore_noop_when_not_applied() {
        let mut fixer = FirewallFixer::new();
        let result = fixer.restore();
        assert!(result.is_ok());
    }
}
