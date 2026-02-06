//! macOS pf (Packet Filter) Firewall Management
//!
//! Manages pf firewall rules for split tunneling on macOS. Uses the anchor
//! mechanism to isolate SwiftTunnel rules from system rules.
//!
//! This module has NO Windows equivalent - it's macOS-specific infrastructure
//! that replaces the ndisapi packet interception approach used on Windows.
//!
//! ## How it works
//!
//! SwiftTunnel's split tunnel model is: tunnel ONLY game app traffic, everything
//! else goes through the normal physical interface. On macOS:
//!
//! 1. Default traffic goes through the physical interface (normal routing)
//! 2. We use pf `route-to` rules to redirect game traffic through the utun interface
//! 3. Since pf cannot filter by PID directly, we track which local ports belong
//!    to game processes (via process_tracker) and create pf rules matching those ports
//! 4. Rules are updated dynamically as game processes create/destroy connections
//!
//! ## pf anchor structure
//!
//! ```
//! anchor "swifttunnel" {
//!     # Game traffic routing rules
//!     pass out on en0 route-to (utunN 10.0.X.1) proto udp from any port { ... } to any
//!     pass out on en0 route-to (utunN 10.0.X.1) proto tcp from any port { ... } to any
//!
//!     # NAT for return traffic
//!     nat on utunN from any to any -> (utunN)
//! }
//! ```
//!
//! ## Requirements
//! - Root privileges (for pfctl)
//! - pf must be enabled (`pfctl -e`)

use std::collections::HashSet;
use std::io::Write;
use std::net::Ipv4Addr;
use std::process::Command;
use super::{VpnError, VpnResult};

/// Name of the pf anchor used by SwiftTunnel
const ANCHOR_NAME: &str = "com.swifttunnel";

/// Manages pf firewall rules for macOS split tunneling
pub struct PfFirewall {
    /// Name of the utun interface (e.g., "utun5")
    utun_name: Option<String>,
    /// Name of the physical interface (e.g., "en0")
    physical_interface: Option<String>,
    /// VPN tunnel gateway IP (the VPN-assigned IP's gateway, typically x.x.x.1)
    tunnel_gateway: Option<Ipv4Addr>,
    /// Currently active game source ports (UDP)
    active_udp_ports: HashSet<u16>,
    /// Currently active game source ports (TCP)
    active_tcp_ports: HashSet<u16>,
    /// Whether split tunnel rules are currently active
    active: bool,
    /// Path to the temporary rules file
    rules_file_path: String,
}

impl PfFirewall {
    /// Create a new pf firewall manager
    pub fn new() -> Self {
        let rules_file_path = format!("/tmp/swifttunnel_pf_rules_{}.conf", std::process::id());

        Self {
            utun_name: None,
            physical_interface: None,
            tunnel_gateway: None,
            active_udp_ports: HashSet::new(),
            active_tcp_ports: HashSet::new(),
            active: false,
            rules_file_path,
        }
    }

    /// Enable split tunnel routing through pf
    ///
    /// Sets up the pf anchor and initial routing rules.
    /// Must be called with root privileges.
    ///
    /// # Arguments
    /// * `utun_name` - Name of the utun VPN interface (e.g., "utun5")
    /// * `physical_interface` - Name of the physical interface (e.g., "en0")
    /// * `tunnel_gateway` - VPN gateway IP for route-to directive
    pub fn enable_split_tunnel(
        &mut self,
        utun_name: &str,
        physical_interface: &str,
        tunnel_gateway: Ipv4Addr,
    ) -> VpnResult<()> {
        log::info!(
            "Enabling pf split tunnel: utun={}, physical={}, gateway={}",
            utun_name, physical_interface, tunnel_gateway
        );

        self.utun_name = Some(utun_name.to_string());
        self.physical_interface = Some(physical_interface.to_string());
        self.tunnel_gateway = Some(tunnel_gateway);

        // Ensure pf is enabled
        self.ensure_pf_enabled()?;

        // Ensure the anchor reference exists in the main ruleset
        self.ensure_anchor_reference()?;

        // Write initial empty rules (no game ports yet)
        self.write_and_load_rules()?;

        self.active = true;
        log::info!("pf split tunnel enabled");

        Ok(())
    }

    /// Update the set of game ports to route through VPN
    ///
    /// Called by the split tunnel coordinator when game process connections change.
    /// Writes new pf rules with the updated port list and loads them atomically.
    pub fn update_game_ports(
        &mut self,
        udp_ports: HashSet<u16>,
        tcp_ports: HashSet<u16>,
    ) -> VpnResult<()> {
        if !self.active {
            return Err(VpnError::SplitTunnel(
                "pf split tunnel not active".to_string(),
            ));
        }

        // Only reload rules if ports actually changed
        if udp_ports == self.active_udp_ports && tcp_ports == self.active_tcp_ports {
            return Ok(());
        }

        let udp_count = udp_ports.len();
        let tcp_count = tcp_ports.len();

        self.active_udp_ports = udp_ports;
        self.active_tcp_ports = tcp_ports;

        self.write_and_load_rules()?;

        log::debug!(
            "pf rules updated: {} UDP ports, {} TCP ports",
            udp_count, tcp_count
        );

        Ok(())
    }

    /// Disable split tunnel and remove all pf rules
    pub fn disable_split_tunnel(&mut self) -> VpnResult<()> {
        if !self.active {
            return Ok(());
        }

        log::info!("Disabling pf split tunnel");

        // Flush all rules in our anchor
        let output = Command::new("pfctl")
            .args(["-a", ANCHOR_NAME, "-F", "all"])
            .output()
            .map_err(|e| VpnError::SplitTunnel(format!("Failed to flush pf anchor: {}", e)))?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            log::warn!("pfctl flush warning: {}", stderr.trim());
        }

        // Clean up temp file
        let _ = std::fs::remove_file(&self.rules_file_path);

        self.active_udp_ports.clear();
        self.active_tcp_ports.clear();
        self.active = false;

        log::info!("pf split tunnel disabled");
        Ok(())
    }

    /// Clean up all SwiftTunnel pf state
    ///
    /// Can be called statically to clean up from a previous crash.
    pub fn cleanup() -> VpnResult<()> {
        log::info!("Cleaning up SwiftTunnel pf rules");

        // Flush anchor rules
        let _ = Command::new("pfctl")
            .args(["-a", ANCHOR_NAME, "-F", "all"])
            .output();

        // Remove any temp files
        let pattern = "/tmp/swifttunnel_pf_rules_*.conf";
        if let Ok(entries) = glob_lite(pattern) {
            for path in entries {
                let _ = std::fs::remove_file(&path);
            }
        }

        log::info!("pf cleanup complete");
        Ok(())
    }

    /// Check if pf rules are currently active
    pub fn is_active(&self) -> bool {
        self.active
    }

    /// Get the number of active game ports being routed
    pub fn active_port_count(&self) -> usize {
        self.active_udp_ports.len() + self.active_tcp_ports.len()
    }

    // ═══════════════════════════════════════════════════════════════════════
    // Internal methods
    // ═══════════════════════════════════════════════════════════════════════

    /// Ensure pf is enabled on the system
    fn ensure_pf_enabled(&self) -> VpnResult<()> {
        let output = Command::new("pfctl")
            .arg("-si")
            .output()
            .map_err(|e| VpnError::SplitTunnel(format!("Failed to check pf status: {}", e)))?;

        let stdout = String::from_utf8_lossy(&output.stdout);

        if stdout.contains("Status: Enabled") {
            log::debug!("pf is already enabled");
            return Ok(());
        }

        // Enable pf
        log::info!("Enabling pf firewall");
        let output = Command::new("pfctl")
            .arg("-e")
            .output()
            .map_err(|e| VpnError::SplitTunnel(format!("Failed to enable pf: {}", e)))?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            // "pf already enabled" is not an error
            if !stderr.contains("already enabled") {
                return Err(VpnError::SplitTunnel(format!(
                    "Failed to enable pf: {}",
                    stderr.trim()
                )));
            }
        }

        Ok(())
    }

    /// Ensure our anchor is referenced in the main pf ruleset
    ///
    /// Checks if `anchor "com.swifttunnel"` exists in the main rules.
    /// If not, adds it by appending to the current ruleset.
    fn ensure_anchor_reference(&self) -> VpnResult<()> {
        // Check current rules for our anchor
        let output = Command::new("pfctl")
            .args(["-sr"])
            .output()
            .map_err(|e| VpnError::SplitTunnel(format!("Failed to read pf rules: {}", e)))?;

        let rules = String::from_utf8_lossy(&output.stdout);

        let anchor_ref = format!("anchor \"{}\"", ANCHOR_NAME);
        let rdr_anchor_ref = format!("rdr-anchor \"{}\"", ANCHOR_NAME);
        let nat_anchor_ref = format!("nat-anchor \"{}\"", ANCHOR_NAME);

        if rules.contains(&anchor_ref) {
            log::debug!("pf anchor reference already exists");
            return Ok(());
        }

        // We need to add our anchor reference to the main ruleset.
        // Write a temp file with the current rules + our anchor references.
        let temp_path = format!("/tmp/swifttunnel_pf_main_{}.conf", std::process::id());
        let mut main_rules = rules.to_string();

        // Add anchor references at the end (before any final pass/block rules)
        if !main_rules.contains(&nat_anchor_ref) {
            main_rules.push_str(&format!("\n{}\n", nat_anchor_ref));
        }
        if !main_rules.contains(&rdr_anchor_ref) {
            main_rules.push_str(&format!("{}\n", rdr_anchor_ref));
        }
        main_rules.push_str(&format!("{}\n", anchor_ref));

        std::fs::write(&temp_path, &main_rules).map_err(|e| {
            VpnError::SplitTunnel(format!("Failed to write main pf rules: {}", e))
        })?;

        let output = Command::new("pfctl")
            .args(["-f", &temp_path])
            .output()
            .map_err(|e| VpnError::SplitTunnel(format!("Failed to load main pf rules: {}", e)))?;

        let _ = std::fs::remove_file(&temp_path);

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            // Warnings about subnets are ok
            if stderr.lines().any(|l| l.contains("error") || l.contains("syntax error")) {
                return Err(VpnError::SplitTunnel(format!(
                    "Failed to add pf anchor: {}",
                    stderr.trim()
                )));
            }
        }

        log::info!("Added pf anchor reference: {}", anchor_ref);
        Ok(())
    }

    /// Write pf rules to temp file and load them into the anchor
    fn write_and_load_rules(&self) -> VpnResult<()> {
        let utun = self
            .utun_name
            .as_deref()
            .ok_or_else(|| VpnError::SplitTunnel("utun interface not set".to_string()))?;
        let physical = self
            .physical_interface
            .as_deref()
            .ok_or_else(|| VpnError::SplitTunnel("physical interface not set".to_string()))?;
        let gateway = self
            .tunnel_gateway
            .ok_or_else(|| VpnError::SplitTunnel("tunnel gateway not set".to_string()))?;

        let mut rules = String::new();

        // Generate rules for UDP game traffic
        if !self.active_udp_ports.is_empty() {
            let port_list = format_port_list(&self.active_udp_ports);
            // Route matching outbound UDP traffic through the VPN tunnel
            rules.push_str(&format!(
                "pass out on {} route-to ({} {}) proto udp from any port {{ {} }} to any no state\n",
                physical, utun, gateway, port_list
            ));
        }

        // Generate rules for TCP game traffic (less common for games, but included)
        if !self.active_tcp_ports.is_empty() {
            let port_list = format_port_list(&self.active_tcp_ports);
            rules.push_str(&format!(
                "pass out on {} route-to ({} {}) proto tcp from any port {{ {} }} to any no state\n",
                physical, utun, gateway, port_list
            ));
        }

        // If no ports, write an empty ruleset (clears previous rules)
        if rules.is_empty() {
            rules.push_str("# No game ports currently active\n");
        }

        // Write rules to temp file
        let mut file = std::fs::File::create(&self.rules_file_path).map_err(|e| {
            VpnError::SplitTunnel(format!("Failed to create rules file: {}", e))
        })?;
        file.write_all(rules.as_bytes()).map_err(|e| {
            VpnError::SplitTunnel(format!("Failed to write rules file: {}", e))
        })?;

        // Load rules into anchor
        let output = Command::new("pfctl")
            .args(["-a", ANCHOR_NAME, "-f", &self.rules_file_path])
            .output()
            .map_err(|e| VpnError::SplitTunnel(format!("Failed to load pf rules: {}", e)))?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            if stderr.lines().any(|l| l.contains("syntax error")) {
                return Err(VpnError::SplitTunnel(format!(
                    "pf rule syntax error: {}",
                    stderr.trim()
                )));
            }
            // Warnings are ok (e.g., "no valid ports")
            log::debug!("pfctl load warning: {}", stderr.trim());
        }

        Ok(())
    }
}

impl Drop for PfFirewall {
    fn drop(&mut self) {
        if self.active {
            if let Err(e) = self.disable_split_tunnel() {
                log::error!("Failed to disable pf split tunnel on drop: {}", e);
            }
        }
    }
}

/// Format a set of ports into a pf port list string
/// e.g., {50123, 50124, 50125}
fn format_port_list(ports: &HashSet<u16>) -> String {
    let mut sorted: Vec<u16> = ports.iter().copied().collect();
    sorted.sort();
    sorted
        .iter()
        .map(|p| p.to_string())
        .collect::<Vec<_>>()
        .join(", ")
}

/// Simple glob matching for cleanup (no external dependency)
fn glob_lite(pattern: &str) -> Result<Vec<String>, std::io::Error> {
    // Very basic glob: only supports /path/prefix_*.ext
    let (dir, file_pattern) = if let Some(pos) = pattern.rfind('/') {
        (&pattern[..pos], &pattern[pos + 1..])
    } else {
        (".", pattern)
    };

    let prefix = file_pattern.split('*').next().unwrap_or("");
    let suffix = file_pattern.split('*').nth(1).unwrap_or("");

    let mut results = Vec::new();
    for entry in std::fs::read_dir(dir)? {
        let entry = entry?;
        let name = entry.file_name().to_string_lossy().to_string();
        if name.starts_with(prefix) && name.ends_with(suffix) {
            results.push(format!("{}/{}", dir, name));
        }
    }
    Ok(results)
}

/// Detect the primary physical network interface (e.g., "en0")
///
/// Uses `route -n get default` to find which interface has the default route.
pub fn detect_physical_interface() -> Option<String> {
    let output = Command::new("route")
        .args(["-n", "get", "default"])
        .output()
        .ok()?;

    let stdout = String::from_utf8_lossy(&output.stdout);

    for line in stdout.lines() {
        let line = line.trim();
        if line.starts_with("interface:") {
            return line.split(':').nth(1).map(|s| s.trim().to_string());
        }
    }

    // Fallback: assume en0
    Some("en0".to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_format_port_list() {
        let mut ports = HashSet::new();
        ports.insert(50123);
        ports.insert(50124);
        ports.insert(50122);

        let result = format_port_list(&ports);
        assert_eq!(result, "50122, 50123, 50124");
    }

    #[test]
    fn test_format_port_list_single() {
        let mut ports = HashSet::new();
        ports.insert(8080);

        let result = format_port_list(&ports);
        assert_eq!(result, "8080");
    }

    #[test]
    fn test_format_port_list_empty() {
        let ports = HashSet::new();
        let result = format_port_list(&ports);
        assert_eq!(result, "");
    }

    #[test]
    fn test_pf_firewall_creation() {
        let fw = PfFirewall::new();
        assert!(!fw.is_active());
        assert_eq!(fw.active_port_count(), 0);
    }

    #[test]
    fn test_detect_physical_interface() {
        // Should return something on macOS
        let iface = detect_physical_interface();
        assert!(iface.is_some(), "Should detect a physical interface");
        let iface = iface.unwrap();
        assert!(!iface.is_empty());
        // Common macOS interfaces
        assert!(
            iface.starts_with("en") || iface.starts_with("utun") || iface.starts_with("bridge"),
            "Unexpected interface: {}",
            iface
        );
    }
}
