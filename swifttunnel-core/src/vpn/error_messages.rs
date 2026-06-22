//! User-Friendly Error Messages
//!
//! Converts technical errors into human-readable messages suitable for display
//! in the GUI. These messages guide users toward solutions rather than exposing
//! raw Windows error codes.

use super::VpnError;

/// Convert a VPN error into a user-friendly message
///
/// Returns a clear, actionable message that helps users understand
/// what went wrong and how to fix it.
pub fn user_friendly_error(error: &VpnError) -> String {
    match error {
        // Split tunnel driver issues
        VpnError::SplitTunnelNotAvailable => {
            "SwiftTunnel could not start its Windows Packet Filter driver.\n\nSwiftTunnel will try to repair this automatically. If this message returns, restart Windows once and contact support with your log file.".to_string()
        }

        VpnError::SplitTunnelSetupFailed(msg) => {
            let lc = msg.to_lowercase();
            if lc.contains("ipv6-only") {
                "SwiftTunnel needs IPv4 connectivity to tunnel game traffic. Your network appears to be IPv6-only and is not supported.\n\nIf you're on a mobile hotspot or carrier network, ask your ISP to enable IPv4 (NAT64/DS-Lite is not enough) or switch to a different network.".to_string()
            } else if lc.contains("timed out") || lc.contains("timeout") {
                "Driver initialization timed out.\n\nPlease restart your computer and try again.".to_string()
            } else if lc.contains("administrator")
                || lc.contains("access denied")
                || lc.contains("access is denied")
            {
                admin_or_access_denied_message(crate::utils::is_administrator())
            } else if is_winpkfilter_reboot_error(&lc) {
                "Restart Windows to finish setting up SwiftTunnel's network filter, then connect again.\n\nIf this still appears after restarting, contact support with your log file.".to_string()
            } else if is_winpkfilter_repairable_setup_error(&lc) {
                "SwiftTunnel could not finish setting up the Windows Packet Filter driver for your active network adapter.\n\nSwiftTunnel tried to repair this automatically. Restart Windows once, then connect again. If it still fails, contact support with your log file.".to_string()
            } else if is_windows_firewall_setup_error(&lc) {
                "Windows Firewall commands are unavailable, so SwiftTunnel could not finish its IPv6 safety setup.\n\nSwiftTunnel tried to repair this automatically. Restart Windows once, then connect again. If it still fails, contact support with your log file.".to_string()
            } else if lc.contains("no ndis adapter matched the default-route interface index") {
                "SwiftTunnel couldn't detect your active network adapter for split tunneling.\n\nGo to Settings -> VPN -> Network Adapter, select your Wi-Fi/Ethernet adapter, then reconnect.\n\nThis can happen if another VPN, network bridge, or virtual adapter owns the default route.".to_string()
            } else if lc.contains("winpkfilter_binding_missing")
                || (lc.contains("nt_ndisrd") && lc.contains("not bound to adapter"))
            {
                "SwiftTunnel could not attach its network filter to the active adapter.\n\nSwiftTunnel tried to repair this automatically. Restart Windows once, then connect again. If it still fails, contact support with your log file.".to_string()
            } else if lc.contains("internet interface") || lc.contains("no default gateway") {
                "No internet connection detected.\n\nPlease check your network connection and try again.".to_string()
            } else {
                format!("Split tunnel setup failed.\n\n{}", msg)
            }
        }

        VpnError::DriverNotOpen => {
            "Split tunnel driver not open.\n\nPlease try reconnecting.".to_string()
        }

        VpnError::DriverNotInitialized => {
            "Split tunnel driver not initialized.\n\nPlease try reconnecting.".to_string()
        }

        // Route issues
        VpnError::Route(msg) => {
            if msg.contains("No default gateway") || msg.contains("no gateway") {
                "No internet connection detected.\n\nPlease check your network connection.".to_string()
            } else if msg.contains("PowerShell") || msg.contains("powershell") {
                "Network configuration failed.\n\nPlease ensure PowerShell is available on your system.".to_string()
            } else {
                format!("Failed to configure game routes.\n\n{}", simplify_message(msg))
            }
        }

        // Connection issues
        VpnError::Connection(msg) => {
            if msg.contains("Already connected") {
                "Already connected.".to_string()
            } else if msg.contains("in progress") {
                "Connection in progress. Please wait.".to_string()
            } else {
                format!("Connection failed.\n\n{}", simplify_message(msg))
            }
        }

        // Network issues
        VpnError::Network(msg) => {
            if msg.contains("timeout") || msg.contains("timed out") {
                "Connection timed out.\n\nPlease check your internet connection and try again.".to_string()
            } else if msg.contains("DNS") || msg.contains("resolve") {
                "DNS lookup failed.\n\nPlease check your internet connection.".to_string()
            } else {
                format!("Network error.\n\n{}", simplify_message(msg))
            }
        }

        // Config issues
        VpnError::ConfigFetch(msg) => {
            if msg.contains("401") || msg.contains("Unauthorized") || msg.contains("unauthorized") {
                "Session expired.\n\nPlease sign out and sign in again.".to_string()
            } else if msg.contains("404") || msg.contains("Not Found") {
                "Server not found.\n\nThe selected region may be temporarily unavailable.".to_string()
            } else if msg.contains("timeout") {
                "Failed to reach server.\n\nPlease check your internet connection.".to_string()
            } else {
                format!("Failed to get configuration.\n\n{}", simplify_message(msg))
            }
        }

        VpnError::InvalidConfig(msg) => {
            format!("Invalid configuration.\n\n{}", simplify_message(msg))
        }

        // Auth issues
        VpnError::NotAuthenticated => {
            "Not signed in.\n\nPlease sign in to continue.".to_string()
        }

        VpnError::UserBanned(reason) => {
            if reason.is_empty() {
                "This account is banned.".to_string()
            } else {
                format!("This account is banned{}.", reason)
            }
        }

        // Split tunnel generic
        VpnError::SplitTunnel(msg) => {
            format!("Split tunnel error.\n\n{}", simplify_message(msg))
        }

        // IO errors
        VpnError::Io(e) => {
            format!("System error.\n\n{}", e)
        }
    }
}

fn is_winpkfilter_reboot_error(lowercase_msg: &str) -> bool {
    lowercase_msg.contains("reboot required to finish driver installation")
        || lowercase_msg.contains("marked for deletion")
        || (lowercase_msg.contains("reboot") && lowercase_msg.contains("driver"))
}

fn is_winpkfilter_repairable_setup_error(lowercase_msg: &str) -> bool {
    (lowercase_msg.contains("failed to ensure winpkfilter binding")
        || lowercase_msg.contains("winpkfilter binding validation failed")
        || lowercase_msg.contains("split tunnel driver binding is missing")
        || (lowercase_msg.contains("split tunnel driver not available")
            && lowercase_msg.contains("windows packet filter driver"))
        || (lowercase_msg.contains("failed to open") && lowercase_msg.contains("ndisrd"))
        || lowercase_msg.contains("no tcp/ip-bound network adapters")
        || lowercase_msg.contains("version query failed")
        || lowercase_msg.contains("installed but ioctl failed")
        || lowercase_msg.contains("get_tcpip_bound_adapters_info")
        || lowercase_msg.contains("windows packet filter driver did not become available")
        || (lowercase_msg.contains("driver service") && lowercase_msg.contains("reset")))
        && !lowercase_msg.contains("administrator privileges required")
        && !lowercase_msg.contains("access denied")
        && !lowercase_msg.contains("access is denied")
}

fn is_windows_firewall_setup_error(lowercase_msg: &str) -> bool {
    (lowercase_msg.contains("advfirewall")
        || lowercase_msg.contains("windows firewall")
        || lowercase_msg.contains("base filtering engine")
        || lowercase_msg.contains("mpssvc")
        || lowercase_msg.contains("ipv6 block firewall rule"))
        && !lowercase_msg.contains("administrator privileges required")
        && !lowercase_msg.contains("access denied")
        && !lowercase_msg.contains("access is denied")
}

fn admin_or_access_denied_message(is_admin: bool) -> String {
    if is_admin {
        "Windows blocked SwiftTunnel's split-tunnel driver access even though SwiftTunnel is elevated.\n\nRestart Windows once so the driver service can reload cleanly. If it still fails, contact support with your log file.".to_string()
    } else {
        "Administrator privileges required.\n\nPlease run SwiftTunnel as Administrator.".to_string()
    }
}

/// Simplify a technical message by removing error codes and hex values
fn simplify_message(msg: &str) -> String {
    // Remove common Windows error code patterns
    let simplified = msg
        .replace("0x80070001", "invalid function")
        .replace("0x80320009", "already exists")
        .replace("0x80320007", "not found")
        .replace("0x80320027", "provider not found")
        .replace("0x80320004", "not found")
        .replace("0x80320001", "does not exist");

    // Remove long hex codes like "0x8007xxxx"
    use std::sync::OnceLock;
    static RE_HEX: OnceLock<regex_lite::Regex> = OnceLock::new();
    let re = RE_HEX.get_or_init(|| regex_lite::Regex::new(r"0x[0-9a-fA-F]{8}").unwrap());
    let result = re.replace_all(&simplified, "[error]").to_string();

    // Truncate if too long
    if result.len() > 200 {
        format!("{}...", &result[..197])
    } else {
        result
    }
}

/// Convert an error to a short status message (for status bars)
pub fn short_error(error: &VpnError) -> &'static str {
    match error {
        VpnError::SplitTunnelNotAvailable => "Driver not installed",
        VpnError::SplitTunnelSetupFailed(_) => "Split tunnel failed",
        VpnError::DriverNotOpen => "Driver not open",
        VpnError::DriverNotInitialized => "Driver not initialized",
        VpnError::Route(_) => "Route setup failed",
        VpnError::Connection(_) => "Connection failed",
        VpnError::Network(_) => "Network error",
        VpnError::ConfigFetch(_) => "Config fetch failed",
        VpnError::InvalidConfig(_) => "Invalid config",
        VpnError::NotAuthenticated => "Not authenticated",
        VpnError::UserBanned(_) => "Account banned",
        VpnError::SplitTunnel(_) => "Split tunnel error",
        VpnError::Io(_) => "System error",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_user_friendly_split_tunnel_not_available() {
        let error = VpnError::SplitTunnelNotAvailable;
        let msg = user_friendly_error(&error);
        assert!(msg.contains("Windows Packet Filter driver"));
        assert!(msg.contains("repair this automatically"));
        assert!(!msg.contains("repair button"));
    }

    #[test]
    fn test_user_friendly_plain_binding_missing_does_not_send_user_to_repair() {
        let error = VpnError::SplitTunnelSetupFailed(
            "Split tunnel driver binding is missing on the active network adapter. SwiftTunnel can repair this automatically. Use Repair driver, then reconnect.".to_string(),
        );
        let msg = user_friendly_error(&error);
        assert!(msg.contains("active network adapter"));
        assert!(msg.contains("tried to repair this automatically"));
        assert!(msg.contains("Restart Windows"));
        assert!(!msg.contains("Use Repair"));
    }

    #[test]
    fn test_user_friendly_elevated_access_denied_does_not_send_user_to_repair() {
        let msg = admin_or_access_denied_message(true);
        assert!(msg.contains("driver access"));
        assert!(msg.contains("Restart Windows"));
        assert!(msg.contains("contact support"));
        assert!(!msg.contains("Repair ->"));
    }

    #[test]
    fn test_user_friendly_access_denied_requires_admin_when_not_elevated() {
        let msg = admin_or_access_denied_message(false);
        assert!(msg.contains("Administrator privileges required"));
    }

    #[test]
    fn test_user_friendly_legacy_driver_not_available_text_is_concise() {
        let error = VpnError::SplitTunnelSetupFailed(
            "Split tunnel driver not available - please install Windows Packet Filter driver"
                .to_string(),
        );
        let msg = user_friendly_error(&error);
        assert!(msg.contains("Windows Packet Filter driver"));
        assert!(msg.contains("tried to repair this automatically"));
        assert!(!msg.contains("please install"));
    }

    #[test]
    fn test_user_friendly_timeout() {
        let error = VpnError::SplitTunnelSetupFailed("Driver timed out".to_string());
        let msg = user_friendly_error(&error);
        assert!(msg.contains("restart your computer"));
    }

    #[test]
    fn test_user_friendly_admin_required() {
        let msg = admin_or_access_denied_message(false);
        assert!(msg.contains("Administrator privileges required"));
    }

    #[test]
    fn test_user_friendly_access_denied_while_elevated() {
        let msg = admin_or_access_denied_message(true);
        assert!(msg.contains("driver access"));
        assert!(msg.contains("Restart Windows"));
        assert!(!msg.contains("Please run SwiftTunnel as Administrator"));
    }

    #[test]
    fn test_user_friendly_default_route_adapter_mismatch_guides_to_picker() {
        let error = VpnError::SplitTunnelSetupFailed(
            "Failed to configure V3 split tunnel: Split tunnel driver error: No NDIS adapter matched the default-route interface index 54.".to_string(),
        );
        let msg = user_friendly_error(&error);
        assert!(msg.contains("Settings"));
        assert!(msg.contains("Network Adapter"));
    }

    #[test]
    fn test_user_friendly_winpkfilter_binding_missing_is_concise() {
        let error = VpnError::SplitTunnelSetupFailed(
            "Failed to configure V3 split tunnel: Split tunnel driver error: winpkfilter_binding_missing: nt_ndisrd is not bound to adapter 'Ethernet'.".to_string(),
        );
        let msg = user_friendly_error(&error);
        assert!(msg.contains("network filter"));
        assert!(msg.contains("Restart Windows"));
        assert!(!msg.contains("Failed to configure V3 split tunnel"));
    }

    #[test]
    fn test_user_friendly_winpkfilter_setup_failure_is_concise() {
        let error = VpnError::SplitTunnelSetupFailed(
            "Failed to configure V3 split tunnel: Split tunnel driver error: Failed to ensure WinpkFilter binding on adapter 'Ethernet': PowerShell failed.".to_string(),
        );
        let msg = user_friendly_error(&error);
        assert!(msg.contains("Windows Packet Filter driver"));
        assert!(msg.contains("repair"));
        assert!(!msg.contains("Failed to configure V3 split tunnel"));
    }

    #[test]
    fn test_user_friendly_no_tcpip_bound_adapters_is_concise() {
        let error = VpnError::SplitTunnelSetupFailed(
            "Split tunnel driver not available (Windows Packet Filter driver): no TCP/IP-bound network adapters were enumerated. Reset the driver service, then try again.".to_string(),
        );
        let msg = user_friendly_error(&error);
        assert!(msg.contains("Windows Packet Filter driver"));
        assert!(msg.contains("Restart Windows"));
        assert!(!msg.contains("no TCP/IP-bound network adapters"));
    }

    #[test]
    fn test_user_friendly_advfirewall_failure_points_to_firewall_repair() {
        let error = VpnError::SplitTunnelSetupFailed(
            "Failed to install IPv6 block firewall rule: The following command was not found: advfirewall firewall add rule.".to_string(),
        );
        let msg = user_friendly_error(&error);
        assert!(msg.contains("Windows Firewall"));
        assert!(msg.contains("tried to repair this automatically"));
        assert!(!msg.contains("advfirewall firewall add rule"));
    }

    #[test]
    fn test_user_friendly_reboot_driver_failure_is_concise() {
        let error = VpnError::SplitTunnelSetupFailed(
            "Reboot required to finish driver installation. Windows signaled exit 3010 and the post-install self-test failed.".to_string(),
        );
        let msg = user_friendly_error(&error);
        assert!(msg.contains("Restart Windows"));
        assert!(!msg.contains("3010"));
    }

    #[test]
    fn test_simplify_message() {
        let msg = simplify_message("Error 0x80070001 occurred");
        assert!(msg.contains("invalid function"));
        assert!(!msg.contains("0x80070001"));
    }

    #[test]
    fn test_short_error() {
        let error = VpnError::NotAuthenticated;
        assert_eq!(short_error(&error), "Not authenticated");
    }

    #[test]
    fn test_user_friendly_user_banned() {
        let error = VpnError::UserBanned(": abuse".to_string());
        let msg = user_friendly_error(&error);
        assert_eq!(msg, "This account is banned: abuse.");
        assert_eq!(short_error(&error), "Account banned");
    }
}
