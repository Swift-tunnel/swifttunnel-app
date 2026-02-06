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
            "Split tunnel driver not installed.\n\nPlease reinstall SwiftTunnel or download the driver from:\nhttps://github.com/wiresock/ndisapi/releases".to_string()
        }

        VpnError::SplitTunnelSetupFailed(msg) => {
            if msg.contains("timed out") || msg.contains("timeout") {
                "Driver initialization timed out.\n\nPlease restart your computer and try again.".to_string()
            } else if msg.contains("administrator") || msg.contains("Administrator") || msg.contains("access denied") {
                "Administrator privileges required.\n\nPlease run SwiftTunnel as Administrator.".to_string()
            } else if msg.contains("internet interface") || msg.contains("No default gateway") {
                "No internet connection detected.\n\nPlease check your network connection and try again.".to_string()
            } else {
                format!("Split tunnel setup failed.\n\n{}", msg)
            }
        }

        // Adapter issues
        VpnError::AdapterCreate(msg) => {
            if msg.contains("Administrator") || msg.contains("privileges") {
                "Administrator privileges required.\n\nPlease run SwiftTunnel as Administrator.".to_string()
            } else if msg.contains("wintun.dll") {
                "Wintun driver not found.\n\nPlease reinstall SwiftTunnel to restore the driver.".to_string()
            } else if msg.contains("Failed to set IP") {
                "Failed to configure network adapter.\n\nTry disconnecting other network software and restarting your computer.".to_string()
            } else {
                format!("Failed to create network adapter.\n\n{}", simplify_message(msg))
            }
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

        // Tunnel issues
        VpnError::TunnelInit(msg) => {
            format!("Failed to initialize connection.\n\n{}", simplify_message(msg))
        }

        VpnError::HandshakeFailed(msg) => {
            if msg.contains("timeout") {
                "Connection timed out.\n\nThe server may be overloaded. Try a different server.".to_string()
            } else {
                "Connection handshake failed.\n\nPlease try connecting to a different server.".to_string()
            }
        }

        // Auth issues
        VpnError::NotAuthenticated => {
            "Not signed in.\n\nPlease sign in to continue.".to_string()
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
        VpnError::AdapterCreate(_) => "Adapter creation failed",
        VpnError::Route(_) => "Route setup failed",
        VpnError::Connection(_) => "Connection failed",
        VpnError::Network(_) => "Network error",
        VpnError::ConfigFetch(_) => "Config fetch failed",
        VpnError::InvalidConfig(_) => "Invalid config",
        VpnError::TunnelInit(_) => "Tunnel init failed",
        VpnError::HandshakeFailed(_) => "Handshake failed",
        VpnError::NotAuthenticated => "Not authenticated",
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
        assert!(msg.contains("Split tunnel driver not installed"));
    }

    #[test]
    fn test_user_friendly_timeout() {
        let error = VpnError::SplitTunnelSetupFailed("Driver timed out".to_string());
        let msg = user_friendly_error(&error);
        assert!(msg.contains("restart your computer"));
    }

    #[test]
    fn test_user_friendly_admin() {
        let error = VpnError::AdapterCreate("Administrator privileges required".to_string());
        let msg = user_friendly_error(&error);
        assert!(msg.contains("Administrator"));
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
}
