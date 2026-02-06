//! macOS notifications
//!
//! Uses mac-notification-sys for native macOS notification center support.

use mac_notification_sys::*;

/// Show a macOS notification via Notification Center
///
/// # Arguments
/// * `title` - The notification title (e.g., "Connected to server")
/// * `message` - The notification body (e.g., "Location: Singapore, SG")
pub fn show_notification(title: &str, message: &str) {
    let bundle = get_bundle_identifier_or_default("com.swifttunnel.app");
    if let Err(e) = set_application(&bundle) {
        log::debug!("Could not set notification bundle: {}", e);
    }

    // Build notification options with default sound
    let mut options = Notification::new();
    options.sound(Sound::Default);

    let result = send_notification(
        title,
        Some("SwiftTunnel"),   // subtitle
        message,
        Some(&options),
    );

    match result {
        Ok(_) => log::debug!("Notification shown: {} - {}", title, message),
        Err(e) => log::warn!("Failed to show notification: {}", e),
    }
}

/// Show a server location notification (Bloxstrap-style)
///
/// # Arguments
/// * `location` - The server location (e.g., "Singapore, SG")
pub fn show_server_location(location: &str) {
    show_notification(
        "Connected to server",
        &format!("Location: {}", location),
    );
}

/// Show a VPN connected notification
pub fn show_vpn_connected(region: &str) {
    show_notification(
        "VPN Connected",
        &format!("Connected to {} server", region),
    );
}

/// Show a VPN disconnected notification
pub fn show_vpn_disconnected() {
    show_notification(
        "VPN Disconnected",
        "Your connection has been restored to normal",
    );
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    #[ignore] // Requires macOS with notification support
    fn test_show_notification() {
        show_notification("Test", "This is a test notification");
    }
}
