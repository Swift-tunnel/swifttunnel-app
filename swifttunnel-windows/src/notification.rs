//! Windows toast notifications
//!
//! Uses Windows Runtime (WinRT) for native Windows 10/11 style notifications.
//! Similar to Bloxstrap's server location notifications.

use winrt_notification::{Duration, Sound, Toast};

/// Show a Windows toast notification
///
/// # Arguments
/// * `title` - The notification title (e.g., "Connected to server")
/// * `message` - The notification body (e.g., "Location: Singapore, SG")
pub fn show_notification(title: &str, message: &str) {
    // Use SwiftTunnel as the app identifier
    // Note: For proper notifications, the app should be registered with a valid AUMID
    // For now, we use PowerShell's AUMID as a fallback which works for development
    let result = Toast::new(Toast::POWERSHELL_APP_ID)
        .title(title)
        .text1(message)
        .sound(Some(Sound::Default))
        .duration(Duration::Short)
        .show();

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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    #[ignore] // Requires Windows with notification support
    fn test_show_notification() {
        show_notification("Test", "This is a test notification");
    }
}
