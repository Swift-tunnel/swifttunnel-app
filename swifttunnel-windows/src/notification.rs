//! Windows toast notifications
//!
//! Uses Windows Runtime (WinRT) for native Windows 10/11 style notifications.
//! Similar to Bloxstrap's server location notifications.

use std::path::Path;
use winrt_notification::{Duration, IconCrop, Sound, Toast};

/// SwiftTunnel's App User Model ID for Windows notifications
/// This allows Windows to display "SwiftTunnel" as the notification source
const SWIFTTUNNEL_AUMID: &str = "SwiftTunnel.GameBooster";

/// Get the path to the SwiftTunnel icon
fn get_icon_path() -> Option<std::path::PathBuf> {
    // Try installed location first
    let installed_path = Path::new(r"C:\Program Files\SwiftTunnel\swifttunnel.ico");
    if installed_path.exists() {
        return Some(installed_path.to_path_buf());
    }

    // Try relative to executable (for development)
    if let Ok(exe_path) = std::env::current_exe() {
        if let Some(exe_dir) = exe_path.parent() {
            let dev_path = exe_dir.join("swifttunnel.ico");
            if dev_path.exists() {
                return Some(dev_path);
            }
            // Also try assets folder
            let assets_path = exe_dir.join("assets").join("swifttunnel.ico");
            if assets_path.exists() {
                return Some(assets_path);
            }
        }
    }

    log::debug!("Notification icon not found in any expected location");
    None
}

/// Show a Windows toast notification
///
/// # Arguments
/// * `title` - The notification title (e.g., "Connected to server")
/// * `message` - The notification body (e.g., "Location: Singapore, SG")
pub fn show_notification(title: &str, message: &str) {
    let mut toast = Toast::new(SWIFTTUNNEL_AUMID)
        .title(title)
        .text1(message)
        .sound(Some(Sound::Default))
        .duration(Duration::Short);

    // Add icon if available
    if let Some(icon_path) = get_icon_path() {
        toast = toast.icon(&icon_path, IconCrop::Square, "SwiftTunnel");
    }

    let result = toast.show();

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
