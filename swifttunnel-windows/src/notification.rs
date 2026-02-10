//! Windows toast notifications
//!
//! Uses Windows Runtime (WinRT) for native Windows 10/11 style notifications.
//! Similar to Bloxstrap's server location notifications.

use std::path::Path;
use winrt_notification::{Duration, IconCrop, Sound, Toast};

/// SwiftTunnel's App User Model ID for Windows notifications.
/// Only works when the app is installed with a matching Start menu shortcut.
const SWIFTTUNNEL_AUMID: &str = "SwiftTunnel.GameBooster";

/// Check if our custom AUMID is registered (Start menu shortcut exists)
fn is_aumid_registered() -> bool {
    // Check for Start menu shortcut that registers our AUMID
    if let Some(appdata) = std::env::var_os("APPDATA") {
        let shortcut = Path::new(&appdata)
            .join(r"Microsoft\Windows\Start Menu\Programs\SwiftTunnel.lnk");
        if shortcut.exists() {
            return true;
        }
    }
    // Also check Program Files install marker
    Path::new(r"C:\Program Files\SwiftTunnel\swifttunnel.exe").exists()
}

/// Get the best AUMID for toast notifications.
/// Falls back to PowerShell's AUMID when our app isn't properly installed,
/// which ensures notifications actually appear (at the cost of showing
/// "Windows PowerShell" as the source instead of "SwiftTunnel").
fn get_aumid() -> &'static str {
    if is_aumid_registered() {
        SWIFTTUNNEL_AUMID
    } else {
        Toast::POWERSHELL_APP_ID
    }
}

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
    // Run on a background thread to avoid blocking the GUI thread
    let title = title.to_string();
    let message = message.to_string();
    std::thread::spawn(move || {
        let aumid = get_aumid();
        let mut toast = Toast::new(aumid)
            .title(&title)
            .text1(&message)
            .sound(Some(Sound::Default))
            .duration(Duration::Short);

        // Add icon if available (only when using our own AUMID)
        if aumid == SWIFTTUNNEL_AUMID {
            if let Some(icon_path) = get_icon_path() {
                toast = toast.icon(&icon_path, IconCrop::Square, "SwiftTunnel");
            }
        }

        match toast.show() {
            Ok(_) => log::debug!("Notification shown: {} - {}", title, message),
            Err(e) => log::warn!("Failed to show notification: {}", e),
        }
    });
}

/// Show a relay switch notification (auto-routing)
///
/// Only fires when the relay server ACTUALLY switches, not just on game server detection.
pub fn show_relay_switch(from_region: &str, to_region: &str, game_location: &str) {
    show_notification(
        "Auto Routing: Relay switched",
        &format!("{} → {} (game server: {})", from_region, to_region, game_location),
    );
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
