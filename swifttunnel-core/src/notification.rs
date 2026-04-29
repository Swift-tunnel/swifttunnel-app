//! Windows toast notifications
//!
//! Uses Windows Runtime (WinRT) for native Windows 10/11 style notifications.
//! Similar to Bloxstrap's server location notifications.

#[cfg(windows)]
use std::path::Path;
#[cfg(windows)]
use winrt_notification::{Duration, IconCrop, Sound, Toast};

/// SwiftTunnel's App User Model ID for Windows notifications.
/// Only works when the app is installed with a matching Start menu shortcut.
const SWIFTTUNNEL_AUMID: &str = "SwiftTunnel.GameBooster";

#[cfg(windows)]
#[derive(Debug, Clone, Copy)]
enum NotificationIcon {
    App,
    Swifty,
}

/// Check if our custom AUMID is registered (Start menu shortcut exists)
#[cfg(windows)]
fn is_aumid_registered() -> bool {
    // Check for Start menu shortcut that registers our AUMID
    if let Some(appdata) = std::env::var_os("APPDATA") {
        let shortcut =
            Path::new(&appdata).join(r"Microsoft\Windows\Start Menu\Programs\SwiftTunnel.lnk");
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
#[cfg(windows)]
fn get_aumid() -> &'static str {
    if is_aumid_registered() {
        SWIFTTUNNEL_AUMID
    } else {
        Toast::POWERSHELL_APP_ID
    }
}

/// Get the path to the SwiftTunnel icon
#[cfg(windows)]
fn get_icon_path(icon: NotificationIcon) -> Option<std::path::PathBuf> {
    let filename = match icon {
        NotificationIcon::App => "swifttunnel.ico",
        NotificationIcon::Swifty => "swifty.png",
    };

    // Try installed locations first.
    let installed_path = Path::new(r"C:\Program Files\SwiftTunnel").join(filename);
    if installed_path.exists() {
        return Some(installed_path);
    }

    let installed_resource_path = Path::new(r"C:\Program Files\SwiftTunnel")
        .join("resources")
        .join(filename);
    if installed_resource_path.exists() {
        return Some(installed_resource_path);
    }

    // Try relative to executable (for development)
    if let Ok(exe_path) = std::env::current_exe() {
        if let Some(exe_dir) = exe_path.parent() {
            let dev_path = exe_dir.join(filename);
            if dev_path.exists() {
                return Some(dev_path);
            }

            let resource_path = exe_dir.join("resources").join(filename);
            if resource_path.exists() {
                return Some(resource_path);
            }

            // Also try assets folder.
            let assets_path = exe_dir.join("assets").join(filename);
            if assets_path.exists() {
                return Some(assets_path);
            }
        }
    }

    log::debug!(
        "Notification icon {} not found in any expected location",
        filename
    );
    None
}

#[cfg(windows)]
fn show_notification_with_icon(title: &str, message: &str, icon: NotificationIcon) {
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

        if let Some(icon_path) = get_icon_path(icon) {
            toast = toast.icon(&icon_path, IconCrop::Square, "SwiftTunnel");
        }

        match toast.show() {
            Ok(_) => log::debug!("Notification shown: {} - {}", title, message),
            Err(e) => log::warn!("Failed to show notification: {}", e),
        }
    });
}

/// Show a Windows toast notification
///
/// # Arguments
/// * `title` - The notification title (e.g., "Connected to server")
/// * `message` - The notification body (e.g., "Location: Singapore, SG")
#[cfg(windows)]
pub fn show_notification(title: &str, message: &str) {
    show_notification_with_icon(title, message, NotificationIcon::App);
}

#[cfg(not(windows))]
pub fn show_notification(_title: &str, _message: &str) {}

/// Show a relay switch notification (auto-routing)
///
/// Only fires when the relay server ACTUALLY switches, not just on game server detection.
pub fn show_relay_switch(_from_region: &str, to_region: &str, game_location: &str) {
    let routed_region = crate::discord_rpc::region_display_label(to_region);
    let title = format!("Routed to {}", routed_region);
    let message = format!("Game server: {}", game_location);

    #[cfg(windows)]
    {
        show_notification_with_icon(&title, &message, NotificationIcon::Swifty);
    }

    #[cfg(not(windows))]
    {
        show_notification(&title, &message);
    }
}

/// Show a server location notification (Bloxstrap-style)
///
/// # Arguments
/// * `location` - The server location (e.g., "Singapore, SG")
pub fn show_server_location(location: &str) {
    show_notification("Connected to server", &format!("Location: {}", location));
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
