//! Windows toast notifications
//!
//! Uses Windows Runtime (WinRT) for native Windows 10/11 style notifications.
//! Similar to Bloxstrap's server location notifications.

#[cfg(windows)]
use std::path::Path;
#[cfg(windows)]
use tauri_winrt_notification::{Duration, IconCrop, Sound, Toast};

/// SwiftTunnel's App User Model ID for Windows notifications.
/// Registered on first use by `ensure_aumid_registered`, so it needs no
/// installer support and behaves the same in a dev run.
const SWIFTTUNNEL_AUMID: &str = "SwiftTunnel.GameBooster";

#[cfg(windows)]
#[derive(Debug, Clone, Copy)]
enum NotificationIcon {
    App,
    Swifty,
}

/// Register our AUMID so Windows knows what to call us on a toast.
///
/// Windows attributes a toast to whatever `DisplayName` is registered for the
/// notifying AUMID. This previously relied on the presence of a Start menu
/// shortcut and, finding none, fell back to PowerShell's AUMID — so every
/// connect and disconnect popped up branded "Windows PowerShell". Worse, the
/// shortcut was never a reliable signal either: the NSIS installer does not
/// stamp `System.AppUserModel.ID` onto it, so even a properly installed copy
/// was announcing itself with a AUMID Windows had no name for.
///
/// Writing the key ourselves fixes both, and works identically for a dev run
/// and an installed build. It is a per-user key under HKCU describing this
/// application's own notification identity — no elevation, nothing outside our
/// own registration.
#[cfg(windows)]
fn ensure_aumid_registered() -> bool {
    use winreg::RegKey;
    use winreg::enums::{HKEY_CURRENT_USER, KEY_WRITE};

    let hkcu = RegKey::predef(HKEY_CURRENT_USER);
    let path = format!(r"Software\Classes\AppUserModelId\{SWIFTTUNNEL_AUMID}");

    let key = match hkcu.create_subkey_with_flags(&path, KEY_WRITE) {
        Ok((key, _)) => key,
        Err(e) => {
            log::warn!("Could not register notification identity: {e}");
            return false;
        }
    };

    if let Err(e) = key.set_value("DisplayName", &"SwiftTunnel") {
        log::warn!("Could not set notification DisplayName: {e}");
        return false;
    }

    // Optional: the small logo beside the app name in the toast and in
    // Settings > Notifications. A missing icon is not worth failing over.
    if let Some(icon) = get_icon_path(NotificationIcon::App) {
        if let Some(icon) = icon.to_str() {
            let _ = key.set_value("IconUri", &icon);
        }
    }

    true
}

/// The AUMID to notify under, registering it on first use.
///
/// Registration is attempted once per process: it is idempotent, but it touches
/// the registry, and this runs on every connect and disconnect.
#[cfg(windows)]
fn get_aumid() -> &'static str {
    use std::sync::OnceLock;
    static REGISTERED: OnceLock<bool> = OnceLock::new();

    if *REGISTERED.get_or_init(ensure_aumid_registered) {
        SWIFTTUNNEL_AUMID
    } else {
        // Registration failed (locked-down profile, roaming policy). Showing
        // the toast under the wrong name still beats showing none at all.
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
