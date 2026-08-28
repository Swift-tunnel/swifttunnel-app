//! Registering a client to start with Windows.
//!
//! Shared, because both clients offer the switch and there is nothing about
//! writing a registry value that either should have its own version of.
//!
//! # Why the value name is a parameter
//!
//! The two clients are separate executables, so the Run entry has to name one
//! of them. They write under different names, which means enabling the switch
//! in Lite starts Lite and enabling it in the full app starts the full app,
//! rather than the two overwriting each other's path under a shared key every
//! time one of them launches.
//!
//! The saved setting is still shared, so turning it on in one turns the switch
//! on in the other's UI too. If both end up registered, the single-client lock
//! sorts it out: the second to launch focuses the first and exits.

use std::path::Path;

/// Passed to a client started by Windows at sign-in, so it can come up quietly.
pub const STARTUP_FLAG: &str = "--startup";

/// Where Windows looks for things to start at sign-in.
pub const RUN_KEY_PATH: &str = "Software\\Microsoft\\Windows\\CurrentVersion\\Run";

/// The Run entry the full app registers under.
pub const RUN_VALUE_APP: &str = "SwiftTunnel";
/// The Run entry SwiftTunnel Lite registers under.
pub const RUN_VALUE_LITE: &str = "SwiftTunnelLite";

#[cfg(windows)]
fn startup_command_for_exe(exe_path: &Path) -> String {
    format!("\"{}\" {}", exe_path.display(), STARTUP_FLAG)
}

/// Add or remove this executable's Run entry.
#[cfg(windows)]
pub fn sync_run_on_startup(value_name: &str, enabled: bool) -> Result<(), String> {
    use std::io::ErrorKind;
    use winreg::RegKey;
    use winreg::enums::HKEY_CURRENT_USER;

    let hkcu = RegKey::predef(HKEY_CURRENT_USER);
    let (run_key, _) = hkcu
        .create_subkey(RUN_KEY_PATH)
        .map_err(|e| format!("Failed to open startup registry key: {}", e))?;

    if enabled {
        let exe_path =
            std::env::current_exe().map_err(|e| format!("Failed to resolve executable: {}", e))?;
        let command = startup_command_for_exe(&exe_path);
        run_key
            .set_value(value_name, &command)
            .map_err(|e| format!("Failed to set startup registry value: {}", e))?;
    } else if let Err(e) = run_key.delete_value(value_name)
        && e.kind() != ErrorKind::NotFound
    {
        return Err(format!("Failed to remove startup registry value: {}", e));
    }

    Ok(())
}

#[cfg(not(windows))]
pub fn sync_run_on_startup(_value_name: &str, _enabled: bool) -> Result<(), String> {
    Ok(())
}

/// Whether Windows started this process at sign-in.
pub fn launched_from_startup_flag() -> bool {
    std::env::args().any(|arg| arg == STARTUP_FLAG)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(windows)]
    #[test]
    fn startup_command_quotes_exe_path_and_appends_flag() {
        let cmd =
            startup_command_for_exe(Path::new("C:\\Program Files\\SwiftTunnel\\SwiftTunnel.exe"));
        assert!(cmd.starts_with("\"C:\\Program Files\\SwiftTunnel\\SwiftTunnel.exe\""));
        assert!(cmd.ends_with("--startup"));
    }

    #[test]
    fn the_two_clients_register_under_different_names() {
        // If these ever collide, enabling the switch in one client silently
        // repoints the other's Run entry at the wrong executable.
        assert_ne!(RUN_VALUE_APP, RUN_VALUE_LITE);
    }
}

/// Remove every SwiftTunnel Run entry, whichever client wrote it.
///
/// For uninstall. The entries are written by the clients at runtime rather than
/// by the installer, so Windows Installer does not know they exist and will not
/// take them away: without this, uninstalling leaves one or two startup entries
/// pointing at an executable that is no longer there. Windows fails them
/// silently at sign-in, so nobody reports it, but the litter is real and it is
/// two values.
///
/// Best effort, and deliberately not an error when there is nothing to remove:
/// this runs during uninstall, where failing loudly buys nothing.
#[cfg(windows)]
pub fn remove_all_run_entries() {
    use std::io::ErrorKind;
    use winreg::RegKey;
    use winreg::enums::{HKEY_CURRENT_USER, KEY_SET_VALUE};

    let hkcu = RegKey::predef(HKEY_CURRENT_USER);
    let Ok(run_key) = hkcu.open_subkey_with_flags(RUN_KEY_PATH, KEY_SET_VALUE) else {
        return;
    };

    for value in [RUN_VALUE_APP, RUN_VALUE_LITE] {
        match run_key.delete_value(value) {
            Ok(()) => log::info!("removed the {value} startup entry"),
            Err(e) if e.kind() == ErrorKind::NotFound => {}
            Err(e) => log::warn!("could not remove the {value} startup entry: {e}"),
        }
    }
}

#[cfg(not(windows))]
pub fn remove_all_run_entries() {}
