use std::path::Path;

use tauri::AppHandle;

const STARTUP_FLAG: &str = "--startup";
const RUN_KEY_PATH: &str = "Software\\Microsoft\\Windows\\CurrentVersion\\Run";
const RUN_VALUE_NAME: &str = "SwiftTunnel";

#[cfg(windows)]
fn startup_command_for_exe(exe_path: &Path) -> String {
    format!("\"{}\" {}", exe_path.display(), STARTUP_FLAG)
}

#[cfg(windows)]
pub fn sync_run_on_startup(_app: &AppHandle, enabled: bool) -> Result<(), String> {
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
            .set_value(RUN_VALUE_NAME, &command)
            .map_err(|e| format!("Failed to set startup registry value: {}", e))?;
    } else if let Err(e) = run_key.delete_value(RUN_VALUE_NAME) {
        if e.kind() != ErrorKind::NotFound {
            return Err(format!("Failed to remove startup registry value: {}", e));
        }
    }

    Ok(())
}

#[cfg(not(windows))]
pub fn sync_run_on_startup(_app: &AppHandle, _enabled: bool) -> Result<(), String> {
    Ok(())
}

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
}
