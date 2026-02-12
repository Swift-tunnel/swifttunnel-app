use serde::Serialize;
#[cfg(windows)]
use std::path::PathBuf;
#[cfg(windows)]
use std::process::Command;

#[derive(Serialize)]
pub struct AdminCheckResponse {
    pub is_admin: bool,
}

#[tauri::command]
pub fn system_is_admin() -> AdminCheckResponse {
    AdminCheckResponse {
        is_admin: swifttunnel_core::is_administrator(),
    }
}

#[derive(Serialize)]
pub struct DriverCheckResponse {
    pub installed: bool,
    pub version: Option<String>,
}

#[tauri::command]
pub fn system_check_driver() -> DriverCheckResponse {
    #[cfg(windows)]
    {
        let available = swifttunnel_core::vpn::SplitTunnelDriver::is_available();
        DriverCheckResponse {
            installed: available,
            version: if available {
                Some("Windows Packet Filter".to_string())
            } else {
                None
            },
        }
    }

    #[cfg(not(windows))]
    {
        DriverCheckResponse {
            installed: false,
            version: None,
        }
    }
}

#[tauri::command]
pub fn system_install_driver() -> Result<(), String> {
    #[cfg(windows)]
    {
        let msi_paths = [
            std::env::current_exe().ok().and_then(|p| {
                p.parent()
                    .map(|d| d.join("drivers").join("WinpkFilter-x64.msi"))
            }),
            Some(PathBuf::from(
                r"C:\Program Files\SwiftTunnel\drivers\WinpkFilter-x64.msi",
            )),
        ];

        let msi_path = msi_paths
            .iter()
            .flatten()
            .find(|p| p.exists())
            .ok_or_else(|| {
                "WinpkFilter-x64.msi not found. Reinstall SwiftTunnel or run the bundled installer."
                    .to_string()
            })?;

        let output = Command::new("msiexec")
            .args(["/i", &msi_path.to_string_lossy(), "/passive", "/norestart"])
            .output()
            .map_err(|e| format!("Failed to run msiexec: {}", e))?;

        if output.status.success() {
            return Ok(());
        }

        let code = output.status.code().unwrap_or(-1);
        if code == 1638 {
            // Another version already installed.
            return Ok(());
        }

        let stderr = String::from_utf8_lossy(&output.stderr);
        Err(format!(
            "Driver install failed with code {}: {}",
            code, stderr
        ))
    }

    #[cfg(not(windows))]
    {
        Err("Driver installation is only supported on Windows".to_string())
    }
}

#[tauri::command]
pub fn system_open_url(url: String) -> Result<(), String> {
    swifttunnel_core::utils::open_url(&url);
    Ok(())
}
