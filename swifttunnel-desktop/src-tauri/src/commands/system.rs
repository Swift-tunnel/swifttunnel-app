use serde::Serialize;
#[cfg(windows)]
use std::path::PathBuf;

#[cfg(windows)]
use tauri::Manager;

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
pub fn system_install_driver(app: tauri::AppHandle) -> Result<(), String> {
    #[cfg(windows)]
    {
        fn is_success_code(code: i32) -> bool {
            // 0 = success
            // 1638 = another version already installed
            // 1641/3010 = success, restart required
            matches!(code, 0 | 1638 | 1641 | 3010)
        }

        if swifttunnel_core::vpn::SplitTunnelDriver::is_available() {
            return Ok(());
        }

        let resource_dir = app.path().resource_dir().ok();
        let exe_dir = std::env::current_exe()
            .ok()
            .and_then(|p| p.parent().map(|d| d.to_path_buf()));

        let mut candidates: Vec<PathBuf> = Vec::new();

        if let Some(ref dir) = resource_dir {
            candidates.push(dir.join("drivers").join("WinpkFilter-x64.msi"));
            candidates.push(dir.join("WinpkFilter-x64.msi"));
        }

        if let Some(ref dir) = exe_dir {
            candidates.push(dir.join("drivers").join("WinpkFilter-x64.msi"));
            candidates.push(
                dir.join("resources")
                    .join("drivers")
                    .join("WinpkFilter-x64.msi"),
            );
            candidates.push(dir.join("resources").join("WinpkFilter-x64.msi"));
        }

        // Hard fallbacks for typical installs.
        let program_files =
            std::env::var("ProgramFiles").unwrap_or_else(|_| "C:\\Program Files".to_string());
        let install_root = PathBuf::from(program_files).join("SwiftTunnel");
        candidates.push(
            install_root
                .join("resources")
                .join("drivers")
                .join("WinpkFilter-x64.msi"),
        );
        candidates.push(install_root.join("drivers").join("WinpkFilter-x64.msi"));

        let msi_path = candidates.into_iter().find(|p| p.exists()).ok_or_else(|| {
            "WinpkFilter-x64.msi not found in app resources. Reinstall SwiftTunnel.".to_string()
        })?;

        let msi_string = msi_path.to_string_lossy().to_string();

        // If we are elevated already, run msiexec directly and capture output.
        // Otherwise, use Start-Process -Verb RunAs to trigger a UAC prompt.
        let exit_code = if swifttunnel_core::is_administrator() {
            let output = swifttunnel_core::hidden_command("msiexec")
                .args(["/i", &msi_string, "/passive", "/norestart"])
                .output()
                .map_err(|e| format!("Failed to run msiexec: {}", e))?;
            output.status.code().unwrap_or(-1)
        } else {
            // PowerShell single-quote escaping.
            let escaped_msi = msi_string.replace('\'', "''");
            let script = format!(
                "$ErrorActionPreference='Stop'; \
                 $p=Start-Process -FilePath 'msiexec.exe' -Verb RunAs -ArgumentList @('/i','{escaped_msi}','/passive','/norestart') -Wait -PassThru; \
                 exit $p.ExitCode"
            );

            let output = swifttunnel_core::hidden_command("powershell")
                .args(["-NoProfile", "-Command", &script])
                .output()
                .map_err(|e| format!("Failed to invoke elevated installer: {}", e))?;

            output.status.code().unwrap_or(-1)
        };

        if !is_success_code(exit_code) {
            return Err(format!("Driver install failed with code {}", exit_code));
        }

        // Post-install: poll driver availability briefly so the UI can proceed immediately.
        for _ in 0..10 {
            if swifttunnel_core::vpn::SplitTunnelDriver::is_available() {
                return Ok(());
            }
            std::thread::sleep(std::time::Duration::from_millis(500));
        }

        Err(
            "Driver installation completed, but the driver is still not available. Please reboot and try again."
                .to_string(),
        )
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
