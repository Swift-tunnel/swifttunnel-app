use serde::Serialize;
#[cfg(windows)]
use std::path::{Path, PathBuf};

#[cfg(windows)]
use tauri::Manager;

#[cfg(windows)]
fn driver_install_success_exit_code(code: i32) -> bool {
    // 0 = success
    // 1638 = another version already installed
    // 1641/3010 = success, restart required
    matches!(code, 0 | 1638 | 1641 | 3010)
}

#[cfg(windows)]
fn winpkfilter_msi_candidate_paths(
    resource_dir: Option<&Path>,
    exe_dir: Option<&Path>,
    program_files_dir: &Path,
) -> Vec<PathBuf> {
    let mut candidates: Vec<PathBuf> = Vec::new();

    if let Some(dir) = resource_dir {
        candidates.push(dir.join("drivers").join("WinpkFilter-x64.msi"));
        candidates.push(dir.join("WinpkFilter-x64.msi"));
    }

    if let Some(dir) = exe_dir {
        candidates.push(dir.join("drivers").join("WinpkFilter-x64.msi"));
        candidates.push(
            dir.join("resources")
                .join("drivers")
                .join("WinpkFilter-x64.msi"),
        );
        candidates.push(dir.join("resources").join("WinpkFilter-x64.msi"));
    }

    // Hard fallbacks for typical installs.
    let install_root = program_files_dir.join("SwiftTunnel");
    candidates.push(
        install_root
            .join("resources")
            .join("drivers")
            .join("WinpkFilter-x64.msi"),
    );
    candidates.push(install_root.join("drivers").join("WinpkFilter-x64.msi"));

    candidates
}

#[cfg(windows)]
fn find_winpkfilter_msi(
    resource_dir: Option<&Path>,
    exe_dir: Option<&Path>,
    program_files_dir: &Path,
) -> Result<PathBuf, String> {
    let candidates = winpkfilter_msi_candidate_paths(resource_dir, exe_dir, program_files_dir);
    candidates.into_iter().find(|p| p.exists()).ok_or_else(|| {
        "WinpkFilter-x64.msi not found in app resources. Reinstall SwiftTunnel.".to_string()
    })
}

#[cfg(windows)]
fn build_elevated_msiexec_script(msi_path: &str) -> String {
    // PowerShell single-quote escaping.
    let escaped_msi = msi_path.replace('\'', "''");
    format!(
        "$ErrorActionPreference='Stop'; \
         $p=Start-Process -FilePath 'msiexec.exe' -Verb RunAs -ArgumentList @('/i','{escaped_msi}','/passive','/norestart') -Wait -PassThru; \
         exit $p.ExitCode"
    )
}

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
        if swifttunnel_core::vpn::SplitTunnelDriver::is_available() {
            return Ok(());
        }

        let resource_dir = app.path().resource_dir().ok();
        let exe_dir = std::env::current_exe()
            .ok()
            .and_then(|p| p.parent().map(|d| d.to_path_buf()));

        let program_files =
            std::env::var("ProgramFiles").unwrap_or_else(|_| "C:\\Program Files".to_string());
        let program_files_dir = PathBuf::from(program_files);
        let msi_path = find_winpkfilter_msi(
            resource_dir.as_deref(),
            exe_dir.as_deref(),
            &program_files_dir,
        )?;

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
            let script = build_elevated_msiexec_script(&msi_string);

            let output = swifttunnel_core::hidden_command("powershell")
                .args(["-NoProfile", "-Command", &script])
                .output()
                .map_err(|e| format!("Failed to invoke elevated installer: {}", e))?;

            output.status.code().unwrap_or(-1)
        };

        if !driver_install_success_exit_code(exit_code) {
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

#[cfg(all(test, windows))]
mod tests {
    use super::*;
    use std::fs;
    use std::time::{SystemTime, UNIX_EPOCH};

    fn unique_temp_dir(label: &str) -> PathBuf {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("time went backwards")
            .as_nanos();
        let dir = std::env::temp_dir().join(format!("swifttunnel_{label}_{nanos}"));
        fs::create_dir_all(&dir).expect("create temp dir");
        dir
    }

    fn touch(path: &Path) {
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent).expect("create parent dirs");
        }
        fs::write(path, b"").expect("write temp file");
    }

    #[test]
    fn driver_install_success_exit_code_accepts_expected_codes() {
        for code in [0, 1638, 1641, 3010] {
            assert!(driver_install_success_exit_code(code));
        }
        assert!(!driver_install_success_exit_code(1));
    }

    #[test]
    fn find_winpkfilter_msi_prefers_first_existing_candidate() {
        let base = unique_temp_dir("winpkfilter_candidates");
        let resource_dir = base.join("resources");
        let exe_dir = base.join("exe");
        let program_files_dir = base.join("ProgramFiles");

        let preferred = resource_dir.join("drivers").join("WinpkFilter-x64.msi");
        let fallback = exe_dir.join("drivers").join("WinpkFilter-x64.msi");

        touch(&preferred);
        touch(&fallback);

        let found = find_winpkfilter_msi(
            Some(resource_dir.as_path()),
            Some(exe_dir.as_path()),
            program_files_dir.as_path(),
        )
        .expect("should resolve msi path");

        assert_eq!(found, preferred);

        let _ = fs::remove_dir_all(base);
    }

    #[test]
    fn find_winpkfilter_msi_returns_error_when_missing() {
        let base = unique_temp_dir("winpkfilter_missing");
        let resource_dir = base.join("resources");
        let program_files_dir = base.join("ProgramFiles");

        let err = find_winpkfilter_msi(
            Some(resource_dir.as_path()),
            None,
            program_files_dir.as_path(),
        )
        .expect_err("should error when no msi exists");

        assert!(err.contains("WinpkFilter-x64.msi not found"));

        let _ = fs::remove_dir_all(base);
    }

    #[test]
    fn build_elevated_msiexec_script_escapes_single_quotes() {
        let script = build_elevated_msiexec_script("C:\\path\\ev'elyn\\WinpkFilter-x64.msi");
        assert!(script.contains("ev''elyn"));
        assert!(script.contains("Start-Process"));
        assert!(script.contains("msiexec.exe"));
        assert!(script.contains("/passive"));
    }
}

#[tauri::command]
pub fn system_open_url(url: String) -> Result<(), String> {
    swifttunnel_core::utils::open_url(&url);
    Ok(())
}
