use serde::Serialize;
#[cfg(windows)]
use sha2::{Digest, Sha256};
#[cfg(windows)]
use std::fs;
#[cfg(windows)]
use std::path::{Path, PathBuf};
#[cfg(windows)]
use std::time::Duration;

#[cfg(windows)]
use tauri::Manager;

#[cfg(windows)]
const WINPKFILTER_MSI_NAME: &str = "WinpkFilter-x64.msi";
#[cfg(windows)]
const WINPKFILTER_PINNED_URL: &str = "https://github.com/wiresock/ndisapi/releases/download/v3.6.2/Windows.Packet.Filter.3.6.2.1.x64.msi";
#[cfg(windows)]
const WINPKFILTER_PINNED_SHA256: &str =
    "9c388c0b7f189f7fa98720bae2caecf7d64f30910838b80b438ecf8956b8502c";
#[cfg(windows)]
const WINPKFILTER_MIN_SIZE_BYTES: usize = 500_000;

#[cfg(windows)]
fn driver_install_success_exit_code(code: i32) -> bool {
    // 0 = success
    // 1638 = another version already installed
    // 1641/3010 = success, restart required
    matches!(code, 0 | 1638 | 1641 | 3010)
}

#[cfg(windows)]
fn driver_install_failure_message(code: i32) -> String {
    match code {
        1223 | 1602 => "Driver installation was canceled at the UAC/installer prompt.".to_string(),
        1618 => "Another installer is already running. Close it and retry.".to_string(),
        1625 => "Windows blocked this installer by policy. Contact support.".to_string(),
        _ => format!("Driver install failed with code {}", code),
    }
}

#[cfg(windows)]
fn is_probable_uac_cancel_message(message: &str) -> bool {
    let normalized = message.to_ascii_lowercase();
    normalized.contains("operation was canceled by the user")
        || normalized.contains("requested operation requires elevation")
        || normalized.contains("requires elevation")
        || normalized.contains("access is denied")
        || normalized.contains("uac")
}

#[cfg(windows)]
fn winpkfilter_msi_candidate_paths(
    resource_dir: Option<&Path>,
    exe_dir: Option<&Path>,
    program_files_dir: &Path,
) -> Vec<PathBuf> {
    let mut candidates: Vec<PathBuf> = Vec::new();

    if let Some(dir) = resource_dir {
        candidates.push(dir.join("drivers").join(WINPKFILTER_MSI_NAME));
        candidates.push(dir.join(WINPKFILTER_MSI_NAME));
    }

    if let Some(dir) = exe_dir {
        candidates.push(dir.join("drivers").join(WINPKFILTER_MSI_NAME));
        candidates.push(
            dir.join("resources")
                .join("drivers")
                .join(WINPKFILTER_MSI_NAME),
        );
        candidates.push(dir.join("resources").join(WINPKFILTER_MSI_NAME));
    }

    // Hard fallbacks for typical installs.
    let install_root = program_files_dir.join("SwiftTunnel");
    candidates.push(
        install_root
            .join("resources")
            .join("drivers")
            .join(WINPKFILTER_MSI_NAME),
    );
    candidates.push(install_root.join("drivers").join(WINPKFILTER_MSI_NAME));

    candidates
}

#[cfg(windows)]
fn find_winpkfilter_msi(
    resource_dir: Option<&Path>,
    exe_dir: Option<&Path>,
    program_files_dir: &Path,
) -> Result<PathBuf, String> {
    let candidates = winpkfilter_msi_candidate_paths(resource_dir, exe_dir, program_files_dir);
    candidates
        .into_iter()
        .find(|p| p.exists())
        .ok_or_else(|| "WinpkFilter-x64.msi not found in app resources.".to_string())
}

#[cfg(windows)]
fn sha256_hex(data: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(data);
    format!("{:x}", hasher.finalize())
}

#[cfg(windows)]
fn validate_payload_sha256(
    data: &[u8],
    expected_sha256: &str,
    min_size_bytes: usize,
) -> Result<(), String> {
    if data.len() < min_size_bytes {
        return Err(format!(
            "Downloaded WinpkFilter MSI is too small ({} bytes).",
            data.len()
        ));
    }

    let digest = sha256_hex(data);
    if digest != expected_sha256 {
        return Err(format!(
            "Downloaded WinpkFilter MSI failed integrity check (sha256 mismatch: expected {}, got {}).",
            expected_sha256, digest
        ));
    }

    Ok(())
}

#[cfg(windows)]
fn validate_winpkfilter_payload(data: &[u8]) -> Result<(), String> {
    validate_payload_sha256(data, WINPKFILTER_PINNED_SHA256, WINPKFILTER_MIN_SIZE_BYTES)
}

#[cfg(windows)]
fn validate_winpkfilter_file(path: &Path) -> Result<(), String> {
    let data = fs::read(path).map_err(|e| format!("Failed to read {}: {}", path.display(), e))?;
    validate_winpkfilter_payload(&data)
}

#[cfg(windows)]
fn resolve_winpkfilter_cache_path(app: &tauri::AppHandle) -> Result<PathBuf, String> {
    let app_data_dir = app
        .path()
        .app_data_dir()
        .map_err(|e| format!("Failed to resolve app data directory: {}", e))?;
    Ok(app_data_dir.join("drivers").join(WINPKFILTER_MSI_NAME))
}

#[cfg(windows)]
fn download_winpkfilter_msi(path: &Path) -> Result<(), String> {
    let client = reqwest::blocking::Client::builder()
        .timeout(Duration::from_secs(45))
        .build()
        .map_err(|e| format!("Failed to create HTTP client for driver download: {}", e))?;

    let response = client
        .get(WINPKFILTER_PINNED_URL)
        .header(reqwest::header::USER_AGENT, "SwiftTunnel/driver-installer")
        .send()
        .map_err(|e| format!("Failed to download WinpkFilter MSI: {}", e))?;

    if !response.status().is_success() {
        return Err(format!(
            "WinpkFilter download failed with HTTP {}.",
            response.status()
        ));
    }

    let data = response
        .bytes()
        .map_err(|e| format!("Failed to read WinpkFilter download bytes: {}", e))?;

    validate_winpkfilter_payload(&data)?;

    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).map_err(|e| {
            format!(
                "Failed to create driver cache directory {}: {}",
                parent.display(),
                e
            )
        })?;
    }

    fs::write(path, &data).map_err(|e| {
        format!(
            "Failed to save WinpkFilter MSI to {}: {}",
            path.display(),
            e
        )
    })?;

    Ok(())
}

#[cfg(windows)]
fn resolve_winpkfilter_msi(
    app: &tauri::AppHandle,
    resource_dir: Option<&Path>,
    exe_dir: Option<&Path>,
    program_files_dir: &Path,
) -> Result<PathBuf, String> {
    if let Ok(path) = find_winpkfilter_msi(resource_dir, exe_dir, program_files_dir) {
        return Ok(path);
    }

    log::warn!(
        "Bundled WinpkFilter MSI is missing; downloading pinned fallback from {}",
        WINPKFILTER_PINNED_URL
    );
    let cache_path = resolve_winpkfilter_cache_path(app)?;

    if cache_path.exists() {
        if validate_winpkfilter_file(&cache_path).is_ok() {
            log::info!("Using cached WinpkFilter MSI from {}", cache_path.display());
            return Ok(cache_path);
        }

        log::warn!(
            "Cached WinpkFilter MSI failed integrity check, removing {}",
            cache_path.display()
        );
        if let Err(e) = fs::remove_file(&cache_path) {
            log::warn!(
                "Failed to remove invalid cached WinpkFilter MSI {}: {}",
                cache_path.display(),
                e
            );
        }
    }

    download_winpkfilter_msi(&cache_path)?;
    log::info!("Downloaded WinpkFilter MSI to {}", cache_path.display());
    Ok(cache_path)
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

#[cfg(windows)]
fn build_restart_as_admin_script(exe_path: &str, current_pid: u32) -> String {
    // Build a non-elevated script that asks UAC for an elevated PowerShell helper.
    // The elevated helper waits for the current process to exit, then relaunches the app.
    let escaped_exe_for_inner = exe_path.replace('\'', "''");
    let inner_script = format!(
        "$ErrorActionPreference='Stop'; \
         $pidToWait={current_pid}; \
         while (Get-Process -Id $pidToWait -ErrorAction SilentlyContinue) {{ Start-Sleep -Milliseconds 200 }}; \
         Start-Process -FilePath '{escaped_exe_for_inner}'"
    );
    let escaped_inner = inner_script.replace('\'', "''");

    format!(
        "$ErrorActionPreference='Stop'; \
         $inner='{escaped_inner}'; \
         $enc=[Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes($inner)); \
         Start-Process -FilePath 'powershell.exe' -Verb RunAs -ArgumentList @('-NoProfile','-EncodedCommand',$enc) | Out-Null"
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
        let msi_path = resolve_winpkfilter_msi(
            &app,
            resource_dir.as_deref(),
            exe_dir.as_deref(),
            &program_files_dir,
        )?;

        let msi_string = msi_path.to_string_lossy().to_string();

        // If we are elevated already, run msiexec directly and capture output.
        // Otherwise, use Start-Process -Verb RunAs to trigger a UAC prompt.
        let (exit_code, output_error) = if swifttunnel_core::is_administrator() {
            let output = swifttunnel_core::hidden_command("msiexec")
                .args(["/i", &msi_string, "/passive", "/norestart"])
                .output()
                .map_err(|e| format!("Failed to run msiexec: {}", e))?;
            (
                output.status.code().unwrap_or(-1),
                String::from_utf8_lossy(&output.stderr).trim().to_string(),
            )
        } else {
            let script = build_elevated_msiexec_script(&msi_string);

            let output = swifttunnel_core::hidden_command("powershell")
                .args(["-NoProfile", "-Command", &script])
                .output()
                .map_err(|e| format!("Failed to invoke elevated installer: {}", e))?;

            let stderr = String::from_utf8_lossy(&output.stderr).trim().to_string();
            let stdout = String::from_utf8_lossy(&output.stdout).trim().to_string();
            (
                output.status.code().unwrap_or(-1),
                if !stderr.is_empty() { stderr } else { stdout },
            )
        };

        if !driver_install_success_exit_code(exit_code) {
            let mut message = if is_probable_uac_cancel_message(&output_error) {
                "Driver installation was canceled at the UAC/installer prompt.".to_string()
            } else {
                driver_install_failure_message(exit_code)
            };
            if !output_error.is_empty() {
                message.push_str(": ");
                message.push_str(&output_error);
            }
            return Err(message);
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
    fn driver_install_failure_message_maps_common_codes() {
        assert!(driver_install_failure_message(1223).contains("canceled"));
        assert!(driver_install_failure_message(1602).contains("canceled"));
        assert!(driver_install_failure_message(1618).contains("Another installer"));
        assert_eq!(
            driver_install_failure_message(42),
            "Driver install failed with code 42"
        );
    }

    #[test]
    fn is_probable_uac_cancel_message_detects_known_patterns() {
        assert!(is_probable_uac_cancel_message(
            "The operation was canceled by the user."
        ));
        assert!(is_probable_uac_cancel_message(
            "Start-Process : This command requires elevation."
        ));
        assert!(is_probable_uac_cancel_message("Access is denied."));
        assert!(!is_probable_uac_cancel_message("Network timeout"));
    }

    #[test]
    fn sha256_hex_returns_expected_lowercase_digest() {
        assert_eq!(
            sha256_hex(b"swift"),
            "a33603bf79f74b056172d43b78358a9d6a51ae59d2720741fbb33ce78e3ad607"
        );
    }

    #[test]
    fn validate_payload_sha256_accepts_matching_hash_and_size() {
        let payload = b"abcdef";
        let digest = sha256_hex(payload);
        assert!(validate_payload_sha256(payload, &digest, payload.len()).is_ok());
    }

    #[test]
    fn validate_payload_sha256_rejects_small_payload() {
        let payload = b"abcdef";
        let digest = sha256_hex(payload);
        let err = validate_payload_sha256(payload, &digest, payload.len() + 1)
            .expect_err("payload should be rejected when too small");
        assert!(err.contains("too small"));
    }

    #[test]
    fn validate_payload_sha256_rejects_hash_mismatch() {
        let payload = b"abcdef";
        let err = validate_payload_sha256(payload, "deadbeef", payload.len())
            .expect_err("payload should be rejected when hash mismatches");
        assert!(err.contains("sha256 mismatch"));
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

    #[test]
    fn build_restart_as_admin_script_waits_for_pid_and_escapes_path() {
        let script =
            build_restart_as_admin_script("C:\\Program Files\\Swift'Tunnel\\SwiftTunnel.exe", 4242);
        assert!(script.contains("$pidToWait=4242"));
        assert!(script.contains("Get-Process -Id $pidToWait"));
        assert!(script.contains("$inner='"));
        assert!(script.contains("Start-Process -FilePath 'powershell.exe'"));
        assert!(script.contains("-Verb RunAs"));
        assert!(script.contains("-EncodedCommand"));
    }
}

#[tauri::command]
pub fn system_open_url(url: String) -> Result<(), String> {
    swifttunnel_core::utils::open_url(&url);
    Ok(())
}

#[tauri::command]
pub fn system_restart_as_admin(app: tauri::AppHandle) -> Result<(), String> {
    #[cfg(windows)]
    {
        if swifttunnel_core::is_administrator() {
            return Ok(());
        }

        let exe_path =
            std::env::current_exe().map_err(|e| format!("Failed to resolve executable: {}", e))?;
        let exe = exe_path.to_string_lossy().to_string();
        let script = build_restart_as_admin_script(&exe, std::process::id());

        let output = swifttunnel_core::hidden_command("powershell")
            .args(["-NoProfile", "-Command", &script])
            .output()
            .map_err(|e| format!("Failed to launch elevated restart helper: {}", e))?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr).trim().to_string();
            let stdout = String::from_utf8_lossy(&output.stdout).trim().to_string();
            let detail = if !stderr.is_empty() { stderr } else { stdout };

            if is_probable_uac_cancel_message(&detail) {
                return Err("Administrator restart was canceled at the UAC prompt.".to_string());
            }

            if detail.is_empty() {
                return Err("Failed to relaunch SwiftTunnel as Administrator.".to_string());
            }

            return Err(format!(
                "Failed to relaunch SwiftTunnel as Administrator: {}",
                detail
            ));
        }

        app.exit(0);
        Ok(())
    }

    #[cfg(not(windows))]
    {
        let _ = app;
        Err("Administrator restart is only supported on Windows".to_string())
    }
}
