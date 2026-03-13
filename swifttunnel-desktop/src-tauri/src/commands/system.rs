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
    // 3010 = success, reboot required
    matches!(code, 0 | 3010)
}

#[cfg(windows)]
fn driver_install_failure_message(code: i32) -> String {
    match code {
        1223 | 1602 => "Driver installation was canceled at the UAC/installer prompt.".to_string(),
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
fn command_output_detail(output: &std::process::Output) -> String {
    let stderr = String::from_utf8_lossy(&output.stderr).trim().to_string();
    let stdout = String::from_utf8_lossy(&output.stdout).trim().to_string();

    if !stderr.is_empty() && !stdout.is_empty() {
        format!("{stderr}; {stdout}")
    } else if !stderr.is_empty() {
        stderr
    } else {
        stdout
    }
}

#[cfg(windows)]
fn resolve_winpkfilter_cache_dir(app: &tauri::AppHandle) -> Result<PathBuf, String> {
    let app_data_dir = app
        .path()
        .app_data_dir()
        .map_err(|e| format!("Failed to resolve app data directory: {}", e))?;
    Ok(app_data_dir.join("drivers"))
}

#[cfg(windows)]
fn resolve_winpkfilter_cache_path(app: &tauri::AppHandle) -> Result<PathBuf, String> {
    Ok(resolve_winpkfilter_cache_dir(app)?.join(WINPKFILTER_MSI_NAME))
}

#[cfg(windows)]
fn resolve_winpkfilter_extract_root(app: &tauri::AppHandle) -> Result<PathBuf, String> {
    Ok(resolve_winpkfilter_cache_dir(app)?.join("winpkfilter-extracted"))
}

#[cfg(windows)]
fn extracted_driver_package_dir(extract_root: &Path) -> PathBuf {
    extract_root
        .join("PFiles64")
        .join("Windows Packet Filter")
        .join("drivers")
        .join("win10")
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
fn extract_driver_package_from_msi(
    msi_path: &Path,
    extract_root: &Path,
) -> Result<swifttunnel_core::vpn::winpkfilter::DriverPackage, String> {
    let package_dir = extracted_driver_package_dir(extract_root);

    // Always re-extract from the pinned MSI in fallback mode instead of trusting
    // cached extraction output, which is harder to validate if a prior attempt
    // was interrupted.
    if extract_root.exists() {
        fs::remove_dir_all(extract_root).map_err(|e| {
            format!(
                "Failed to clear previous WinpkFilter extraction {}: {}",
                extract_root.display(),
                e
            )
        })?;
    }
    fs::create_dir_all(extract_root).map_err(|e| {
        format!(
            "Failed to create WinpkFilter extraction directory {}: {}",
            extract_root.display(),
            e
        )
    })?;

    let extract_log = default_driver_install_log_path().with_extension("extract.log");
    let msi_string = msi_path.to_string_lossy().to_string();
    let extract_log_string = extract_log.to_string_lossy().to_string();
    let target_dir_arg = format!("TARGETDIR={}", extract_root.to_string_lossy());
    let output = swifttunnel_core::hidden_command("msiexec")
        .args([
            "/a",
            &msi_string,
            "/qn",
            &target_dir_arg,
            "/L*V",
            &extract_log_string,
        ])
        .output()
        .map_err(|e| format!("Failed to extract WinpkFilter MSI: {}", e))?;

    if !output.status.success() {
        let code = output.status.code().unwrap_or(-1);
        let detail = command_output_detail(&output);
        let mut message = if detail.is_empty() {
            format!("Failed to extract WinpkFilter MSI (code {})", code)
        } else {
            format!(
                "Failed to extract WinpkFilter MSI (code {}): {}",
                code, detail
            )
        };
        message.push_str(". Extract log: ");
        message.push_str(&extract_log.to_string_lossy());
        return Err(message);
    }

    let package = swifttunnel_core::vpn::winpkfilter::validate_driver_package_dir(&package_dir)?;
    let _ = fs::remove_file(&extract_log);
    Ok(package)
}

#[cfg(windows)]
fn resolve_winpkfilter_driver_package(
    app: &tauri::AppHandle,
    resource_dir: Option<&Path>,
    exe_dir: Option<&Path>,
    program_files_dir: &Path,
) -> Result<swifttunnel_core::vpn::winpkfilter::DriverPackage, String> {
    if let Ok(package) = swifttunnel_core::vpn::winpkfilter::find_bundled_driver_package(
        resource_dir,
        exe_dir,
        program_files_dir,
    ) {
        return Ok(package);
    }

    log::warn!(
        "Bundled WinpkFilter driver package is missing; downloading pinned MSI fallback from {}",
        WINPKFILTER_PINNED_URL
    );
    let cache_path = resolve_winpkfilter_cache_path(app)?;
    let extract_root = resolve_winpkfilter_extract_root(app)?;

    if cache_path.exists() {
        if validate_winpkfilter_file(&cache_path).is_ok() {
            log::info!("Using cached WinpkFilter MSI from {}", cache_path.display());
            return extract_driver_package_from_msi(&cache_path, &extract_root);
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
    extract_driver_package_from_msi(&cache_path, &extract_root)
}

#[cfg(windows)]
fn default_driver_install_log_path() -> PathBuf {
    let now_ms = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis())
        .unwrap_or(0);
    std::env::temp_dir().join(format!("swifttunnel-winpkfilter-install-{now_ms}.log"))
}

#[cfg(windows)]
fn build_elevated_pnputil_script(inf_path: &str, output_path: &str) -> String {
    // PowerShell single-quote escaping.
    let escaped_inf = inf_path.replace('\'', "''");
    let escaped_output = output_path.replace('\'', "''");
    let inner_script = format!(
        "$ErrorActionPreference='Stop'; \
         $rendered=(& pnputil.exe /add-driver '{escaped_inf}' /install 2>&1 | Out-String); \
         [IO.File]::WriteAllText('{escaped_output}',$rendered); \
         exit $LASTEXITCODE"
    );
    let escaped_inner = inner_script.replace('\'', "''");

    format!(
        "$ErrorActionPreference='Stop'; \
         $inner='{escaped_inner}'; \
         $enc=[Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes($inner)); \
         $p=Start-Process -FilePath 'powershell.exe' -Verb RunAs -WindowStyle Hidden -ArgumentList @('-NoProfile','-EncodedCommand',$enc) -Wait -PassThru; \
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
        let program_files_dir = swifttunnel_core::vpn::winpkfilter::default_program_files_dir();
        let driver_package = resolve_winpkfilter_driver_package(
            &app,
            resource_dir.as_deref(),
            exe_dir.as_deref(),
            program_files_dir.as_path(),
        )?;

        let inf_string = driver_package.inf_path.to_string_lossy().to_string();
        let install_output_path = default_driver_install_log_path().with_extension("txt");
        let install_output_string = install_output_path.to_string_lossy().to_string();

        // If we are elevated already, run pnputil directly and capture output.
        // Otherwise, use Start-Process -Verb RunAs to trigger a UAC prompt.
        let run_install = || -> Result<(i32, String), String> {
            if swifttunnel_core::is_administrator() {
                let output = swifttunnel_core::hidden_command("pnputil")
                    .args(["/add-driver", &inf_string, "/install"])
                    .output()
                    .map_err(|e| format!("Failed to run pnputil: {}", e))?;
                Ok((
                    output.status.code().unwrap_or(-1),
                    command_output_detail(&output),
                ))
            } else {
                let _ = fs::remove_file(&install_output_path);
                let script = build_elevated_pnputil_script(&inf_string, &install_output_string);

                let output = swifttunnel_core::hidden_command("powershell")
                    .args(["-NoProfile", "-Command", &script])
                    .output()
                    .map_err(|e| format!("Failed to invoke elevated installer: {}", e))?;

                let detail = fs::read_to_string(&install_output_path)
                    .unwrap_or_else(|_| command_output_detail(&output));
                let _ = fs::remove_file(&install_output_path);

                Ok((
                    output.status.code().unwrap_or(-1),
                    detail.trim().to_string(),
                ))
            }
        };

        let (exit_code, output_error) = run_install()?;

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
            message.push_str(". Driver package: ");
            message.push_str(&driver_package.root_dir.to_string_lossy());
            return Err(message);
        }

        if let Err(e) = swifttunnel_core::vpn::SplitTunnelDriver::restart_driver_service() {
            log::warn!(
                "Failed to restart WinpkFilter driver service after install: {}",
                e
            );
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

    fn decode_single_quoted_powershell_assignment(script: &str, variable_name: &str) -> String {
        let marker = format!("{variable_name}='");
        let start = script
            .find(&marker)
            .unwrap_or_else(|| panic!("missing assignment marker: {marker}"))
            + marker.len();
        let remainder = &script[start..];
        let mut decoded = String::new();
        let mut chars = remainder.chars().peekable();

        while let Some(ch) = chars.next() {
            if ch == '\'' {
                if chars.peek() == Some(&'\'') {
                    decoded.push('\'');
                    chars.next();
                    continue;
                }
                return decoded;
            }
            decoded.push(ch);
        }

        panic!("missing assignment terminator for: {variable_name}");
    }

    #[test]
    fn driver_install_success_exit_code_accepts_expected_codes() {
        for code in [0, 3010] {
            assert!(driver_install_success_exit_code(code));
        }
        assert!(!driver_install_success_exit_code(1));
    }

    #[test]
    fn driver_install_failure_message_maps_common_codes() {
        assert!(driver_install_failure_message(1223).contains("canceled"));
        assert!(driver_install_failure_message(1602).contains("canceled"));
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
    fn extracted_driver_package_dir_matches_vendor_layout() {
        let root = PathBuf::from(r"C:\Temp\SwiftTunnel");
        let package_dir = extracted_driver_package_dir(&root);
        assert_eq!(
            package_dir,
            PathBuf::from(r"C:\Temp\SwiftTunnel")
                .join("PFiles64")
                .join("Windows Packet Filter")
                .join("drivers")
                .join("win10")
        );
    }

    #[test]
    fn build_elevated_pnputil_script_escapes_single_quotes() {
        let script = build_elevated_pnputil_script(
            "C:\\path\\ev'elyn\\ndisrd_lwf.inf",
            "C:\\Temp\\log's\\pnputil.txt",
        );
        let inner = decode_single_quoted_powershell_assignment(&script, "$inner");
        assert!(inner.contains("ev''elyn"));
        assert!(inner.contains("log''s"));
        assert!(script.contains("Start-Process"));
        assert!(inner.contains("pnputil.exe"));
        assert!(inner.contains("/add-driver"));
        assert!(inner.contains("/install"));
        assert!(script.contains("-WindowStyle Hidden"));
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
pub fn system_cleanup() -> Result<(), String> {
    swifttunnel_core::network_booster::cleanup_all_system_state().map_err(|e| e.to_string())
}

#[tauri::command]
pub fn system_uninstall(app: tauri::AppHandle) -> Result<(), String> {
    // Run cleanup first to revert all system modifications
    swifttunnel_core::network_booster::cleanup_all_system_state()
        .map_err(|e| format!("Cleanup failed before uninstall: {}", e))?;

    #[cfg(windows)]
    {
        // Find and launch the NSIS uninstaller
        let exe_path =
            std::env::current_exe().map_err(|e| format!("Failed to resolve executable: {e}"))?;
        let install_dir = exe_path
            .parent()
            .ok_or("Failed to resolve install directory")?;
        let uninstaller = install_dir.join("uninstall.exe");

        if !uninstaller.exists() {
            return Err(
                "Uninstaller not found. The app may not have been installed via the installer."
                    .to_string(),
            );
        }

        std::process::Command::new(&uninstaller)
            .spawn()
            .map_err(|e| format!("Failed to launch uninstaller: {e}"))?;

        app.exit(0);
        Ok(())
    }

    #[cfg(not(windows))]
    {
        let _ = app;
        Err("Uninstall is only supported on Windows".to_string())
    }
}

#[tauri::command]
pub fn system_show_notification(title: String, body: String) {
    swifttunnel_core::notification::show_notification(&title, &body);
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
