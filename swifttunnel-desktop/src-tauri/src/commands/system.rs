use serde::Serialize;
#[cfg(windows)]
use sha2::{Digest, Sha256};
#[cfg(windows)]
use std::fs;
#[cfg(windows)]
use std::path::{Path, PathBuf};
#[cfg(windows)]
use std::time::{Duration, SystemTime, UNIX_EPOCH};

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
fn driver_install_failure_message(code: i32) -> String {
    match code {
        1223 | 1602 => "Driver installation was canceled at the UAC/installer prompt.".to_string(),
        1603 => "Windows Installer reported a fatal error (1603). This usually means antivirus \
                 interference, a pending reboot, or a corrupted prior install. Check the \
                 installer log for details.".to_string(),
        1618 => "Another installer is already running. Close it and retry.".to_string(),
        1625 => "Windows blocked this installer by policy. Contact support.".to_string(),
        1639 => {
            "Driver installer received invalid command-line arguments (msiexec 1639).".to_string()
        }
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

/// Decide whether to attempt the INF-based fallback install (pnputil) after an
/// MSI install failure. The trigger set is intentionally narrow: only 1603
/// (MSI's generic "fatal error") unless the stderr indicates a UAC cancel.
///
/// Other MSI error codes either (a) indicate user intent we must respect
/// (1223/1602), (b) are policy/platform blocks the fallback cannot bypass
/// (1625/1633/1643/1644/1654), or (c) indicate MSI package/temp access
/// problems that would break `msiexec /a` extraction the same way
/// (1619/1620/1622/1632).
#[cfg(windows)]
fn should_try_inf_fallback(exit_code: i32, stderr: &str) -> bool {
    if is_probable_uac_cancel_message(stderr) {
        return false;
    }
    exit_code == 1603
}

#[cfg(windows)]
fn unique_extract_dir() -> PathBuf {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    let program_data = std::env::var("ProgramData")
        .unwrap_or_else(|_| "C:\\ProgramData".to_string());
    PathBuf::from(program_data)
        .join("SwiftTunnel")
        .join("driver-extract")
        .join(format!("{nanos}"))
}

/// Extract an MSI's payload to a directory via `msiexec /a` (administrative
/// install). Does not run the normal install sequence, so most MSI custom
/// actions are skipped — the key property that makes this a viable fallback
/// when `/i` returns 1603 on custom-action failure. Still not guaranteed to
/// be custom-action-free (the AdminExecuteSequence can carry actions), so the
/// caller must validate the extracted payload before using it.
#[cfg(windows)]
fn extract_msi_to_dir(
    msi_path: &Path,
    extract_dir: &Path,
    log_path: &Path,
) -> Result<(), String> {
    fs::create_dir_all(extract_dir).map_err(|e| {
        format!(
            "Failed to create MSI extract dir {}: {}",
            extract_dir.display(),
            e
        )
    })?;

    let target_dir_arg = format!("TARGETDIR={}", extract_dir.display());
    let output = swifttunnel_core::hidden_command("msiexec")
        .args([
            "/a",
            &msi_path.to_string_lossy(),
            &target_dir_arg,
            "/qn",
            "/norestart",
            "/L*V",
            &log_path.to_string_lossy(),
        ])
        .output()
        .map_err(|e| format!("Failed to run msiexec /a: {}", e))?;

    let code = output.status.code().unwrap_or(-1);
    if code == 0 {
        return Ok(());
    }

    let stderr = String::from_utf8_lossy(&output.stderr).trim().to_string();
    if stderr.is_empty() {
        Err(format!(
            "msiexec /a failed with code {} (log: {})",
            code,
            log_path.display()
        ))
    } else {
        Err(format!(
            "msiexec /a failed with code {}: {} (log: {})",
            code,
            stderr,
            log_path.display()
        ))
    }
}

/// Recursively search `extract_dir` for `ndisrd_lwf.inf` (case-insensitive).
/// Returns the parent directory of the matched file (which is the argument
/// shape expected by `install_driver_from_package_dir`). Bounded depth to
/// guard against symlink loops or unexpected tree layouts; WinpkFilter's
/// admin-install layout nests to depth ~3.
#[cfg(windows)]
fn find_inf_in_extract_dir(extract_dir: &Path) -> Result<PathBuf, String> {
    let target = swifttunnel_core::vpn::winpkfilter::DRIVER_INF_NAME;

    fn walk(dir: &Path, target: &str, depth: u32) -> Option<PathBuf> {
        if depth > 6 {
            return None;
        }
        let Ok(entries) = fs::read_dir(dir) else {
            return None;
        };

        let mut subdirs = Vec::new();
        for entry in entries.flatten() {
            let Ok(file_type) = entry.file_type() else {
                continue;
            };
            let path = entry.path();
            if file_type.is_file() {
                let matches = path
                    .file_name()
                    .and_then(|s| s.to_str())
                    .map(|n| n.eq_ignore_ascii_case(target))
                    .unwrap_or(false);
                if matches {
                    return path.parent().map(|p| p.to_path_buf());
                }
            } else if file_type.is_dir() {
                subdirs.push(path);
            }
        }
        for sub in subdirs {
            if let Some(found) = walk(&sub, target, depth + 1) {
                return Some(found);
            }
        }
        None
    }

    walk(extract_dir, target, 0).ok_or_else(|| {
        format!(
            "Could not locate {} under {}",
            target,
            extract_dir.display()
        )
    })
}

/// Returns `Some(published_name)` if the WinpkFilter driver package is
/// registered in the driver store but the driver itself is not available
/// at runtime (service missing, files stale, etc.). This is the "broken
/// prior install" state that MSI 1603 commonly maps to.
///
/// Returns `None` in the healthy cases (not installed at all, or installed
/// and working), so the caller should only cleanup when this returns `Some`.
// TODO: handle multi-oem case — `find_installed_driver_published_name` only
// returns the first match, so if the store has multiple stale ndisrd_lwf.inf
// entries we'd only detect one. Rare in practice.
#[cfg(windows)]
fn detect_broken_install() -> Option<String> {
    match swifttunnel_core::vpn::winpkfilter::find_installed_driver_published_name() {
        Ok(Some(name)) if !swifttunnel_core::vpn::SplitTunnelDriver::is_available() => {
            Some(name)
        }
        _ => None,
    }
}

/// Orchestrates the INF fallback install: cleanup stale store entries,
/// extract the MSI payload via `msiexec /a`, locate the INF, and hand off
/// to pnputil via the existing `install_driver_from_package_dir`.
///
/// The pre-extract cleanup is mandatory: `install_driver_from_package_dir`
/// short-circuits as success if the INF is already in the driver store,
/// even when the driver is broken at runtime. Without cleanup, the
/// fallback would silently claim success on exactly the state it was
/// trying to fix.
///
/// Caller owns `extract_dir` lifecycle — on `Ok`, caller may delete it;
/// on `Err`, caller should preserve it for support triage.
#[cfg(windows)]
fn try_inf_fallback(
    msi_path: &Path,
    extract_dir: &Path,
    extract_log: &Path,
) -> Result<(), String> {
    // Step 1: mandatory pre-pnputil cleanup so pnputil doesn't short-circuit
    // on a stale store entry.
    if let Err(e) = swifttunnel_core::vpn::winpkfilter::remove_installed_driver_package() {
        log::warn!(
            "Pre-fallback driver-store cleanup failed (continuing anyway): {}",
            e
        );
    }

    // Step 2: extract MSI payload (no /i custom actions).
    extract_msi_to_dir(msi_path, extract_dir, extract_log)?;

    // Step 3: locate the INF.
    let inf_parent = find_inf_in_extract_dir(extract_dir)?;

    // Step 4: install via pnputil (validates the package internally).
    swifttunnel_core::vpn::winpkfilter::install_driver_from_package_dir(&inf_parent)
        .map_err(|e| format!("pnputil install from {} failed: {}", inf_parent.display(), e))
}

#[cfg(windows)]
fn winpkfilter_msi_candidate_paths(
    msi_name: &str,
    resource_dir: Option<&Path>,
    exe_dir: Option<&Path>,
    program_files_dir: &Path,
) -> Vec<PathBuf> {
    let mut candidates: Vec<PathBuf> = Vec::new();

    if let Some(dir) = resource_dir {
        candidates.push(dir.join("drivers").join(msi_name));
        candidates.push(dir.join(msi_name));
    }

    if let Some(dir) = exe_dir {
        candidates.push(dir.join("drivers").join(msi_name));
        candidates.push(dir.join("resources").join("drivers").join(msi_name));
        candidates.push(dir.join("resources").join(msi_name));
    }

    let install_root = program_files_dir.join("SwiftTunnel");
    candidates.push(
        install_root
            .join("resources")
            .join("drivers")
            .join(msi_name),
    );
    candidates.push(install_root.join("drivers").join(msi_name));

    candidates
}

#[cfg(windows)]
fn find_winpkfilter_msi(
    msi_name: &str,
    resource_dir: Option<&Path>,
    exe_dir: Option<&Path>,
    program_files_dir: &Path,
) -> Result<PathBuf, String> {
    let candidates =
        winpkfilter_msi_candidate_paths(msi_name, resource_dir, exe_dir, program_files_dir);
    candidates
        .into_iter()
        .find(|path| path.exists())
        .ok_or_else(|| format!("{} not found in app resources.", msi_name))
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
fn validate_winpkfilter_payload(
    data: &[u8],
    pkg: &swifttunnel_core::vpn::winpkfilter::WinpkFilterMsiPackage,
) -> Result<(), String> {
    validate_payload_sha256(data, pkg.sha256, pkg.min_size_bytes)
}

#[cfg(windows)]
fn validate_winpkfilter_file(
    path: &Path,
    pkg: &swifttunnel_core::vpn::winpkfilter::WinpkFilterMsiPackage,
) -> Result<(), String> {
    let data = fs::read(path).map_err(|e| format!("Failed to read {}: {}", path.display(), e))?;
    validate_winpkfilter_payload(&data, pkg)
}

#[cfg(windows)]
fn resolve_winpkfilter_cache_path(
    app: &tauri::AppHandle,
    msi_name: &str,
) -> Result<PathBuf, String> {
    let app_data_dir = app
        .path()
        .app_data_dir()
        .map_err(|e| format!("Failed to resolve app data directory: {}", e))?;
    Ok(app_data_dir.join("drivers").join(msi_name))
}

#[cfg(windows)]
fn download_winpkfilter_msi(
    path: &Path,
    pkg: &swifttunnel_core::vpn::winpkfilter::WinpkFilterMsiPackage,
) -> Result<(), String> {
    let client = reqwest::blocking::Client::builder()
        .timeout(Duration::from_secs(45))
        .build()
        .map_err(|e| format!("Failed to create HTTP client for driver download: {}", e))?;

    let response = client
        .get(pkg.download_url)
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

    validate_winpkfilter_payload(&data, pkg)?;

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
    let pkg = swifttunnel_core::vpn::winpkfilter::native_msi_package();

    if let Ok(path) = find_winpkfilter_msi(pkg.msi_name, resource_dir, exe_dir, program_files_dir) {
        return Ok(path);
    }

    log::warn!(
        "Bundled WinpkFilter MSI ({}) is missing; downloading pinned fallback from {}",
        pkg.msi_name,
        pkg.download_url
    );
    let cache_path = resolve_winpkfilter_cache_path(app, pkg.msi_name)?;

    if cache_path.exists() {
        if validate_winpkfilter_file(&cache_path, pkg).is_ok() {
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

    download_winpkfilter_msi(&cache_path, pkg)?;
    log::info!("Downloaded WinpkFilter MSI to {}", cache_path.display());
    Ok(cache_path)
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
fn build_elevated_msiexec_script(msi_path: &str, log_path: &str, passive: bool) -> String {
    // PowerShell single-quote escaping.
    let escaped_msi = msi_path.replace('\'', "''");
    let escaped_log = log_path.replace('\'', "''");
    let ui_flag = if passive { "/passive" } else { "/qn" };

    format!(
        "$ErrorActionPreference='Stop'; \
         $args=@('/i','{escaped_msi}','{ui_flag}','/norestart','/L*V','{escaped_log}'); \
         $p=Start-Process -FilePath 'msiexec.exe' -Verb RunAs -ArgumentList $args -Wait -PassThru; \
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
         Start-Process -FilePath 'powershell.exe' -Verb RunAs -ArgumentList @('-NoProfile','-Command',$inner) | Out-Null"
    )
}

#[cfg(windows)]
fn build_launch_uninstaller_after_exit_script(uninstaller_path: &str, current_pid: u32) -> String {
    let escaped_uninstaller = uninstaller_path.replace('\'', "''");

    format!(
        "$ErrorActionPreference='Stop'; \
         $pidToWait={current_pid}; \
         while (Get-Process -Id $pidToWait -ErrorAction SilentlyContinue) {{ Start-Sleep -Milliseconds 200 }}; \
         Start-Process -FilePath '{escaped_uninstaller}'"
    )
}

#[cfg(windows)]
fn build_launch_msi_uninstall_after_exit_script(current_pid: u32) -> String {
    format!(
        "$ErrorActionPreference='SilentlyContinue'; \
         $pidToWait={current_pid}; \
         while (Get-Process -Id $pidToWait -ErrorAction SilentlyContinue) {{ Start-Sleep -Milliseconds 200 }}; \
         $entry = Get-ItemProperty 'HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\*' | \
           Where-Object {{ $_.DisplayName -eq 'SwiftTunnel' }} | Select-Object -First 1; \
         if ($entry) {{ Start-Process msiexec.exe -ArgumentList '/x',$entry.PSChildName,'/passive' -Wait }}"
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
pub async fn system_check_driver() -> Result<DriverCheckResponse, String> {
    #[cfg(windows)]
    {
        tauri::async_runtime::spawn_blocking(|| {
            let available = swifttunnel_core::vpn::SplitTunnelDriver::is_available();
            DriverCheckResponse {
                installed: available,
                version: if available {
                    Some("Windows Packet Filter".to_string())
                } else {
                    None
                },
            }
        })
        .await
        .map_err(|e| format!("Driver check task failed: {}", e))
    }

    #[cfg(not(windows))]
    {
        Ok(DriverCheckResponse {
            installed: false,
            version: None,
        })
    }
}

#[tauri::command]
pub async fn system_install_driver(app: tauri::AppHandle) -> Result<(), String> {
    #[cfg(windows)]
    {
        if swifttunnel_core::vpn::SplitTunnelDriver::is_available() {
            return Ok(());
        }

        let resource_dir = app.path().resource_dir().ok();
        let exe_dir = std::env::current_exe()
            .ok()
            .and_then(|p| p.parent().map(|d| d.to_path_buf()));
        let program_files_dir = PathBuf::from(
            std::env::var("ProgramFiles").unwrap_or_else(|_| "C:\\Program Files".to_string()),
        );
        tauri::async_runtime::spawn_blocking(move || {
            let msi_path = resolve_winpkfilter_msi(
                &app,
                resource_dir.as_deref(),
                exe_dir.as_deref(),
                &program_files_dir,
            )?;
            let msi_string = msi_path.to_string_lossy().to_string();
            let first_log_path = default_driver_install_log_path();
            let first_log_string = first_log_path.to_string_lossy().to_string();
            let retry_log_path = first_log_path.with_extension("retry.log");
            let retry_log_string = retry_log_path.to_string_lossy().to_string();

            // ── Phase A: pre-flight (broken-install detection) ──
            // If the WinpkFilter driver package is registered in the driver store
            // but the driver isn't available at runtime, the MSI is very likely
            // to return 1603 trying to "repair" the stale state. Clean it up
            // first so the MSI install starts from a known-empty state.
            if let Some(published) = detect_broken_install() {
                log::warn!(
                    "Detected broken WinpkFilter install ({}); cleaning up before retry",
                    published
                );
                if let Err(e) =
                    swifttunnel_core::vpn::SplitTunnelDriver::remove_driver_for_uninstall()
                {
                    log::warn!("Pre-install cleanup failed (continuing anyway): {}", e);
                }
            }

            let run_install =
                |passive: bool, log_string: &str| -> Result<(i32, String), String> {
                    if swifttunnel_core::is_administrator() {
                        let ui_flag = if passive { "/passive" } else { "/qn" };
                        let output = swifttunnel_core::hidden_command("msiexec")
                            .args([
                                "/i",
                                &msi_string,
                                ui_flag,
                                "/norestart",
                                "/L*V",
                                log_string,
                            ])
                            .output()
                            .map_err(|e| format!("Failed to run msiexec: {}", e))?;
                        Ok((
                            output.status.code().unwrap_or(-1),
                            String::from_utf8_lossy(&output.stderr).trim().to_string(),
                        ))
                    } else {
                        let script =
                            build_elevated_msiexec_script(&msi_string, log_string, passive);

                        let output = swifttunnel_core::hidden_command("powershell")
                            .args(["-NoProfile", "-Command", &script])
                            .output()
                            .map_err(|e| format!("Failed to invoke elevated installer: {}", e))?;

                        let stderr =
                            String::from_utf8_lossy(&output.stderr).trim().to_string();
                        let stdout =
                            String::from_utf8_lossy(&output.stdout).trim().to_string();
                        Ok((
                            output.status.code().unwrap_or(-1),
                            if !stderr.is_empty() { stderr } else { stdout },
                        ))
                    }
                };

            let (mut exit_code, mut output_error) = run_install(true, &first_log_string)?;
            let mut retry_attempted = false;

            // Some systems return 1639 with /passive. Retry once with /qn.
            if exit_code == 1639 {
                retry_attempted = true;
                log::warn!(
                    "WinpkFilter install returned 1639 with /passive; retrying with /qn"
                );
                let (retry_code, retry_error) = run_install(false, &retry_log_string)?;
                exit_code = retry_code;
                output_error = retry_error;
            }

            // ── Phase C: handle MSI result ──
            if !driver_install_success_exit_code(exit_code) {
                if should_try_inf_fallback(exit_code, &output_error) {
                    log::warn!(
                        "MSI install returned recoverable code {}; attempting INF fallback via pnputil",
                        exit_code
                    );
                    let extract_dir = unique_extract_dir();
                    let extract_log = extract_dir.join("extract.log");
                    match try_inf_fallback(&msi_path, &extract_dir, &extract_log) {
                        Ok(()) => {
                            log::info!(
                                "INF fallback succeeded; proceeding to service repair"
                            );
                            // Best-effort cleanup of the extract dir on success.
                            let _ = fs::remove_dir_all(&extract_dir);
                            // Fall through to Phase D.
                        }
                        Err(fallback_err) => {
                            // Preserve extract dir for support triage.
                            log::error!(
                                "INF fallback failed; extract dir preserved at {}",
                                extract_dir.display()
                            );
                            let mut message = format!(
                                "Driver install failed (msiexec code {}). INF fallback also failed: {}. Installer log: {}. Extract dir: {}",
                                exit_code,
                                fallback_err,
                                first_log_string,
                                extract_dir.display()
                            );
                            if retry_attempted {
                                message.push_str(". Retry log: ");
                                message.push_str(&retry_log_string);
                            }
                            return Err(message);
                        }
                    }
                } else {
                    let mut message = if is_probable_uac_cancel_message(&output_error) {
                        "Driver installation was canceled at the UAC/installer prompt.".to_string()
                    } else {
                        driver_install_failure_message(exit_code)
                    };
                    if !output_error.is_empty() {
                        message.push_str(": ");
                        message.push_str(&output_error);
                    }
                    message.push_str(". Installer log: ");
                    message.push_str(&first_log_string);
                    if retry_attempted {
                        message.push_str(". Retry log: ");
                        message.push_str(&retry_log_string);
                    }
                    return Err(message);
                }
            }

            // ── Phase D: post-install verification (unchanged) ──
            match swifttunnel_core::vpn::SplitTunnelDriver::repair_and_wait_until_available(
                Duration::from_secs(20),
            ) {
                Ok(()) => {
                    let _ = fs::remove_file(&first_log_path);
                    let _ = fs::remove_file(&retry_log_path);
                    Ok(())
                }
                Err(e) if matches!(exit_code, 1641 | 3010) => Err(format!(
                    "Driver installation completed and Windows requested a reboot before the driver became available. Please reboot and try again. {}",
                    e
                )),
                Err(e) => Err(format!(
                    "Driver installation completed, but the driver is still not available after service repair attempts. {}",
                    e
                )),
            }
        })
        .await
        .map_err(|e| format!("Driver install task failed: {}", e))?
    }

    #[cfg(not(windows))]
    {
        Err("Driver installation is only supported on Windows".to_string())
    }
}

#[cfg(all(test, windows))]
mod tests {
    use super::*;
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
        assert!(driver_install_failure_message(1603).contains("fatal error"));
        assert!(driver_install_failure_message(1603).contains("1603"));
        assert!(driver_install_failure_message(1618).contains("Another installer"));
        assert!(driver_install_failure_message(1639).contains("invalid command-line"));
        assert_eq!(
            driver_install_failure_message(42),
            "Driver install failed with code 42"
        );
    }

    #[test]
    fn should_try_inf_fallback_triggers_only_on_1603() {
        // Success codes: never fall back.
        assert!(!should_try_inf_fallback(0, ""));
        assert!(!should_try_inf_fallback(1638, ""));
        assert!(!should_try_inf_fallback(1641, ""));
        assert!(!should_try_inf_fallback(3010, ""));

        // 1603 is the single recoverable trigger.
        assert!(should_try_inf_fallback(1603, ""));

        // Everything else must not fall back.
        for code in [
            1, 1223, 1602, 1612, 1618, 1619, 1620, 1622, 1625, 1632, 1633,
            1639, 1640, 1643, 1644, 1645, 1654,
        ] {
            assert!(
                !should_try_inf_fallback(code, ""),
                "should not fall back on code {}",
                code
            );
        }
    }

    #[test]
    fn should_try_inf_fallback_rejects_uac_cancel_stderr_even_on_1603() {
        assert!(!should_try_inf_fallback(
            1603,
            "The operation was canceled by the user."
        ));
        assert!(!should_try_inf_fallback(1603, "Access is denied."));
        assert!(!should_try_inf_fallback(
            1603,
            "Start-Process : This command requires elevation."
        ));
    }

    #[test]
    fn unique_extract_dir_lives_under_program_data_swifttunnel() {
        let dir = unique_extract_dir();
        let s = dir.to_string_lossy();
        assert!(
            s.contains("SwiftTunnel")
                && s.contains("driver-extract"),
            "unexpected extract dir: {}",
            s
        );
        // Distinct nanos on consecutive calls.
        let again = unique_extract_dir();
        assert_ne!(dir, again);
    }

    #[test]
    fn find_inf_in_extract_dir_finds_at_top_level() {
        let base = unique_temp_dir("extract_top");
        touch(&base.join("ndisrd_lwf.inf"));
        let result = find_inf_in_extract_dir(&base).expect("should find top-level inf");
        assert_eq!(result, base);
        let _ = fs::remove_dir_all(&base);
    }

    #[test]
    fn find_inf_in_extract_dir_finds_nested() {
        let base = unique_temp_dir("extract_nested");
        let nested = base.join("PFiles").join("WinpkFilter").join("driver");
        fs::create_dir_all(&nested).expect("create nested dir");
        touch(&nested.join("ndisrd_lwf.inf"));
        let result = find_inf_in_extract_dir(&base).expect("should find nested inf");
        assert_eq!(result, nested);
        let _ = fs::remove_dir_all(&base);
    }

    #[test]
    fn find_inf_in_extract_dir_case_insensitive() {
        let base = unique_temp_dir("extract_case");
        touch(&base.join("NDISRD_LWF.INF"));
        let result =
            find_inf_in_extract_dir(&base).expect("should find case-insensitive inf");
        assert_eq!(result, base);
        let _ = fs::remove_dir_all(&base);
    }

    #[test]
    fn find_inf_in_extract_dir_errors_when_missing() {
        let base = unique_temp_dir("extract_missing");
        touch(&base.join("some_other.inf"));
        let err =
            find_inf_in_extract_dir(&base).expect_err("should not find ndisrd_lwf.inf");
        assert!(err.contains("ndisrd_lwf.inf"));
        assert!(err.contains(&base.display().to_string()));
        let _ = fs::remove_dir_all(&base);
    }

    #[test]
    fn find_inf_in_extract_dir_respects_depth_cap() {
        let base = unique_temp_dir("extract_deep");
        // Plant the INF at depth 8 (deeper than the cap of 6).
        let mut deep = base.clone();
        for n in 0..8 {
            deep = deep.join(format!("d{n}"));
        }
        fs::create_dir_all(&deep).expect("create deep dirs");
        touch(&deep.join("ndisrd_lwf.inf"));
        let err = find_inf_in_extract_dir(&base)
            .expect_err("should not descend past depth cap");
        assert!(err.contains("ndisrd_lwf.inf"));
        let _ = fs::remove_dir_all(&base);
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
        let pkg = swifttunnel_core::vpn::winpkfilter::native_msi_package();
        let base = unique_temp_dir("winpkfilter_candidates");
        let resource_dir = base.join("resources");
        let exe_dir = base.join("exe");
        let program_files_dir = base.join("ProgramFiles");

        let preferred = resource_dir.join("drivers").join(pkg.msi_name);
        let fallback = exe_dir.join("drivers").join(pkg.msi_name);

        touch(&preferred);
        touch(&fallback);

        let found = find_winpkfilter_msi(
            pkg.msi_name,
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
        let pkg = swifttunnel_core::vpn::winpkfilter::native_msi_package();
        let base = unique_temp_dir("winpkfilter_missing");
        let resource_dir = base.join("resources");
        let program_files_dir = base.join("ProgramFiles");

        let err = find_winpkfilter_msi(
            pkg.msi_name,
            Some(resource_dir.as_path()),
            None,
            program_files_dir.as_path(),
        )
        .expect_err("should error when no msi exists");

        assert!(err.contains("not found in app resources"));

        let _ = fs::remove_dir_all(base);
    }

    #[test]
    fn find_winpkfilter_msi_works_for_both_arch_variants() {
        for pkg in swifttunnel_core::vpn::winpkfilter::ALL_MSI_PACKAGES {
            let base = unique_temp_dir(&format!("winpkfilter_{}", pkg.arch));
            let resource_dir = base.join("resources");
            let program_files_dir = base.join("ProgramFiles");

            let expected = resource_dir.join("drivers").join(pkg.msi_name);
            touch(&expected);

            let found = find_winpkfilter_msi(
                pkg.msi_name,
                Some(resource_dir.as_path()),
                None,
                program_files_dir.as_path(),
            )
            .expect("should resolve msi path");
            assert_eq!(found, expected);

            let _ = fs::remove_dir_all(base);
        }
    }

    #[test]
    fn build_elevated_msiexec_script_escapes_single_quotes() {
        let script = build_elevated_msiexec_script(
            "C:\\path\\ev'elyn\\WinpkFilter-x64.msi",
            "C:\\Temp\\log's\\winpk.log",
            true,
        );
        assert!(script.contains("ev''elyn"));
        assert!(script.contains("log''s"));
        assert!(script.contains("Start-Process"));
        assert!(script.contains("msiexec.exe"));
        assert!(script.contains("/passive"));
        assert!(script.contains("/L*V"));
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
        assert!(script.contains("-Command"));
    }

    #[test]
    fn build_launch_uninstaller_after_exit_script_waits_for_pid_and_escapes_path() {
        let script = build_launch_uninstaller_after_exit_script(
            "C:\\Program Files\\Swift'Tunnel\\uninstall.exe",
            4242,
        );
        assert!(script.contains("$pidToWait=4242"));
        assert!(script.contains("Get-Process -Id $pidToWait"));
        assert!(
            script.contains(
                "Start-Process -FilePath 'C:\\Program Files\\Swift''Tunnel\\uninstall.exe'"
            )
        );
    }

    #[test]
    fn build_launch_msi_uninstall_after_exit_script_waits_for_pid_and_uses_msiexec() {
        let script = build_launch_msi_uninstall_after_exit_script(5678);
        assert!(script.contains("$pidToWait=5678"));
        assert!(script.contains("Get-Process -Id $pidToWait"));
        assert!(script.contains("DisplayName -eq 'SwiftTunnel'"));
        assert!(script.contains("msiexec.exe"));
        assert!(script.contains("/passive"));
    }
}

#[tauri::command]
pub async fn system_cleanup() -> Result<(), String> {
    tauri::async_runtime::spawn_blocking(|| {
        swifttunnel_core::network_booster::cleanup_all_system_state().map_err(|e| e.to_string())
    })
    .await
    .map_err(|e| format!("Cleanup task failed: {}", e))?
}

#[tauri::command]
pub async fn system_uninstall(
    state: tauri::State<'_, crate::state::AppState>,
    app: tauri::AppHandle,
) -> Result<(), String> {
    #[cfg(windows)]
    {
        let conn_state = state.vpn_state_handle.borrow().clone();
        if !matches!(
            conn_state,
            swifttunnel_core::vpn::ConnectionState::Disconnected
        ) {
            // Tear down the live session before touching the uninstaller.
            // Best-effort: swallow any error so a stuck driver never blocks
            // the uninstall. The shared helper has already cleared the split
            // tunnel handle, set Discord idle, and persisted
            // `resume_vpn_on_startup = false` by this point, so continuing
            // is safe even when the driver-level disconnect errored.
            if let Err(e) = crate::commands::vpn::disconnect_and_persist(&state).await {
                log::warn!("Uninstall proceeding despite disconnect error: {}", e);
            }
        }

        // Find and launch the appropriate uninstaller (NSIS legacy or MSI).
        let exe_path =
            std::env::current_exe().map_err(|e| format!("Failed to resolve executable: {e}"))?;
        let install_dir = exe_path
            .parent()
            .ok_or("Failed to resolve install directory")?;
        let nsis_uninstaller = install_dir.join("uninstall.exe");

        let uninstall_script = if nsis_uninstaller.exists() {
            // Legacy NSIS install — launch uninstall.exe after app exits
            build_launch_uninstaller_after_exit_script(
                &nsis_uninstaller.to_string_lossy(),
                std::process::id(),
            )
        } else {
            // MSI install — find product code from registry and run msiexec
            build_launch_msi_uninstall_after_exit_script(std::process::id())
        };

        swifttunnel_core::hidden_command("powershell")
            .args(["-Command", &uninstall_script])
            .spawn()
            .map_err(|e| format!("Failed to queue uninstaller launch: {e}"))?;

        app.exit(0);
        Ok(())
    }

    #[cfg(not(windows))]
    {
        let _ = state;
        let _ = app;
        Err("Uninstall is only supported on Windows".to_string())
    }
}

#[tauri::command]
pub fn system_launched_from_startup(state: tauri::State<'_, crate::state::AppState>) -> bool {
    state.launched_from_startup
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
pub async fn system_restart_as_admin(app: tauri::AppHandle) -> Result<(), String> {
    #[cfg(windows)]
    {
        if swifttunnel_core::is_administrator() {
            return Ok(());
        }

        let exe_path =
            std::env::current_exe().map_err(|e| format!("Failed to resolve executable: {}", e))?;
        let exe = exe_path.to_string_lossy().to_string();
        let script = build_restart_as_admin_script(&exe, std::process::id());

        let output = tauri::async_runtime::spawn_blocking(move || {
            swifttunnel_core::hidden_command("powershell")
                .args(["-NoProfile", "-Command", &script])
                .output()
                .map_err(|e| format!("Failed to launch elevated restart helper: {}", e))
        })
        .await
        .map_err(|e| format!("Restart-as-admin task failed: {}", e))??;

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
