use std::path::{Path, PathBuf};

#[cfg(windows)]
use crate::hidden_command;

// ═══════════════════════════════════════════════════════════════════════════════
//  MSI PACKAGE METADATA & ARCHITECTURE DETECTION
// ═══════════════════════════════════════════════════════════════════════════════

/// Native machine architecture relevant for WinpkFilter MSI selection.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WinpkFilterMsiArch {
    X64,
    Arm64,
}

impl std::fmt::Display for WinpkFilterMsiArch {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            WinpkFilterMsiArch::X64 => f.write_str("x64"),
            WinpkFilterMsiArch::Arm64 => f.write_str("arm64"),
        }
    }
}

/// Metadata for an architecture-specific WinpkFilter MSI installer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WinpkFilterMsiPackage {
    pub arch: WinpkFilterMsiArch,
    /// Bundled filename used locally (e.g. `WinpkFilter-x64.msi`).
    pub msi_name: &'static str,
    /// GitHub release asset name for download.
    pub asset_name: &'static str,
    /// Pinned download URL.
    pub download_url: &'static str,
    /// Expected SHA-256 hex digest.
    pub sha256: &'static str,
    /// Minimum acceptable file size in bytes.
    pub min_size_bytes: usize,
}

pub const MSI_PACKAGE_X64: WinpkFilterMsiPackage = WinpkFilterMsiPackage {
    arch: WinpkFilterMsiArch::X64,
    msi_name: "WinpkFilter-x64.msi",
    asset_name: "Windows.Packet.Filter.3.6.2.1.x64.msi",
    download_url: "https://github.com/wiresock/ndisapi/releases/download/v3.6.2/Windows.Packet.Filter.3.6.2.1.x64.msi",
    sha256: "9c388c0b7f189f7fa98720bae2caecf7d64f30910838b80b438ecf8956b8502c",
    min_size_bytes: 500_000,
};

pub const MSI_PACKAGE_ARM64: WinpkFilterMsiPackage = WinpkFilterMsiPackage {
    arch: WinpkFilterMsiArch::Arm64,
    msi_name: "WinpkFilter-arm64.msi",
    asset_name: "Windows.Packet.Filter.3.6.2.1.ARM64.msi",
    download_url: "https://github.com/wiresock/ndisapi/releases/download/v3.6.2/Windows.Packet.Filter.3.6.2.1.ARM64.msi",
    sha256: "b13c6832c9e5c0c14948bbf5c17ccbe65dff55c0f6069df01494d97ebd1f3d69",
    min_size_bytes: 500_000,
};

/// All known MSI packages. Used during uninstall to clean up any variant.
pub const ALL_MSI_PACKAGES: &[&WinpkFilterMsiPackage] = &[&MSI_PACKAGE_X64, &MSI_PACKAGE_ARM64];

/// Minimum Windows Packet Filter driver version SwiftTunnel requires at runtime.
///
/// 3.6.2 fixes the `ERROR_INVALID_PARAMETER` regression that made the reader
/// return 0x80070057 on certain Realtek NICs. Older installs (3.5.x, 3.6.0,
/// 3.6.1) still open the `\\.\NDISRD` handle, so without an explicit floor
/// the install path would accept them as "healthy" and the user would hit
/// the same reader-bind failure we thought we'd fixed. Keep this in lockstep
/// with the MSI we ship.
pub const MIN_DRIVER_VERSION: (u32, u32, u32) = (3, 6, 2);

/// Format a `(major, minor, revision)` version triple for log messages.
pub fn format_version((major, minor, revision): (u32, u32, u32)) -> String {
    format!("{}.{}.{}", major, minor, revision)
}

/// Compute the lowercase hex SHA-256 of `data`.
pub fn sha256_hex(data: &[u8]) -> String {
    use sha2::{Digest, Sha256};
    let mut hasher = Sha256::new();
    hasher.update(data);
    format!("{:x}", hasher.finalize())
}

/// Validate an MSI payload (bytes in memory) against the pinned size+hash
/// from `WinpkFilterMsiPackage`.
///
/// Why this lives in core and not in the desktop crate: both the auto-install
/// path in `SplitTunnelDriver::install_driver_from_msi` and the explicit
/// `system_install_driver` Tauri command need to refuse corrupted MSIs before
/// handing them to `msiexec /i`. A bad MSI bundled into the NSIS installer
/// (e.g. a partial copy from a flaky disk) would otherwise surface as an
/// opaque msiexec 1603 with no hint that the file itself is the problem.
pub fn validate_msi_payload(data: &[u8], pkg: &WinpkFilterMsiPackage) -> Result<(), String> {
    if data.len() < pkg.min_size_bytes {
        return Err(format!(
            "WinpkFilter MSI too small ({} bytes, expected at least {} bytes). The bundled file is likely truncated — reinstall SwiftTunnel.",
            data.len(),
            pkg.min_size_bytes
        ));
    }

    let digest = sha256_hex(data);
    if digest != pkg.sha256 {
        return Err(format!(
            "WinpkFilter MSI failed integrity check (sha256 mismatch: expected {}, got {}). The bundled file is corrupted — reinstall SwiftTunnel.",
            pkg.sha256, digest
        ));
    }

    Ok(())
}

/// Read `path` and validate it against the pinned size+hash from `pkg`.
pub fn validate_msi_file(path: &Path, pkg: &WinpkFilterMsiPackage) -> Result<(), String> {
    let data =
        std::fs::read(path).map_err(|e| format!("Failed to read {}: {}", path.display(), e))?;
    validate_msi_payload(&data, pkg)
}

/// Detect the native machine architecture using `IsWow64Process2`, with an
/// environment-variable fallback (`PROCESSOR_ARCHITECTURE`).
#[cfg(windows)]
pub fn detect_native_arch() -> WinpkFilterMsiArch {
    use windows::Win32::System::Threading::{GetCurrentProcess, IsWow64Process2};

    let mut process_machine: windows::Win32::System::SystemInformation::IMAGE_FILE_MACHINE =
        Default::default();
    let mut native_machine: windows::Win32::System::SystemInformation::IMAGE_FILE_MACHINE =
        Default::default();

    // SAFETY: GetCurrentProcess returns a pseudo-handle that does not need closing.
    // IsWow64Process2 writes into the two out-params we provide.
    unsafe {
        if IsWow64Process2(
            GetCurrentProcess(),
            &mut process_machine,
            Some(&mut native_machine),
        )
        .is_ok()
        {
            // IMAGE_FILE_MACHINE_ARM64 = 0xAA64
            if native_machine.0 == 0xAA64 {
                return WinpkFilterMsiArch::Arm64;
            }
            return WinpkFilterMsiArch::X64;
        }
    }

    // Fallback: PROCESSOR_ARCHITECTURE env var.
    if let Ok(arch) = std::env::var("PROCESSOR_ARCHITECTURE") {
        if arch.eq_ignore_ascii_case("ARM64") {
            return WinpkFilterMsiArch::Arm64;
        }
    }

    WinpkFilterMsiArch::X64
}

#[cfg(not(windows))]
pub fn detect_native_arch() -> WinpkFilterMsiArch {
    WinpkFilterMsiArch::X64
}

/// Return the MSI package matching the native machine architecture.
pub fn native_msi_package() -> &'static WinpkFilterMsiPackage {
    match detect_native_arch() {
        WinpkFilterMsiArch::X64 => &MSI_PACKAGE_X64,
        WinpkFilterMsiArch::Arm64 => &MSI_PACKAGE_ARM64,
    }
}

// ═══════════════════════════════════════════════════════════════════════════════
//  DRIVER PACKAGE (INF/SYS/CAT) UTILITIES
// ═══════════════════════════════════════════════════════════════════════════════

pub const DRIVER_PACKAGE_ROOT_RELATIVE_DIR: &str = "winpkfilter";
pub const DRIVER_PACKAGE_LEGACY_RELATIVE_DIR: &str = "winpkfilter/win10";
pub const DRIVER_PACKAGE_WIN10_DIR: &str = "win10";
pub const DRIVER_INF_NAME: &str = "ndisrd_lwf.inf";
pub const DRIVER_SYS_NAME: &str = "ndisrd.sys";
pub const DRIVER_CAT_NAME: &str = "ndisrd.cat";
const DRIVER_COMPONENT_ID: &str = "nt_ndisrd";
const DRIVER_INF_MIN_SIZE_BYTES: u64 = 256;
const DRIVER_SYS_MIN_SIZE_BYTES: u64 = 4 * 1024;
const DRIVER_CAT_MIN_SIZE_BYTES: u64 = 256;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DriverPackage {
    pub root_dir: PathBuf,
    pub inf_path: PathBuf,
    pub sys_path: PathBuf,
    pub cat_path: PathBuf,
}

pub fn driver_package_relative_dir_for_arch(arch: WinpkFilterMsiArch) -> PathBuf {
    PathBuf::from(DRIVER_PACKAGE_ROOT_RELATIVE_DIR)
        .join(arch.to_string())
        .join(DRIVER_PACKAGE_WIN10_DIR)
}

pub fn native_driver_package_relative_dir() -> PathBuf {
    driver_package_relative_dir_for_arch(detect_native_arch())
}

struct DriverPackageFileSpec {
    name: &'static str,
    min_size_bytes: u64,
}

const DRIVER_PACKAGE_FILE_SPECS: [DriverPackageFileSpec; 3] = [
    DriverPackageFileSpec {
        name: DRIVER_INF_NAME,
        min_size_bytes: DRIVER_INF_MIN_SIZE_BYTES,
    },
    DriverPackageFileSpec {
        name: DRIVER_SYS_NAME,
        min_size_bytes: DRIVER_SYS_MIN_SIZE_BYTES,
    },
    DriverPackageFileSpec {
        name: DRIVER_CAT_NAME,
        min_size_bytes: DRIVER_CAT_MIN_SIZE_BYTES,
    },
];

pub fn driver_package_not_found_message() -> String {
    "WinpkFilter driver package not found in app resources.".to_string()
}

#[cfg(windows)]
pub fn default_program_files_dir() -> PathBuf {
    PathBuf::from(std::env::var("ProgramFiles").unwrap_or_else(|_| "C:\\Program Files".to_string()))
}

#[cfg(not(windows))]
pub fn default_program_files_dir() -> PathBuf {
    PathBuf::new()
}

#[cfg(windows)]
pub fn driver_package_candidate_paths(
    resource_dir: Option<&Path>,
    exe_dir: Option<&Path>,
    program_files_dir: &Path,
) -> Vec<PathBuf> {
    let mut candidates = Vec::new();
    let native_rel = native_driver_package_relative_dir();
    let legacy_rel = PathBuf::from(DRIVER_PACKAGE_LEGACY_RELATIVE_DIR);

    if let Some(dir) = resource_dir {
        candidates.push(dir.join("drivers").join(&native_rel));
        candidates.push(dir.join(&native_rel));
        candidates.push(dir.join("drivers").join(&legacy_rel));
        candidates.push(dir.join(&legacy_rel));
    }

    if let Some(dir) = exe_dir {
        candidates.push(dir.join("drivers").join(&native_rel));
        candidates.push(dir.join("resources").join("drivers").join(&native_rel));
        candidates.push(dir.join("resources").join(&native_rel));
        candidates.push(dir.join("drivers").join(&legacy_rel));
        candidates.push(dir.join("resources").join("drivers").join(&legacy_rel));
        candidates.push(dir.join("resources").join(&legacy_rel));
    }

    let install_root = program_files_dir.join("SwiftTunnel");
    candidates.push(
        install_root
            .join("resources")
            .join("drivers")
            .join(&native_rel),
    );
    candidates.push(install_root.join("drivers").join(&native_rel));
    candidates.push(
        install_root
            .join("resources")
            .join("drivers")
            .join(&legacy_rel),
    );
    candidates.push(install_root.join("drivers").join(&legacy_rel));

    candidates
}

#[cfg(not(windows))]
pub fn driver_package_candidate_paths(
    _resource_dir: Option<&Path>,
    _exe_dir: Option<&Path>,
    _program_files_dir: &Path,
) -> Vec<PathBuf> {
    Vec::new()
}

pub fn validate_driver_package_dir(package_dir: &Path) -> Result<DriverPackage, String> {
    let inf_path = package_dir.join(DRIVER_INF_NAME);
    let sys_path = package_dir.join(DRIVER_SYS_NAME);
    let cat_path = package_dir.join(DRIVER_CAT_NAME);

    let mut missing = Vec::new();
    let mut undersized = Vec::new();

    for spec in DRIVER_PACKAGE_FILE_SPECS {
        let path = package_dir.join(spec.name);
        match std::fs::metadata(&path) {
            Ok(metadata) if metadata.is_file() => {
                if metadata.len() < spec.min_size_bytes {
                    undersized.push(format!(
                        "{} ({} bytes, expected at least {} bytes)",
                        spec.name,
                        metadata.len(),
                        spec.min_size_bytes
                    ));
                }
            }
            Ok(_) => missing.push(spec.name),
            Err(_) => missing.push(spec.name),
        }
    }

    if !missing.is_empty() || !undersized.is_empty() {
        let mut reasons = Vec::new();
        if !missing.is_empty() {
            reasons.push(format!("missing: {}", missing.join(", ")));
        }
        if !undersized.is_empty() {
            reasons.push(format!("undersized: {}", undersized.join(", ")));
        }

        return Err(format!(
            "Incomplete WinpkFilter driver package in {} ({}).",
            package_dir.display(),
            reasons.join("; ")
        ));
    }

    Ok(DriverPackage {
        root_dir: package_dir.to_path_buf(),
        inf_path,
        sys_path,
        cat_path,
    })
}

pub fn find_bundled_driver_package(
    resource_dir: Option<&Path>,
    exe_dir: Option<&Path>,
    program_files_dir: &Path,
) -> Result<DriverPackage, String> {
    let mut first_invalid: Option<String> = None;

    for candidate in driver_package_candidate_paths(resource_dir, exe_dir, program_files_dir) {
        if !candidate.exists() {
            continue;
        }

        match validate_driver_package_dir(&candidate) {
            Ok(package) => return Ok(package),
            Err(err) => {
                if first_invalid.is_none() {
                    first_invalid = Some(err);
                }
            }
        }
    }

    Err(first_invalid.unwrap_or_else(driver_package_not_found_message))
}

#[cfg(windows)]
fn pnputil_success_exit_code(code: i32) -> bool {
    code == 0
}

#[cfg(windows)]
fn pnputil_reboot_required_exit_code(code: i32) -> bool {
    code == 3010
}

fn driver_netcfg_install_command(inf_path: &str) -> (&'static str, [&str; 6]) {
    (
        "netcfg",
        ["/l", inf_path, "/c", "s", "/i", DRIVER_COMPONENT_ID],
    )
}

fn driver_pnputil_install_command(inf_path: &str) -> (&'static str, [&str; 3]) {
    ("pnputil", ["/add-driver", inf_path, "/install"])
}

#[cfg(windows)]
fn pnputil_output_detail(output: &std::process::Output) -> String {
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

/// Exit codes from pnputil that indicate a transient/retryable failure.
///
/// - `2` (`ERROR_FILE_NOT_FOUND`): can happen transiently when the driver store is
///   being reorganized or another installer holds a lock.
/// - `5` (`ERROR_ACCESS_DENIED`): can occur if another process briefly holds the
///   driver store lock.
#[cfg(windows)]
fn pnputil_retryable_exit_code(code: i32) -> bool {
    matches!(code, 2 | 5)
}

#[cfg(windows)]
fn netcfg_already_installed_detail(detail: &str) -> bool {
    let detail = detail.to_ascii_lowercase();
    detail.contains("already installed")
        || detail.contains("already exists")
        || detail.contains("0x800700b7")
}

#[cfg(windows)]
fn run_netcfg_install(inf_path: &str) -> Result<(), String> {
    let (program, args) = driver_netcfg_install_command(inf_path);
    let output = hidden_command(program)
        .args(args)
        .output()
        .map_err(|e| format!("Failed to run netcfg: {}", e))?;

    let code = output.status.code().unwrap_or(-1);
    if output.status.success() {
        log::info!("WinpkFilter network component installed/refreshed with netcfg");
        return Ok(());
    }

    let detail = pnputil_output_detail(&output);
    if netcfg_already_installed_detail(&detail) {
        log::info!(
            "WinpkFilter network component already installed according to netcfg: {}",
            detail
        );
        return Ok(());
    }

    if pnputil_reboot_required_exit_code(code) {
        if detail.is_empty() {
            return Err(
                "Reboot required to finish WinpkFilter binding installation. netcfg exited with code 3010."
                    .to_string(),
            );
        }
        return Err(format!(
            "Reboot required to finish WinpkFilter binding installation. netcfg exited with code 3010: {}",
            detail
        ));
    }

    if detail.is_empty() {
        Err(format!("netcfg failed with code {}", code))
    } else {
        Err(format!("netcfg failed with code {}: {}", code, detail))
    }
}

/// Maximum number of pnputil install attempts before giving up.
const PNPUTIL_INSTALL_MAX_ATTEMPTS: u32 = 3;

#[cfg(windows)]
fn run_pnputil_install(inf_path: &str) -> Result<(), String> {
    let mut last_error = String::new();

    for attempt in 1..=PNPUTIL_INSTALL_MAX_ATTEMPTS {
        if attempt > 1 {
            let delay_ms = 1000 * (attempt - 1);
            log::info!(
                "Retrying pnputil install (attempt {}/{}), waiting {}ms...",
                attempt,
                PNPUTIL_INSTALL_MAX_ATTEMPTS,
                delay_ms
            );
            std::thread::sleep(std::time::Duration::from_millis(delay_ms as u64));
        }

        let (program, args) = driver_pnputil_install_command(inf_path);
        let output = match hidden_command(program).args(args).output() {
            Ok(output) => output,
            Err(e) => {
                last_error = format!("Failed to run pnputil: {}", e);
                log::warn!(
                    "{} (attempt {}/{})",
                    last_error,
                    attempt,
                    PNPUTIL_INSTALL_MAX_ATTEMPTS
                );
                continue;
            }
        };

        let code = output.status.code().unwrap_or(-1);
        if pnputil_success_exit_code(code) {
            // Verify the driver actually appeared in the store.
            match find_installed_driver_published_name() {
                Ok(Some(published)) => {
                    log::info!(
                        "WinpkFilter driver installed and verified in store as {}",
                        published
                    );
                }
                Ok(None) => {
                    log::warn!(
                        "pnputil exited with code {} but driver not found in store; \
                         proceeding anyway (driver may appear after binding)",
                        code
                    );
                }
                Err(e) => {
                    log::warn!(
                        "Could not verify driver store after install: {}; proceeding anyway",
                        e
                    );
                }
            }
            return Ok(());
        }

        if pnputil_reboot_required_exit_code(code) {
            let detail = pnputil_output_detail(&output);
            if detail.is_empty() {
                return Err(
                    "Reboot required to finish driver installation. pnputil exited with code 3010."
                        .to_string(),
                );
            }
            return Err(format!(
                "Reboot required to finish driver installation. pnputil exited with code 3010: {}",
                detail
            ));
        }

        let detail = pnputil_output_detail(&output);
        last_error = if detail.is_empty() {
            format!("pnputil failed with code {}", code)
        } else {
            format!("pnputil failed with code {}: {}", code, detail)
        };

        log::warn!(
            "{} (attempt {}/{})",
            last_error,
            attempt,
            PNPUTIL_INSTALL_MAX_ATTEMPTS
        );

        // Only retry on transient failure codes.
        if !pnputil_retryable_exit_code(code) {
            break;
        }
    }

    Err(last_error)
}

#[cfg(windows)]
pub fn install_driver_from_package_dir(package_dir: &Path) -> Result<(), String> {
    let package = validate_driver_package_dir(package_dir)?;
    let inf_path = package.inf_path.to_string_lossy().to_string();

    match find_installed_driver_published_name() {
        Ok(Some(published)) => {
            log::info!(
                "WinpkFilter driver already present in driver store as {}; refreshing network component binding",
                published
            );
        }
        Ok(None) => {
            log::info!("WinpkFilter driver package not present in driver store; installing");
        }
        Err(e) => {
            // Non-fatal: if we can't query the store, proceed with install anyway.
            log::warn!("Could not query driver store before install: {}", e);
        }
    }

    let mut issues = Vec::new();

    if let Err(e) = run_netcfg_install(&inf_path) {
        log::warn!("WinpkFilter netcfg binding install failed: {}", e);
        issues.push(format!("netcfg binding install failed: {}", e));
    }

    if let Err(e) = run_pnputil_install(&inf_path) {
        log::warn!("WinpkFilter pnputil driver install failed: {}", e);
        issues.push(format!("pnputil driver install failed: {}", e));
    }

    if issues
        .iter()
        .any(|issue| issue.to_ascii_lowercase().contains("reboot required"))
    {
        Err(issues.join("; "))
    } else if issues.len() >= 2 {
        Err(issues.join("; "))
    } else {
        Ok(())
    }
}

#[cfg(not(windows))]
pub fn install_driver_from_package_dir(_package_dir: &Path) -> Result<(), String> {
    Err("WinpkFilter installation is only supported on Windows".to_string())
}

#[cfg(windows)]
fn parse_enum_drivers_output(output: &str, original_name: &str) -> Option<String> {
    let target_name = original_name.to_ascii_lowercase();
    let mut published_name: Option<String> = None;
    let mut current_original_name: Option<String> = None;

    for line in output.lines().chain(std::iter::once("")) {
        let trimmed = line.trim();
        if trimmed.is_empty() {
            if current_original_name.as_deref() == Some(target_name.as_str()) {
                return published_name;
            }
            published_name = None;
            current_original_name = None;
            continue;
        }

        let Some((key, value)) = trimmed.split_once(':') else {
            continue;
        };

        let key = key.trim().to_ascii_lowercase();
        let value = value.trim();
        match key.as_str() {
            "published name" => published_name = Some(value.to_string()),
            "original name" => current_original_name = Some(value.to_ascii_lowercase()),
            _ => {}
        }
    }

    None
}

#[cfg(windows)]
pub fn find_installed_driver_published_name() -> Result<Option<String>, String> {
    let output = hidden_command("pnputil")
        .args(["/enum-drivers"])
        .output()
        .map_err(|e| format!("Failed to run pnputil /enum-drivers: {}", e))?;

    let code = output.status.code().unwrap_or(-1);
    if !output.status.success() {
        let detail = pnputil_output_detail(&output);
        if detail.is_empty() {
            return Err(format!("pnputil /enum-drivers failed with code {}", code));
        }
        return Err(format!(
            "pnputil /enum-drivers failed with code {}: {}",
            code, detail
        ));
    }

    let stdout = String::from_utf8_lossy(&output.stdout);
    Ok(parse_enum_drivers_output(&stdout, DRIVER_INF_NAME))
}

#[cfg(not(windows))]
pub fn find_installed_driver_published_name() -> Result<Option<String>, String> {
    Ok(None)
}

#[cfg(windows)]
pub fn remove_installed_driver_package() -> Result<(), String> {
    let Some(published_name) = find_installed_driver_published_name()? else {
        log::info!("WinpkFilter driver package is not present in the Driver Store");
        return Ok(());
    };

    let output = hidden_command("pnputil")
        .args(["/delete-driver", &published_name, "/uninstall", "/force"])
        .output()
        .map_err(|e| format!("Failed to run pnputil /delete-driver: {}", e))?;

    let code = output.status.code().unwrap_or(-1);
    if pnputil_success_exit_code(code) {
        return Ok(());
    }

    if pnputil_reboot_required_exit_code(code) {
        let detail = pnputil_output_detail(&output);
        if detail.is_empty() {
            return Err(format!(
                "Reboot required to finish driver package removal. pnputil /delete-driver {} exited with code 3010.",
                published_name
            ));
        }
        return Err(format!(
            "Reboot required to finish driver package removal. pnputil /delete-driver {} exited with code 3010: {}",
            published_name, detail
        ));
    }

    let detail = pnputil_output_detail(&output);
    if detail.is_empty() {
        Err(format!(
            "pnputil /delete-driver {} failed with code {}",
            published_name, code
        ))
    } else {
        Err(format!(
            "pnputil /delete-driver {} failed with code {}: {}",
            published_name, code, detail
        ))
    }
}

#[cfg(not(windows))]
pub fn remove_installed_driver_package() -> Result<(), String> {
    Err("WinpkFilter removal is only supported on Windows".to_string())
}

#[cfg(test)]
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

    fn write_file_with_size(path: &Path, size: usize) {
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent).expect("create parent dirs");
        }
        fs::write(path, vec![b'x'; size]).expect("write temp file");
    }

    fn write_valid_driver_package(dir: &Path) {
        write_file_with_size(
            &dir.join(DRIVER_INF_NAME),
            DRIVER_INF_MIN_SIZE_BYTES as usize,
        );
        write_file_with_size(
            &dir.join(DRIVER_SYS_NAME),
            DRIVER_SYS_MIN_SIZE_BYTES as usize,
        );
        write_file_with_size(
            &dir.join(DRIVER_CAT_NAME),
            DRIVER_CAT_MIN_SIZE_BYTES as usize,
        );
    }

    #[test]
    fn validate_driver_package_dir_accepts_complete_package() {
        let base = unique_temp_dir("winpkfilter_package_ok");
        write_valid_driver_package(&base);

        let package = validate_driver_package_dir(&base).expect("package should validate");
        let root_dir = package.root_dir.clone();
        assert_eq!(package.root_dir, base);
        assert!(package.inf_path.ends_with(DRIVER_INF_NAME));

        let _ = fs::remove_dir_all(root_dir);
    }

    #[test]
    fn validate_driver_package_dir_rejects_missing_files() {
        let base = unique_temp_dir("winpkfilter_package_missing");
        write_file_with_size(
            &base.join(DRIVER_INF_NAME),
            DRIVER_INF_MIN_SIZE_BYTES as usize,
        );

        let err = validate_driver_package_dir(&base).expect_err("package should be incomplete");
        assert!(err.contains(DRIVER_SYS_NAME));
        assert!(err.contains(DRIVER_CAT_NAME));

        let _ = fs::remove_dir_all(base);
    }

    #[test]
    fn validate_driver_package_dir_rejects_undersized_files() {
        let base = unique_temp_dir("winpkfilter_package_undersized");
        write_file_with_size(&base.join(DRIVER_INF_NAME), 1);
        write_file_with_size(&base.join(DRIVER_SYS_NAME), 1);
        write_file_with_size(&base.join(DRIVER_CAT_NAME), 1);

        let err = validate_driver_package_dir(&base).expect_err("package should reject stubs");
        assert!(err.contains("undersized"));
        assert!(err.contains(DRIVER_INF_NAME));
        assert!(err.contains(DRIVER_SYS_NAME));
        assert!(err.contains(DRIVER_CAT_NAME));

        let _ = fs::remove_dir_all(base);
    }

    #[test]
    fn find_bundled_driver_package_prefers_resource_dir() {
        let base = unique_temp_dir("winpkfilter_candidates");
        let resource_dir = base.join("resources");
        let exe_dir = base.join("exe");
        let program_files_dir = base.join("ProgramFiles");

        let native_rel = native_driver_package_relative_dir();
        let preferred = resource_dir.join("drivers").join(&native_rel);
        let fallback = exe_dir.join("drivers").join(&native_rel);

        for dir in [&preferred, &fallback] {
            write_valid_driver_package(dir);
        }

        let package = find_bundled_driver_package(
            Some(resource_dir.as_path()),
            Some(exe_dir.as_path()),
            program_files_dir.as_path(),
        )
        .expect("package should resolve");

        assert_eq!(package.root_dir, preferred);

        let _ = fs::remove_dir_all(base);
    }

    #[test]
    fn parse_enum_drivers_output_finds_matching_package() {
        #[cfg(windows)]
        {
            let output = r"
Microsoft PnP Utility

Published Name:     oem7.inf
Original Name:      ndisrd_lwf.inf
Provider Name:      NDISAPI

Published Name:     oem8.inf
Original Name:      something_else.inf
";

            assert_eq!(
                parse_enum_drivers_output(output, DRIVER_INF_NAME).as_deref(),
                Some("oem7.inf")
            );
        }
    }

    #[test]
    fn parse_enum_drivers_output_returns_none_for_empty_output() {
        #[cfg(windows)]
        {
            assert_eq!(parse_enum_drivers_output("", DRIVER_INF_NAME), None);
            assert_eq!(
                parse_enum_drivers_output("Microsoft PnP Utility\n\n", DRIVER_INF_NAME),
                None
            );
        }
    }

    #[test]
    fn parse_enum_drivers_output_returns_none_when_no_match() {
        #[cfg(windows)]
        {
            let output = r"
Microsoft PnP Utility

Published Name:     oem5.inf
Original Name:      some_other_driver.inf
Provider Name:      OtherVendor

Published Name:     oem6.inf
Original Name:      yet_another.inf
Provider Name:      AnotherVendor
";
            assert_eq!(parse_enum_drivers_output(output, DRIVER_INF_NAME), None);
        }
    }

    #[test]
    fn parse_enum_drivers_output_case_insensitive_original_name() {
        #[cfg(windows)]
        {
            let output = r"
Published Name:     oem12.inf
Original Name:      NDISRD_LWF.INF
Provider Name:      NDISAPI
";
            assert_eq!(
                parse_enum_drivers_output(output, DRIVER_INF_NAME).as_deref(),
                Some("oem12.inf")
            );
        }
    }

    #[test]
    fn pnputil_retryable_exit_codes() {
        #[cfg(windows)]
        {
            assert!(pnputil_retryable_exit_code(2));
            assert!(pnputil_retryable_exit_code(5));
            assert!(!pnputil_retryable_exit_code(0));
            assert!(!pnputil_retryable_exit_code(1));
            assert!(!pnputil_retryable_exit_code(3010));
        }
    }

    #[test]
    fn driver_rebind_commands_include_netcfg_and_pnputil_install() {
        let inf_path = r"C:\Program Files\SwiftTunnel\drivers\ndisrd_lwf.inf";
        let (netcfg_program, netcfg_args) = driver_netcfg_install_command(inf_path);
        assert_eq!(netcfg_program, "netcfg");
        assert_eq!(netcfg_args, ["/l", inf_path, "/c", "s", "/i", "nt_ndisrd"]);

        let (pnputil_program, pnputil_args) = driver_pnputil_install_command(inf_path);
        assert_eq!(pnputil_program, "pnputil");
        assert_eq!(pnputil_args, ["/add-driver", inf_path, "/install"]);
    }

    #[test]
    fn netcfg_already_installed_detection_is_lenient() {
        #[cfg(windows)]
        {
            assert!(netcfg_already_installed_detail(
                "The requested component is already installed."
            ));
            assert!(netcfg_already_installed_detail(
                "0x800700b7 Cannot create a file when that file already exists"
            ));
            assert!(!netcfg_already_installed_detail("Access is denied."));
        }
    }

    // ── MSI package metadata & arch detection tests ──

    #[test]
    fn detect_native_arch_returns_valid_variant() {
        let arch = detect_native_arch();
        assert!(
            arch == WinpkFilterMsiArch::X64 || arch == WinpkFilterMsiArch::Arm64,
            "unexpected arch: {:?}",
            arch
        );
    }

    #[test]
    fn native_msi_package_has_valid_metadata() {
        let pkg = native_msi_package();
        assert!(!pkg.msi_name.is_empty());
        assert!(!pkg.download_url.is_empty());
        assert_eq!(pkg.sha256.len(), 64); // hex SHA-256 is 64 chars
        assert!(pkg.min_size_bytes > 0);
    }

    #[test]
    fn all_msi_packages_have_unique_names() {
        let names: Vec<&str> = ALL_MSI_PACKAGES.iter().map(|p| p.msi_name).collect();
        let unique: std::collections::HashSet<&str> = names.iter().copied().collect();
        assert_eq!(
            names.len(),
            unique.len(),
            "duplicate MSI names: {:?}",
            names
        );
    }

    #[test]
    fn all_msi_packages_have_unique_sha256() {
        let shas: Vec<&str> = ALL_MSI_PACKAGES.iter().map(|p| p.sha256).collect();
        let unique: std::collections::HashSet<&str> = shas.iter().copied().collect();
        assert_eq!(shas.len(), unique.len(), "duplicate SHA-256 values");
    }

    #[test]
    fn msi_arch_display() {
        assert_eq!(WinpkFilterMsiArch::X64.to_string(), "x64");
        assert_eq!(WinpkFilterMsiArch::Arm64.to_string(), "arm64");
    }

    #[test]
    fn x64_package_has_expected_name() {
        assert_eq!(MSI_PACKAGE_X64.msi_name, "WinpkFilter-x64.msi");
    }

    #[test]
    fn arm64_package_has_expected_name() {
        assert_eq!(MSI_PACKAGE_ARM64.msi_name, "WinpkFilter-arm64.msi");
    }

    #[test]
    fn native_msi_package_matches_detect_native_arch() {
        let arch = detect_native_arch();
        let pkg = native_msi_package();
        assert_eq!(pkg.arch, arch);
    }
}
