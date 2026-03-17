use std::path::{Path, PathBuf};

#[cfg(windows)]
use crate::hidden_command;
#[cfg(windows)]
use windows::Win32::System::{
    SystemInformation::IMAGE_FILE_MACHINE_UNKNOWN,
    Threading::{GetCurrentProcess, IsWow64Process2},
};

pub const DRIVER_PACKAGE_RELATIVE_DIR: &str = "winpkfilter/win10";
pub const DRIVER_INF_NAME: &str = "ndisrd_lwf.inf";
pub const DRIVER_SYS_NAME: &str = "ndisrd.sys";
pub const DRIVER_CAT_NAME: &str = "ndisrd.cat";
pub const DRIVER_MSI_MIN_SIZE_BYTES: usize = 500_000;
const DRIVER_INF_MIN_SIZE_BYTES: u64 = 256;
const DRIVER_SYS_MIN_SIZE_BYTES: u64 = 4 * 1024;
const DRIVER_CAT_MIN_SIZE_BYTES: u64 = 256;
const IMAGE_FILE_MACHINE_AMD64_CODE: u16 = 0x8664;
const IMAGE_FILE_MACHINE_ARM64_CODE: u16 = 0xAA64;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DriverMsiArchitecture {
    X64,
    Arm64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DriverMsiPackage {
    pub architecture: DriverMsiArchitecture,
    pub bundled_name: &'static str,
    pub release_asset_name: &'static str,
    pub download_url: &'static str,
    pub sha256: &'static str,
}

pub const DRIVER_MSI_X64: DriverMsiPackage = DriverMsiPackage {
    architecture: DriverMsiArchitecture::X64,
    bundled_name: "WinpkFilter-x64.msi",
    release_asset_name: "Windows.Packet.Filter.3.6.2.1.x64.msi",
    download_url: "https://github.com/wiresock/ndisapi/releases/download/v3.6.2/Windows.Packet.Filter.3.6.2.1.x64.msi",
    sha256: "9c388c0b7f189f7fa98720bae2caecf7d64f30910838b80b438ecf8956b8502c",
};

pub const DRIVER_MSI_ARM64: DriverMsiPackage = DriverMsiPackage {
    architecture: DriverMsiArchitecture::Arm64,
    bundled_name: "WinpkFilter-arm64.msi",
    release_asset_name: "Windows.Packet.Filter.3.6.2.1.ARM64.msi",
    download_url: "https://github.com/wiresock/ndisapi/releases/download/v3.6.2/Windows.Packet.Filter.3.6.2.1.ARM64.msi",
    sha256: "b13c6832c9e5c0c14948bbf5c17ccbe65dff55c0f6069df01494d97ebd1f3d69",
};

const DRIVER_MSI_PACKAGES: [DriverMsiPackage; 2] = [DRIVER_MSI_X64, DRIVER_MSI_ARM64];

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DriverPackage {
    pub root_dir: PathBuf,
    pub inf_path: PathBuf,
    pub sys_path: PathBuf,
    pub cat_path: PathBuf,
}

pub fn driver_msi_packages() -> &'static [DriverMsiPackage] {
    &DRIVER_MSI_PACKAGES
}

pub fn driver_msi_package_for_arch(architecture: DriverMsiArchitecture) -> DriverMsiPackage {
    match architecture {
        DriverMsiArchitecture::X64 => DRIVER_MSI_X64,
        DriverMsiArchitecture::Arm64 => DRIVER_MSI_ARM64,
    }
}

fn parse_processor_architecture(value: &str) -> Option<DriverMsiArchitecture> {
    match value.trim().to_ascii_uppercase().as_str() {
        "ARM64" | "AARCH64" => Some(DriverMsiArchitecture::Arm64),
        "AMD64" | "X86_64" | "X64" => Some(DriverMsiArchitecture::X64),
        _ => None,
    }
}

fn machine_architecture(machine: u16) -> Option<DriverMsiArchitecture> {
    match machine {
        IMAGE_FILE_MACHINE_ARM64_CODE => Some(DriverMsiArchitecture::Arm64),
        IMAGE_FILE_MACHINE_AMD64_CODE => Some(DriverMsiArchitecture::X64),
        _ => None,
    }
}

#[cfg(windows)]
fn native_driver_msi_architecture() -> Option<DriverMsiArchitecture> {
    let mut process_machine = IMAGE_FILE_MACHINE_UNKNOWN;
    let mut native_machine = IMAGE_FILE_MACHINE_UNKNOWN;

    unsafe {
        IsWow64Process2(
            GetCurrentProcess(),
            &mut process_machine,
            Some(&mut native_machine as *mut _),
        )
        .ok()?;
    }

    machine_architecture(native_machine.0).or_else(|| machine_architecture(process_machine.0))
}

#[cfg(not(windows))]
fn native_driver_msi_architecture() -> Option<DriverMsiArchitecture> {
    None
}

fn driver_msi_package_for_detected_architecture(
    native_architecture: Option<DriverMsiArchitecture>,
    processor_arch_w6432: Option<&str>,
    processor_arch: Option<&str>,
) -> DriverMsiPackage {
    if let Some(architecture) = native_architecture {
        return driver_msi_package_for_arch(architecture);
    }

    if let Some(architecture) = processor_arch_w6432.and_then(parse_processor_architecture) {
        return driver_msi_package_for_arch(architecture);
    }

    if let Some(architecture) = processor_arch.and_then(parse_processor_architecture) {
        return driver_msi_package_for_arch(architecture);
    }

    DRIVER_MSI_X64
}

pub fn current_driver_msi_package() -> DriverMsiPackage {
    let processor_arch_w6432 = std::env::var("PROCESSOR_ARCHITEW6432").ok();
    let processor_arch = std::env::var("PROCESSOR_ARCHITECTURE").ok();
    driver_msi_package_for_detected_architecture(
        native_driver_msi_architecture(),
        processor_arch_w6432.as_deref(),
        processor_arch.as_deref(),
    )
}

pub fn driver_msi_packages_for_cleanup() -> Vec<DriverMsiPackage> {
    let preferred = current_driver_msi_package();
    let mut packages = vec![preferred];
    packages.extend(
        DRIVER_MSI_PACKAGES
            .into_iter()
            .filter(|package| package.architecture != preferred.architecture),
    );
    packages
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

    if let Some(dir) = resource_dir {
        candidates.push(dir.join("drivers").join(DRIVER_PACKAGE_RELATIVE_DIR));
        candidates.push(dir.join(DRIVER_PACKAGE_RELATIVE_DIR));
    }

    if let Some(dir) = exe_dir {
        candidates.push(dir.join("drivers").join(DRIVER_PACKAGE_RELATIVE_DIR));
        candidates.push(
            dir.join("resources")
                .join("drivers")
                .join(DRIVER_PACKAGE_RELATIVE_DIR),
        );
        candidates.push(dir.join("resources").join(DRIVER_PACKAGE_RELATIVE_DIR));
    }

    let install_root = program_files_dir.join("SwiftTunnel");
    candidates.push(
        install_root
            .join("resources")
            .join("drivers")
            .join(DRIVER_PACKAGE_RELATIVE_DIR),
    );
    candidates.push(
        install_root
            .join("drivers")
            .join(DRIVER_PACKAGE_RELATIVE_DIR),
    );

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
    matches!(code, 0 | 3010)
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

/// Maximum number of pnputil install attempts before giving up.
const PNPUTIL_INSTALL_MAX_ATTEMPTS: u32 = 3;

#[cfg(windows)]
pub fn install_driver_from_package_dir(package_dir: &Path) -> Result<(), String> {
    let package = validate_driver_package_dir(package_dir)?;
    let inf_path = package.inf_path.to_string_lossy().to_string();

    // Idempotency: skip install if the driver is already in the store.
    match find_installed_driver_published_name() {
        Ok(Some(published)) => {
            log::info!(
                "WinpkFilter driver already present in driver store as {}; skipping install",
                published
            );
            return Ok(());
        }
        Ok(None) => {} // Not installed yet — proceed.
        Err(e) => {
            // Non-fatal: if we can't query the store, proceed with install anyway.
            log::warn!("Could not query driver store before install: {}", e);
        }
    }

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

        let output = match hidden_command("pnputil")
            .args(["/add-driver", &inf_path, "/install"])
            .output()
        {
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

        let preferred = resource_dir
            .join("drivers")
            .join(DRIVER_PACKAGE_RELATIVE_DIR);
        let fallback = exe_dir.join("drivers").join(DRIVER_PACKAGE_RELATIVE_DIR);

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
    fn driver_msi_package_prefers_native_arch_from_w6432() {
        let package =
            driver_msi_package_for_detected_architecture(None, Some("ARM64"), Some("AMD64"));
        assert_eq!(package, DRIVER_MSI_ARM64);
    }

    #[test]
    fn driver_msi_package_prefers_detected_native_architecture() {
        let package = driver_msi_package_for_detected_architecture(
            Some(DriverMsiArchitecture::Arm64),
            None,
            Some("AMD64"),
        );
        assert_eq!(package, DRIVER_MSI_ARM64);
    }

    #[test]
    fn driver_msi_package_uses_processor_arch_when_native() {
        let package = driver_msi_package_for_detected_architecture(None, None, Some("ARM64"));
        assert_eq!(package, DRIVER_MSI_ARM64);
    }

    #[test]
    fn driver_msi_package_defaults_to_x64_for_unknown_architecture() {
        let package =
            driver_msi_package_for_detected_architecture(None, Some("mips"), Some("sparc"));
        assert_eq!(package, DRIVER_MSI_X64);
    }

    #[test]
    fn driver_msi_packages_for_cleanup_prefers_current_package() {
        let packages = driver_msi_packages_for_cleanup();
        assert_eq!(
            packages.first().copied(),
            Some(current_driver_msi_package())
        );
        assert_eq!(packages.len(), DRIVER_MSI_PACKAGES.len());
    }
}
