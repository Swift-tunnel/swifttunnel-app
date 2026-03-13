use std::path::{Path, PathBuf};

#[cfg(windows)]
use crate::hidden_command;

pub const DRIVER_PACKAGE_RELATIVE_DIR: &str = "winpkfilter/win10";
pub const DRIVER_INF_NAME: &str = "ndisrd_lwf.inf";
pub const DRIVER_SYS_NAME: &str = "ndisrd.sys";
pub const DRIVER_CAT_NAME: &str = "ndisrd.cat";
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

#[cfg(windows)]
pub fn install_driver_from_package_dir(package_dir: &Path) -> Result<(), String> {
    let package = validate_driver_package_dir(package_dir)?;
    let inf_path = package.inf_path.to_string_lossy().to_string();

    let output = hidden_command("pnputil")
        .args(["/add-driver", &inf_path, "/install"])
        .output()
        .map_err(|e| format!("Failed to run pnputil: {}", e))?;

    let code = output.status.code().unwrap_or(-1);
    if pnputil_success_exit_code(code) {
        return Ok(());
    }

    let detail = pnputil_output_detail(&output);
    if detail.is_empty() {
        Err(format!("pnputil failed with code {}", code))
    } else {
        Err(format!("pnputil failed with code {}: {}", code, detail))
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
}
