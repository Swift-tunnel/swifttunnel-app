//! Legacy cleanup for the removed GoodbyeDPI country-ban bypass feature.
//!
//! New SwiftTunnel builds do not start GoodbyeDPI. This module only removes
//! process/file residue left by v2.1.9-era installs during upgrade or uninstall.

use log::info;
use std::collections::HashSet;
use std::fs;
use std::path::{Path, PathBuf};

const GOODBYEDPI_EXE_NAME: &str = "goodbyedpi.exe";

pub fn cleanup_for_uninstall() -> Result<(), String> {
    let mut errors = Vec::new();

    if cfg!(windows)
        && let Err(e) = stop_managed_goodbyedpi_processes()
    {
        errors.push(e);
    }

    if let Err(e) = remove_goodbyedpi_data_dir() {
        errors.push(e);
    }

    if errors.is_empty() {
        Ok(())
    } else {
        Err(errors.join("; "))
    }
}

fn goodbyedpi_data_dir() -> PathBuf {
    std::env::var_os("ProgramData")
        .map(PathBuf::from)
        .unwrap_or_else(std::env::temp_dir)
        .join("SwiftTunnel")
        .join("goodbyedpi")
}

fn remove_goodbyedpi_data_dir() -> Result<(), String> {
    remove_goodbyedpi_data_dir_at(&goodbyedpi_data_dir())
}

fn remove_goodbyedpi_data_dir_at(path: &Path) -> Result<(), String> {
    match fs::remove_dir_all(path) {
        Ok(()) => {
            info!(
                "Removed legacy GoodbyeDPI runtime directory {}",
                path.display()
            );
            Ok(())
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(e) => Err(format!(
            "Failed to remove legacy GoodbyeDPI runtime directory {}: {e}",
            path.display()
        )),
    }
}

fn stop_managed_goodbyedpi_processes() -> Result<(), String> {
    let current_exe = std::env::current_exe().ok();
    let program_files = std::env::var_os("ProgramFiles").map(PathBuf::from);
    let roots = managed_goodbyedpi_roots(current_exe.as_deref(), program_files.as_deref());
    if roots.is_empty() {
        return Ok(());
    }

    stop_managed_processes_native(&roots)
}

#[cfg(not(windows))]
fn stop_managed_processes_native(_roots: &[PathBuf]) -> Result<(), String> {
    Ok(())
}

#[cfg(windows)]
fn stop_managed_processes_native(roots: &[PathBuf]) -> Result<(), String> {
    use std::time::{Duration, Instant};
    use windows::Win32::Foundation::{
        CloseHandle, ERROR_INVALID_PARAMETER, ERROR_NO_MORE_FILES, HANDLE, WAIT_OBJECT_0,
    };
    use windows::Win32::System::Diagnostics::ToolHelp::{
        CreateToolhelp32Snapshot, PROCESSENTRY32W, Process32FirstW, Process32NextW,
        TH32CS_SNAPPROCESS,
    };
    use windows::Win32::System::Threading::{
        OpenProcess, PROCESS_NAME_WIN32, PROCESS_QUERY_LIMITED_INFORMATION, PROCESS_SYNCHRONIZE,
        PROCESS_TERMINATE, QueryFullProcessImageNameW, TerminateProcess, WaitForSingleObject,
    };
    use windows::core::PWSTR;

    struct OwnedHandle(HANDLE);
    impl Drop for OwnedHandle {
        fn drop(&mut self) {
            unsafe {
                let _ = CloseHandle(self.0);
            }
        }
    }

    // A process-only snapshot requires no module walks or WMI. Open once and
    // check the image on the same handle we terminate, avoiding a PID reuse race.
    let snapshot = OwnedHandle(
        unsafe { CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0) }
            .map_err(|e| format!("Could not enumerate legacy helper processes: {e}"))?,
    );
    let mut entry = PROCESSENTRY32W {
        dwSize: std::mem::size_of::<PROCESSENTRY32W>() as u32,
        ..Default::default()
    };
    let mut next = unsafe { Process32FirstW(snapshot.0, &mut entry) };
    let mut errors = Vec::new();
    let deadline = Instant::now() + Duration::from_secs(3);
    while next.is_ok() {
        let length = entry
            .szExeFile
            .iter()
            .position(|c| *c == 0)
            .unwrap_or(entry.szExeFile.len());
        let name = String::from_utf16_lossy(&entry.szExeFile[..length]);
        if name.eq_ignore_ascii_case(GOODBYEDPI_EXE_NAME) {
            let result = (|| -> Result<(), String> {
                let process = match unsafe {
                    OpenProcess(
                        PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_TERMINATE | PROCESS_SYNCHRONIZE,
                        false,
                        entry.th32ProcessID,
                    )
                } {
                    Ok(handle) => OwnedHandle(handle),
                    Err(e) if e.code() == ERROR_INVALID_PARAMETER.to_hresult() => return Ok(()), // Already exited.
                    Err(e) => {
                        return Err(format!(
                            "Could not inspect legacy helper PID {}: {e}",
                            entry.th32ProcessID
                        ));
                    }
                };
                let mut image = vec![0u16; 32768];
                let mut size = image.len() as u32;
                if let Err(e) = unsafe {
                    QueryFullProcessImageNameW(
                        process.0,
                        PROCESS_NAME_WIN32,
                        PWSTR(image.as_mut_ptr()),
                        &mut size,
                    )
                } {
                    if unsafe { WaitForSingleObject(process.0, 0) } == WAIT_OBJECT_0 {
                        return Ok(());
                    }
                    return Err(format!(
                        "Could not verify legacy helper PID {}: {e}",
                        entry.th32ProcessID
                    ));
                }
                let path = PathBuf::from(String::from_utf16_lossy(&image[..size as usize]));
                if !is_managed_goodbyedpi_image(&path, roots) {
                    return Ok(());
                }
                if let Err(e) = unsafe { TerminateProcess(process.0, 0) } {
                    if unsafe { WaitForSingleObject(process.0, 0) } == WAIT_OBJECT_0 {
                        return Ok(());
                    }
                    return Err(format!(
                        "Could not stop legacy helper PID {}: {e}",
                        entry.th32ProcessID
                    ));
                }
                let remaining = deadline
                    .saturating_duration_since(Instant::now())
                    .as_millis() as u32;
                if unsafe { WaitForSingleObject(process.0, remaining) } != WAIT_OBJECT_0 {
                    return Err(format!(
                        "Legacy helper PID {} has not exited; retry cleanup after restarting Windows",
                        entry.th32ProcessID
                    ));
                }
                Ok(())
            })();
            if let Err(e) = result {
                errors.push(e);
            }
        }
        next = unsafe { Process32NextW(snapshot.0, &mut entry) };
    }
    if let Err(e) = next {
        if e.code() != ERROR_NO_MORE_FILES.to_hresult() {
            errors.push(format!("Legacy helper enumeration incomplete: {e}"));
        }
    }
    if errors.is_empty() {
        Ok(())
    } else {
        Err(errors.join("; "))
    }
}

fn is_managed_goodbyedpi_image(image: &Path, roots: &[PathBuf]) -> bool {
    let normalize = |path: &Path| {
        let path = path
            .to_string_lossy()
            .replace('/', "\\")
            .to_ascii_lowercase();
        path.strip_prefix(r"\\?\")
            .unwrap_or(&path)
            .trim_end_matches('\\')
            .to_string()
    };
    let image = normalize(image);
    if image.split('\\').any(|part| part == "." || part == "..") {
        return false;
    }
    if image.rsplit('\\').next() != Some(GOODBYEDPI_EXE_NAME) {
        return false;
    }
    roots
        .iter()
        .any(|root| image.starts_with(&format!("{}\\", normalize(root))))
}

fn managed_goodbyedpi_roots(
    current_exe: Option<&Path>,
    program_files: Option<&Path>,
) -> Vec<PathBuf> {
    let mut roots = Vec::new();

    if let Some(base) = current_exe.and_then(Path::parent) {
        roots.push(base.join("tools").join("goodbyedpi"));
        roots.push(base.join("resources").join("tools").join("goodbyedpi"));
        roots.push(base.join("goodbyedpi"));
    }

    if let Some(program_files) = program_files {
        let install_root = program_files.join("SwiftTunnel");
        roots.push(install_root.join("tools").join("goodbyedpi"));
        roots.push(
            install_root
                .join("resources")
                .join("tools")
                .join("goodbyedpi"),
        );
        roots.push(install_root.join("goodbyedpi"));
    }

    dedupe_paths(roots)
}

fn dedupe_paths(paths: Vec<PathBuf>) -> Vec<PathBuf> {
    let mut seen = HashSet::new();
    let mut out = Vec::new();
    for path in paths {
        if seen.insert(path.clone()) {
            out.push(path);
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn managed_goodbyedpi_roots_scope_to_install_dirs() {
        let roots = managed_goodbyedpi_roots(
            Some(Path::new(r"C:\Program Files\SwiftTunnel\SwiftTunnel.exe")),
            Some(Path::new(r"C:\Program Files")),
        );

        assert!(roots.contains(&PathBuf::from(
            r"C:\Program Files\SwiftTunnel\tools\goodbyedpi"
        )));
        assert!(roots.contains(&PathBuf::from(
            r"C:\Program Files\SwiftTunnel\resources\tools\goodbyedpi"
        )));
        assert!(!roots.contains(&PathBuf::from(r"D:\tools\goodbyedpi")));
    }

    #[test]
    fn native_cleanup_requires_both_image_name_and_managed_directory() {
        let roots = [PathBuf::from(
            r"C:\Program Files\SwiftTunnel\tools\goodbyedpi",
        )];
        assert!(is_managed_goodbyedpi_image(
            Path::new(r"c:\PROGRAM FILES\SwiftTunnel\tools\GoodbyeDPI\x64\GoodbyeDPI.exe"),
            &roots
        ));
        assert!(is_managed_goodbyedpi_image(
            Path::new(r"\\?\C:\Program Files\SwiftTunnel\tools\goodbyedpi\goodbyedpi.exe"),
            &roots
        ));
        for external in [
            r"D:\tools\goodbyedpi\goodbyedpi.exe",
            r"C:\Program Files\SwiftTunnel\tools\goodbyedpi-other\goodbyedpi.exe",
            r"C:\Program Files\SwiftTunnel\tools\goodbyedpi\other.exe",
            r"C:\Program Files\SwiftTunnel\tools\goodbyedpi\..\goodbyedpi.exe",
        ] {
            assert!(
                !is_managed_goodbyedpi_image(Path::new(external), &roots),
                "{external}"
            );
        }
    }

    #[test]
    fn remove_goodbyedpi_data_dir_ignores_missing_dir() {
        let path = std::env::temp_dir().join("swifttunnel-missing-goodbyedpi-dir");
        let _ = fs::remove_dir_all(&path);

        assert!(remove_goodbyedpi_data_dir_at(&path).is_ok());
    }
}
