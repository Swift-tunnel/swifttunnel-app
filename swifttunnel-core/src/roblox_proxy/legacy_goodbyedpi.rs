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

#[cfg(windows)]
fn goodbyedpi_data_dir() -> Result<PathBuf, String> {
    use std::{ffi::OsString, os::windows::ffi::OsStringExt};
    use windows::Win32::{
        System::Com::CoTaskMemFree,
        UI::Shell::{FOLDERID_ProgramData, KF_FLAG_DEFAULT, SHGetKnownFolderPath},
    };
    // Cleanup is elevated. Never redirect it through ProgramData/TEMP env vars.
    let native = unsafe { SHGetKnownFolderPath(&FOLDERID_ProgramData, KF_FLAG_DEFAULT, None) }
        .map_err(|error| format!("Could not locate legacy helper data: {error}"))?;
    if native.0.is_null() {
        return Err("Windows did not return a shared data folder.".into());
    }
    let base = PathBuf::from(OsString::from_wide(unsafe { native.as_wide() }));
    unsafe {
        CoTaskMemFree(Some(native.0.cast()));
    }
    if !base.is_absolute() {
        return Err("Windows returned an invalid shared data folder.".into());
    }
    Ok(base.join("SwiftTunnel").join("goodbyedpi"))
}

#[cfg(not(windows))]
fn goodbyedpi_data_dir() -> Result<PathBuf, String> {
    Err("Legacy Windows helper cleanup is available on Windows only.".into())
}

fn remove_goodbyedpi_data_dir() -> Result<(), String> {
    remove_goodbyedpi_data_dir_at(&goodbyedpi_data_dir()?)
}

const MAX_CLEANUP_ENTRIES: usize = 512;
const MAX_CLEANUP_DEPTH: usize = 8;

fn remove_goodbyedpi_data_dir_at(path: &Path) -> Result<(), String> {
    if !path.is_absolute() || path.file_name().is_none() {
        return Err("Invalid legacy helper cleanup folder.".into());
    }
    match fs::symlink_metadata(path) {
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(error) => return Err(error.to_string()),
        Ok(meta) if !meta.is_dir() => return Err("Legacy helper data is not a directory.".into()),
        Ok(_) => {}
    }
    // Inspect the whole small legacy layout before removing anything. An
    // unexpected tree must not become unbounded recursive uninstall work.
    fn inspect(
        path: &Path,
        depth: usize,
        remaining: &mut usize,
        plan: &mut Vec<(PathBuf, bool)>,
    ) -> Result<(), String> {
        if *remaining == 0 || depth > MAX_CLEANUP_DEPTH {
            return Err(
                "Legacy helper data contains too many files or nested folders; it was kept.".into(),
            );
        }
        *remaining -= 1;
        crate::roblox_native_launch::safe_path(path)?;
        let meta = fs::symlink_metadata(path).map_err(|error| error.to_string())?;
        if meta.is_dir() {
            for entry in fs::read_dir(path).map_err(|error| error.to_string())? {
                let entry = entry.map_err(|error| error.to_string())?;
                inspect(&entry.path(), depth + 1, remaining, plan)?;
            }
        } else if !meta.is_file() {
            return Err("An unexpected legacy helper file was left untouched.".into());
        }
        plan.push((path.to_path_buf(), meta.is_dir()));
        Ok(())
    }
    let mut plan = Vec::new();
    let mut remaining = MAX_CLEANUP_ENTRIES;
    inspect(path, 0, &mut remaining, &mut plan)?;
    for (target, directory) in plan {
        // Recheck each path immediately before its nonrecursive removal.
        crate::roblox_native_launch::safe_path(&target)?;
        let result = if directory {
            fs::remove_dir(&target)
        } else {
            fs::remove_file(&target)
        };
        match result {
            Ok(()) => {}
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => return Err(format!("Could not remove legacy helper files: {error}")),
        }
    }
    info!(
        "Removed legacy GoodbyeDPI runtime directory {}",
        path.display()
    );
    Ok(())
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

    fn fixture() -> PathBuf {
        let root = crate::test_support::recovery_directory()
            .join(format!("legacy-cleanup-{:032x}", rand::random::<u128>()));
        fs::create_dir(&root).unwrap();
        root
    }

    #[test]
    fn legacy_cleanup_removes_only_the_owned_tree_and_keeps_external_hardlinks() {
        let root = fixture();
        let outside = root.join("keep.txt");
        fs::write(&outside, b"unrelated").unwrap();
        let legacy = root.join("goodbyedpi");
        fs::create_dir_all(legacy.join("x64")).unwrap();
        fs::hard_link(&outside, legacy.join("x64").join("old.txt")).unwrap();
        remove_goodbyedpi_data_dir_at(&legacy).unwrap();
        assert!(!legacy.exists());
        assert_eq!(fs::read(outside).unwrap(), b"unrelated");
        assert!(remove_goodbyedpi_data_dir_at(Path::new("relative-folder")).is_err());
    }

    #[test]
    fn oversized_or_deep_legacy_trees_are_preserved_before_any_deletion() {
        let root = fixture();
        let large = root.join("large");
        fs::create_dir(&large).unwrap();
        for index in 0..MAX_CLEANUP_ENTRIES {
            fs::write(large.join(format!("{index}.txt")), b"keep").unwrap();
        }
        assert!(
            remove_goodbyedpi_data_dir_at(&large)
                .unwrap_err()
                .contains("too many")
        );
        assert_eq!(fs::read_dir(&large).unwrap().count(), MAX_CLEANUP_ENTRIES);
        let deep = root.join("deep");
        let mut leaf = deep.clone();
        for _ in 0..=MAX_CLEANUP_DEPTH {
            leaf.push("child");
        }
        fs::create_dir_all(&leaf).unwrap();
        fs::write(leaf.join("keep.txt"), b"keep").unwrap();
        assert!(remove_goodbyedpi_data_dir_at(&deep).is_err());
        assert!(leaf.join("keep.txt").exists());
    }

    #[cfg(windows)]
    #[test]
    fn redirected_legacy_root_or_ancestor_is_left_untouched() {
        let root = fixture();
        let outside = root.join("outside");
        fs::create_dir_all(outside.join("goodbyedpi")).unwrap();
        fs::write(outside.join("goodbyedpi").join("keep.txt"), b"keep").unwrap();
        let redirect = root.join("redirect");
        // Junction creation requires no symlink privilege. Quote each path as
        // a PowerShell literal; the fixture never names a real helper folder.
        let literal = |path: &Path| format!("'{}'", path.to_string_lossy().replace('\'', "''"));
        let script = format!(
            "$ErrorActionPreference='Stop'; New-Item -ItemType Junction -Path {} -Target {} | Out-Null",
            literal(&redirect),
            literal(&outside)
        );
        let created = crate::run_hidden_command_with_timeout(
            "powershell",
            &["-NoProfile", "-NonInteractive", "-Command", &script],
            std::time::Duration::from_secs(10),
        );
        assert!(created.success, "{}", created.stderr);
        assert!(remove_goodbyedpi_data_dir_at(&redirect).is_err());
        assert!(remove_goodbyedpi_data_dir_at(&redirect.join("goodbyedpi")).is_err());
        assert_eq!(
            fs::read(outside.join("goodbyedpi").join("keep.txt")).unwrap(),
            b"keep"
        );
        fs::remove_dir(redirect).unwrap();
    }

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
