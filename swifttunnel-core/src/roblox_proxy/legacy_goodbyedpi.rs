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

    if cfg!(windows) {
        if let Err(e) = stop_managed_goodbyedpi_processes() {
            errors.push(e);
        }
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

    let script = build_stop_managed_processes_script(&roots);
    let status = crate::hidden_command("powershell")
        .args([
            "-NoProfile",
            "-ExecutionPolicy",
            "Bypass",
            "-Command",
            &script,
        ])
        .status()
        .map_err(|e| format!("Failed to run legacy GoodbyeDPI process cleanup: {e}"))?;

    if status.success() {
        Ok(())
    } else {
        Err(format!(
            "Legacy GoodbyeDPI process cleanup exited with {}",
            status
                .code()
                .map_or_else(|| "unknown status".to_string(), |code| code.to_string())
        ))
    }
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

fn build_stop_managed_processes_script(roots: &[PathBuf]) -> String {
    let roots = roots
        .iter()
        .map(|path| format!("'{}'", powershell_single_quote(&path.to_string_lossy())))
        .collect::<Vec<_>>()
        .join(", ");

    format!(
        r#"$ErrorActionPreference = 'Stop'
$roots = @({roots}) | ForEach-Object {{
  [System.IO.Path]::GetFullPath($_).TrimEnd('\') + '\'
}}
Get-CimInstance Win32_Process -Filter "Name = '{GOODBYEDPI_EXE_NAME}'" | ForEach-Object {{
  $path = $_.ExecutablePath
  if (-not [string]::IsNullOrWhiteSpace($path)) {{
    $fullPath = [System.IO.Path]::GetFullPath($path)
    foreach ($root in $roots) {{
      if ($fullPath.StartsWith($root, [System.StringComparison]::OrdinalIgnoreCase)) {{
        Stop-Process -Id $_.ProcessId -Force -ErrorAction Stop
        break
      }}
    }}
  }}
}}"#
    )
}

fn powershell_single_quote(value: &str) -> String {
    value.replace('\'', "''")
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
    fn stop_script_uses_path_scoped_process_cleanup() {
        let script = build_stop_managed_processes_script(&[PathBuf::from(
            r"C:\Program Files\Swift'Tunnel\tools\goodbyedpi",
        )]);

        assert!(script.contains("Get-CimInstance Win32_Process"));
        assert!(script.contains("Name = 'goodbyedpi.exe'"));
        assert!(script.contains("ExecutablePath"));
        assert!(script.contains("StartsWith"));
        assert!(script.contains("Stop-Process"));
        assert!(script.contains("Swift''Tunnel"));
        assert!(!script.contains("taskkill"));
    }

    #[test]
    fn remove_goodbyedpi_data_dir_ignores_missing_dir() {
        let path = std::env::temp_dir().join("swifttunnel-missing-goodbyedpi-dir");
        let _ = fs::remove_dir_all(&path);

        assert!(remove_goodbyedpi_data_dir_at(&path).is_ok());
    }
}
