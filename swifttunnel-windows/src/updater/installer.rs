//! Update installer - launches the bootstrapper EXE for installation
//!
//! The bootstrapper EXE (WiX Burn bundle) handles:
//! - UAC elevation automatically via InstallPrivilegeLevel="elevated"
//! - MSI installation with proper UI
//! - Cleanup and restart

use log::{error, info};
use std::path::Path;
use std::process::Command;

#[cfg(windows)]
use std::os::windows::process::CommandExt;

#[cfg(windows)]
const CREATE_NO_WINDOW: u32 = 0x08000000;

/// Install an update by launching the bootstrapper EXE
///
/// The bootstrapper:
/// 1. Automatically requests UAC elevation
/// 2. Installs the embedded MSI
/// 3. Handles restart
pub fn install_update(installer_path: &Path) -> Result<(), String> {
    if !installer_path.exists() {
        return Err(format!("Installer file not found: {}", installer_path.display()));
    }

    let extension = installer_path.extension().and_then(|e| e.to_str()).unwrap_or("");

    match extension {
        "exe" => install_via_bootstrapper(installer_path),
        "msi" => install_via_msi(installer_path),
        _ => Err(format!("Unknown installer type: {}", extension)),
    }
}

/// Install using the bootstrapper EXE (preferred method)
/// The bootstrapper self-elevates via WiX Burn's InstallPrivilegeLevel="elevated"
fn install_via_bootstrapper(exe_path: &Path) -> Result<(), String> {
    info!("Launching bootstrapper installer: {}", exe_path.display());

    // Get the current exe path so we can restart after update
    let current_exe = std::env::current_exe()
        .map_err(|e| format!("Failed to get current exe path: {}", e))?;

    // Create a simple batch script that:
    // 1. Waits for current app to close
    // 2. Runs the bootstrapper (which self-elevates)
    // 3. Starts the new version after install completes
    let temp_dir = std::env::temp_dir();
    let bat_path = temp_dir.join("swifttunnel_update.bat");

    let exe_path_str = exe_path.to_string_lossy();
    let current_exe_str = current_exe.to_string_lossy();
    let exe_name = current_exe
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or("swifttunnel-fps-booster.exe");

    // Batch script content
    let bat_content = format!(
        r#"@echo off
:: SwiftTunnel Update Script
:: Wait for app to close
timeout /t 2 /nobreak >nul

:: Kill any remaining instances
taskkill /f /im "{exe_name}" >nul 2>&1

:: Wait for file handles to release
timeout /t 2 /nobreak >nul

:: Run the bootstrapper (it will self-elevate via UAC)
"{installer_path}"

:: Wait for installation to complete
timeout /t 5 /nobreak >nul

:: Start new version
if exist "{app_path}" (
    start "" "{app_path}"
)

:: Clean up this script
del "%~f0"
"#,
        exe_name = exe_name,
        installer_path = exe_path_str,
        app_path = current_exe_str
    );

    std::fs::write(&bat_path, &bat_content)
        .map_err(|e| format!("Failed to write update script: {}", e))?;

    info!("Created update script at: {}", bat_path.display());
    info!("Launching bootstrapper installer...");

    // Launch the batch script
    let mut cmd = Command::new("cmd");
    cmd.args(["/c", &bat_path.to_string_lossy()]);

    #[cfg(windows)]
    cmd.creation_flags(CREATE_NO_WINDOW);

    match cmd.spawn() {
        Ok(_) => {
            info!("Update script launched successfully. Exiting for update...");
            Ok(())
        }
        Err(e) => {
            error!("Failed to launch update script: {}", e);
            let _ = std::fs::remove_file(&bat_path);
            Err(format!("Failed to launch installer: {}", e))
        }
    }
}

/// Fallback: Install using MSI directly via PowerShell (for older releases without bootstrapper)
fn install_via_msi(msi_path: &Path) -> Result<(), String> {
    info!("Falling back to MSI installation: {}", msi_path.display());

    let exe_path = std::env::current_exe()
        .map_err(|e| format!("Failed to get current exe path: {}", e))?;

    let temp_dir = std::env::temp_dir();
    let ps_path = temp_dir.join("swifttunnel_update.ps1");

    let msi_path_str = msi_path.to_string_lossy().replace("'", "''");
    let exe_path_str = exe_path.to_string_lossy().replace("'", "''");
    let exe_name = exe_path
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or("swifttunnel-fps-booster.exe");

    let local_app_data = std::env::var("LOCALAPPDATA")
        .unwrap_or_else(|_| "C:\\Users\\Public".to_string());
    let log_dir = format!("{}\\SwiftTunnel", local_app_data).replace("\\", "\\\\");

    // PowerShell script for MSI installation with UAC elevation
    let ps_content = format!(
        r#"# SwiftTunnel MSI Update Script
$ErrorActionPreference = 'Continue'
Add-Type -AssemblyName System.Windows.Forms

$logDir = '{log_dir}'
$logFile = "$logDir\update_install.log"
$msiPath = '{msi_path}'
$exePath = '{exe_path}'
$exeName = '{exe_name}'

if (-not (Test-Path $logDir)) {{
    New-Item -ItemType Directory -Path $logDir -Force | Out-Null
}}

function Log {{
    param([string]$message)
    $timestamp = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'
    "[$timestamp] $message" | Add-Content -Path $logFile -Encoding UTF8
}}

Log "=== Starting MSI update ==="
Start-Sleep -Seconds 2
Get-Process -Name ($exeName -replace '\.exe$','') -ErrorAction SilentlyContinue | Stop-Process -Force -ErrorAction SilentlyContinue
Start-Sleep -Seconds 2

$msiLogPath = "$logDir\msi_install.log"
$msiArgs = "/i `"$msiPath`" /qb /norestart /l*v `"$msiLogPath`""

try {{
    $process = Start-Process -FilePath "msiexec.exe" -ArgumentList $msiArgs -Verb RunAs -Wait -PassThru
    $exitCode = $process.ExitCode
    Log "MSI exit code: $exitCode"

    if ($exitCode -eq 0 -or $exitCode -eq 3010) {{
        Log "Installation successful!"
        Start-Sleep -Seconds 3
        Remove-Item $msiPath -Force -ErrorAction SilentlyContinue
        if (Test-Path $exePath) {{ Start-Process -FilePath $exePath }}
    }} else {{
        Log "MSI failed with code $exitCode"
        [System.Windows.Forms.MessageBox]::Show("Update failed (code: $exitCode). Please reinstall from swifttunnel.net", "Update Failed", [System.Windows.Forms.MessageBoxButtons]::OK, [System.Windows.Forms.MessageBoxIcon]::Error)
    }}
}} catch {{
    Log "ERROR: $($_.Exception.Message)"
    if ($_.Exception.Message -match "canceled") {{
        [System.Windows.Forms.MessageBox]::Show("Update cancelled.", "Update Cancelled", [System.Windows.Forms.MessageBoxButtons]::OK, [System.Windows.Forms.MessageBoxIcon]::Information)
    }}
}}

Log "=== Update script finished ==="
Start-Sleep -Seconds 1
Remove-Item -Path $MyInvocation.MyCommand.Path -Force -ErrorAction SilentlyContinue
"#,
        log_dir = log_dir,
        exe_name = exe_name,
        msi_path = msi_path_str,
        exe_path = exe_path_str
    );

    std::fs::write(&ps_path, &ps_content)
        .map_err(|e| format!("Failed to write update script: {}", e))?;

    let mut cmd = Command::new("powershell");
    cmd.args([
        "-ExecutionPolicy", "Bypass",
        "-WindowStyle", "Hidden",
        "-File", &ps_path.to_string_lossy(),
    ]);

    #[cfg(windows)]
    cmd.creation_flags(CREATE_NO_WINDOW);

    match cmd.spawn() {
        Ok(_) => {
            info!("MSI update script launched successfully");
            Ok(())
        }
        Err(e) => {
            error!("Failed to launch MSI update script: {}", e);
            let _ = std::fs::remove_file(&ps_path);
            Err(format!("Failed to launch installer: {}", e))
        }
    }
}

/// Check if installation is possible (basic validation)
pub fn can_install() -> Result<(), String> {
    let mut cmd = Command::new("cmd");
    cmd.args(["/c", "echo ok"]);

    #[cfg(windows)]
    cmd.creation_flags(CREATE_NO_WINDOW);

    match cmd.output() {
        Ok(_) => Ok(()),
        Err(e) => Err(format!("Command execution not available: {}", e)),
    }
}

/// Get the updates directory path
pub fn get_updates_dir() -> Option<std::path::PathBuf> {
    dirs::data_local_dir().map(|d| d.join("SwiftTunnel").join("updates"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_updates_dir() {
        let dir = get_updates_dir();
        assert!(dir.is_some());
        let dir = dir.unwrap();
        assert!(dir.to_string_lossy().contains("SwiftTunnel"));
    }

    #[test]
    fn test_install_missing_file() {
        let result = install_update(Path::new("nonexistent.exe"));
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("not found"));
    }
}
