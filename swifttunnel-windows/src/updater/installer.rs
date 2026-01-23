//! Update installer - performs MSI installation with proper elevation
//!
//! Key improvements in v3:
//! - Uses PowerShell to request UAC elevation for msiexec
//! - Proper error handling and logging
//! - Fallback to interactive UI if silent install fails

use log::{error, info};
use std::path::Path;
use std::process::Command;

#[cfg(windows)]
use std::os::windows::process::CommandExt;

#[cfg(windows)]
const CREATE_NO_WINDOW: u32 = 0x08000000;

/// Install an update by creating a PowerShell script that:
/// 1. Waits for the current app to exit
/// 2. Runs the MSI installer with elevation (UAC prompt)
/// 3. Launches the new version
/// 4. Cleans up
pub fn install_update(msi_path: &Path) -> Result<(), String> {
    if !msi_path.exists() {
        return Err(format!("MSI file not found: {}", msi_path.display()));
    }

    // Get the install directory (where the exe is)
    let exe_path = std::env::current_exe()
        .map_err(|e| format!("Failed to get current exe path: {}", e))?;

    // Create PowerShell script in temp directory
    let temp_dir = std::env::temp_dir();
    let ps_path = temp_dir.join("swifttunnel_update.ps1");

    let msi_path_str = msi_path.to_string_lossy().replace("'", "''");
    let exe_path_str = exe_path.to_string_lossy().replace("'", "''");

    // Get just the exe filename for taskkill
    let exe_name = exe_path
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or("swifttunnel-fps-booster.exe");

    // Get LocalAppData path for logs
    let local_app_data = std::env::var("LOCALAPPDATA")
        .unwrap_or_else(|_| "C:\\Users\\Public".to_string());
    let log_dir = format!("{}\\SwiftTunnel", local_app_data).replace("\\", "\\\\");

    // PowerShell script that performs the update with proper elevation
    // Key: Uses Start-Process -Verb RunAs to trigger UAC for msiexec
    let ps_content = format!(
        r#"# SwiftTunnel Update Script v4
$ErrorActionPreference = 'Continue'

# Load Windows.Forms for MessageBox dialogs
Add-Type -AssemblyName System.Windows.Forms

$logDir = '{log_dir}'
$logFile = "$logDir\update_install.log"
$msiPath = '{msi_path}'
$exePath = '{exe_path}'
$exeName = '{exe_name}'

# Ensure log directory exists
if (-not (Test-Path $logDir)) {{
    New-Item -ItemType Directory -Path $logDir -Force | Out-Null
}}

function Log {{
    param([string]$message)
    $timestamp = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'
    "[$timestamp] $message" | Add-Content -Path $logFile -Encoding UTF8
}}

Log "=== Starting update ==="
Log "MSI: $msiPath"
Log "Target: $exePath"

# Step 1: Wait for graceful close
Log "Waiting for app to close..."
Start-Sleep -Seconds 2

# Step 2: Force kill any remaining instances
Log "Force killing $exeName..."
Get-Process -Name ($exeName -replace '\.exe$','') -ErrorAction SilentlyContinue | Stop-Process -Force -ErrorAction SilentlyContinue

# Step 3: Wait for file handles to release
Start-Sleep -Seconds 2

# Step 4: Wait for exe to be deletable (max 30 seconds)
$waitCount = 0
while ($waitCount -lt 30) {{
    try {{
        if (Test-Path $exePath) {{
            Remove-Item $exePath -Force -ErrorAction Stop
        }}
        break
    }} catch {{
        $waitCount++
        Log "Wait attempt $waitCount of 30..."
        Start-Sleep -Seconds 1
    }}
}}

if ($waitCount -ge 30) {{
    Log "TIMEOUT: Exe still locked after 30 seconds"
    # Continue anyway - MSI might be able to handle it
}}

# Step 5: Run MSI with elevation
Log "Starting MSI install with elevation..."

$msiLogPath = "$logDir\msi_install.log"
$msiArgs = "/i `"$msiPath`" /qb /norestart /l*v `"$msiLogPath`""

try {{
    # Run msiexec elevated - this will trigger UAC prompt
    $process = Start-Process -FilePath "msiexec.exe" -ArgumentList $msiArgs -Verb RunAs -Wait -PassThru
    $exitCode = $process.ExitCode
    Log "MSI exit code: $exitCode"

    if ($exitCode -eq 0 -or $exitCode -eq 3010) {{
        Log "Installation successful!"

        # Step 6: Wait for msiexec cleanup
        Start-Sleep -Seconds 3

        # Step 7: Clean up MSI
        if (Test-Path $msiPath) {{
            Remove-Item $msiPath -Force -ErrorAction SilentlyContinue
        }}

        # Step 8: Start new version
        Log "Starting new version..."
        if (Test-Path $exePath) {{
            Start-Process -FilePath $exePath
        }} else {{
            Log "WARNING: Exe not found at $exePath after install"
        }}
    }} else {{
        Log "MSI installation failed with code $exitCode"

        # Try again with full UI if silent failed
        if ($exitCode -eq 1603 -or $exitCode -eq 1602) {{
            Log "Retrying with interactive UI..."
            $msiArgsInteractive = "/i `"$msiPath`" /l*v `"$msiLogPath`""
            $retryProcess = Start-Process -FilePath "msiexec.exe" -ArgumentList $msiArgsInteractive -Verb RunAs -Wait -PassThru
            $retryExit = $retryProcess.ExitCode
            Log "Retry MSI exit code: $retryExit"

            if ($retryExit -eq 0 -or $retryExit -eq 3010) {{
                Log "Retry installation successful!"
                Start-Sleep -Seconds 3
                if (Test-Path $msiPath) {{
                    Remove-Item $msiPath -Force -ErrorAction SilentlyContinue
                }}
                if (Test-Path $exePath) {{
                    Start-Process -FilePath $exePath
                }}
            }} else {{
                Log "Retry also failed. Please reinstall manually."
                [System.Windows.Forms.MessageBox]::Show("SwiftTunnel update failed (code: $retryExit). Please download and reinstall manually from swifttunnel.net", "Update Failed", [System.Windows.Forms.MessageBoxButtons]::OK, [System.Windows.Forms.MessageBoxIcon]::Error)
            }}
        }} else {{
            [System.Windows.Forms.MessageBox]::Show("SwiftTunnel update failed (code: $exitCode). Please download and reinstall manually from swifttunnel.net", "Update Failed", [System.Windows.Forms.MessageBoxButtons]::OK, [System.Windows.Forms.MessageBoxIcon]::Error)
        }}
    }}
}} catch {{
    $err = $_.Exception.Message
    Log "ERROR: $err"

    # If elevation was cancelled, show message
    if ($err -match "canceled by the user") {{
        Log "UAC elevation was cancelled"
        [System.Windows.Forms.MessageBox]::Show("Update was cancelled. The app will continue with the current version.", "Update Cancelled", [System.Windows.Forms.MessageBoxButtons]::OK, [System.Windows.Forms.MessageBoxIcon]::Information)
    }} else {{
        [System.Windows.Forms.MessageBox]::Show("SwiftTunnel update error: $err", "Update Failed", [System.Windows.Forms.MessageBoxButtons]::OK, [System.Windows.Forms.MessageBoxIcon]::Error)
    }}
}}

Log "=== Update script finished ==="

# Clean up this script
Start-Sleep -Seconds 1
Remove-Item -Path $MyInvocation.MyCommand.Path -Force -ErrorAction SilentlyContinue
"#,
        log_dir = log_dir,
        exe_name = exe_name,
        msi_path = msi_path_str,
        exe_path = exe_path_str
    );

    // Write the PowerShell script
    std::fs::write(&ps_path, &ps_content)
        .map_err(|e| format!("Failed to write update script: {}", e))?;

    info!("Created update script at: {}", ps_path.display());
    info!("Launching update installer...");

    // Launch PowerShell to run the script
    // Using -ExecutionPolicy Bypass to allow the script to run
    // Using -WindowStyle Hidden to minimize visual disturbance
    let mut cmd = Command::new("powershell");
    cmd.args([
        "-ExecutionPolicy", "Bypass",
        "-WindowStyle", "Hidden",
        "-File", &ps_path.to_string_lossy(),
    ]);

    #[cfg(windows)]
    cmd.creation_flags(CREATE_NO_WINDOW);

    let result = cmd.spawn();

    match result {
        Ok(_) => {
            info!("Update script launched successfully. Exiting for update...");
            Ok(())
        }
        Err(e) => {
            error!("Failed to launch update script: {}", e);
            // Try to clean up the script file
            let _ = std::fs::remove_file(&ps_path);
            Err(format!("Failed to launch installer: {}", e))
        }
    }
}

/// Check if an MSI installation is possible (basic validation)
pub fn can_install() -> Result<(), String> {
    // Check if msiexec is available (hidden, no window)
    let mut cmd = Command::new("msiexec");
    cmd.arg("/?");

    #[cfg(windows)]
    cmd.creation_flags(CREATE_NO_WINDOW);

    let output = cmd.output();

    match output {
        Ok(_) => Ok(()),
        Err(e) => Err(format!("msiexec not available: {}", e)),
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
        let result = install_update(Path::new("nonexistent.msi"));
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("not found"));
    }
}
