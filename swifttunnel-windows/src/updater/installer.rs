//! Update installer - performs MSI silent installation

use log::{error, info};
use std::path::Path;
use std::process::Command;

#[cfg(windows)]
use std::os::windows::process::CommandExt;

#[cfg(windows)]
const CREATE_NO_WINDOW: u32 = 0x08000000;

/// Install an update by creating a batch script and launching it
/// The batch script will:
/// 1. Wait for the current app to exit
/// 2. Run the MSI installer silently
/// 3. Launch the new version
/// 4. Delete itself
pub fn install_update(msi_path: &Path) -> Result<(), String> {
    if !msi_path.exists() {
        return Err(format!("MSI file not found: {}", msi_path.display()));
    }

    // Get the install directory (where the exe is)
    let exe_path = std::env::current_exe()
        .map_err(|e| format!("Failed to get current exe path: {}", e))?;

    // Create batch script in temp directory
    let temp_dir = std::env::temp_dir();
    let batch_path = temp_dir.join("swifttunnel_update.bat");

    let msi_path_str = msi_path.to_string_lossy();
    let exe_path_str = exe_path.to_string_lossy();

    // Get just the exe filename for taskkill
    let exe_name = exe_path
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or("swifttunnel-fps-booster.exe");

    // Get LocalAppData path for logs
    let local_app_data = std::env::var("LOCALAPPDATA")
        .unwrap_or_else(|_| "C:\\Users\\Public".to_string());
    let log_dir = format!("{}\\SwiftTunnel", local_app_data);

    // Batch script that performs the update with proper waiting and verification
    // Key improvements:
    // - Uses start /wait for msiexec to ensure completion
    // - Adds logging for debugging
    // - Uses timeout instead of ping for delays
    // - Limits wait loop to prevent infinite loops
    // - Verifies installation success before restarting
    let batch_content = format!(
        r#"@echo off
setlocal EnableDelayedExpansion

:: SwiftTunnel Update Script v2
set "LOGDIR={log_dir}"
set "LOGFILE=%LOGDIR%\update_install.log"

:: Ensure log directory exists
if not exist "%LOGDIR%" mkdir "%LOGDIR%"

echo [%date% %time%] === Starting update === >> "%LOGFILE%"
echo [%date% %time%] Target: {msi_path} >> "%LOGFILE%"

:: Step 1: Wait 2 seconds for graceful close
echo [%date% %time%] Waiting for app to close... >> "%LOGFILE%"
timeout /t 2 /nobreak > nul

:: Step 2: Force kill any remaining instances
echo [%date% %time%] Force killing {exe_name}... >> "%LOGFILE%"
taskkill /f /im "{exe_name}" >nul 2>&1

:: Step 3: Wait for file handles to release
timeout /t 2 /nobreak > nul

:: Step 4: Wait for exe to be unlocked (max 30 attempts = 30 seconds)
set "WAIT_COUNT=0"
:waitloop
del /f "{exe_path}" >nul 2>&1
if not exist "{exe_path}" goto install
set /a WAIT_COUNT+=1
echo [%date% %time%] Wait attempt %WAIT_COUNT% of 30... >> "%LOGFILE%"
if %WAIT_COUNT% geq 30 (
    echo [%date% %time%] TIMEOUT: Exe still locked after 30 seconds >> "%LOGFILE%"
    goto error
)
timeout /t 1 /nobreak > nul
goto waitloop

:install
echo [%date% %time%] Exe unlocked, starting MSI install... >> "%LOGFILE%"

:: Step 5: Run MSI with explicit wait and verbose logging
start /wait msiexec /i "{msi_path}" /qn /norestart /l*v "%LOGDIR%\msi_install.log"
set "MSI_EXIT=%errorlevel%"
echo [%date% %time%] MSI exit code: %MSI_EXIT% >> "%LOGFILE%"

if %MSI_EXIT% neq 0 (
    echo [%date% %time%] MSI installation failed with code %MSI_EXIT% >> "%LOGFILE%"
    goto error
)

:: Step 6: Wait for msiexec cleanup
timeout /t 3 /nobreak > nul

:: Step 7: Verify exe exists after installation
if not exist "{exe_path}" (
    echo [%date% %time%] ERROR: Exe not found after installation >> "%LOGFILE%"
    goto error
)

echo [%date% %time%] Installation successful! >> "%LOGFILE%"

:: Step 8: Clean up MSI and start app
del /f "{msi_path}" >nul 2>&1
echo [%date% %time%] Starting new version... >> "%LOGFILE%"
start "" "{exe_path}"
goto cleanup

:error
echo [%date% %time%] === UPDATE FAILED === >> "%LOGFILE%"
msg "%USERNAME%" "SwiftTunnel update failed (code: %MSI_EXIT%). Please reinstall manually. Check log: %LOGFILE%"
goto cleanup

:cleanup
echo [%date% %time%] Cleanup complete >> "%LOGFILE%"
:: Delete this script
del "%~f0"
"#,
        log_dir = log_dir,
        exe_name = exe_name,
        msi_path = msi_path_str,
        exe_path = exe_path_str
    );

    // Write the batch script
    std::fs::write(&batch_path, &batch_content)
        .map_err(|e| format!("Failed to write update script: {}", e))?;

    info!("Created update script at: {}", batch_path.display());
    info!("Launching update installer...");

    // Launch the batch script completely hidden (no console window at all)
    // Using CREATE_NO_WINDOW flag to prevent any visible window
    let mut cmd = Command::new("cmd");
    cmd.args(["/c", &batch_path.to_string_lossy().to_string()]);

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
            // Try to clean up the batch file
            let _ = std::fs::remove_file(&batch_path);
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
