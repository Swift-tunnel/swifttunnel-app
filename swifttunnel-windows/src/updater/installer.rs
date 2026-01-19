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

    // Batch script that performs the update
    // Uses ping for reliable delay (more compatible than timeout on all Windows versions)
    let batch_content = format!(
        r#"@echo off
:: SwiftTunnel Update Script
:: Wait for the app to close
ping -n 3 127.0.0.1 > nul

:: Run the MSI installer silently
:: /qn = completely silent
:: /norestart = don't restart computer
:: REINSTALLMODE=amus = reinstall all files
msiexec /i "{msi_path}" /qn /norestart REINSTALLMODE=amus

:: Wait for installation to complete
ping -n 2 127.0.0.1 > nul

:: Start the new version
start "" "{exe_path}"

:: Delete this script
del "%~f0"
"#,
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
