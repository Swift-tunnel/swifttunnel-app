//! TSO (TCP Segmentation Offload) crash recovery
//!
//! When SwiftTunnel disables TSO on the physical network adapter for split tunneling,
//! it creates a marker file. If the app crashes before re-enabling TSO, the marker
//! file persists. On next startup, we detect this and restore TSO settings.
//!
//! This prevents users from being stuck with degraded network performance after a crash.

use std::fs;
use std::path::PathBuf;
use std::process::Command;

/// Marker file name stored in %LOCALAPPDATA%/SwiftTunnel/
const TSO_MARKER_FILE: &str = "tso_disabled.marker";

/// Get the path to the TSO marker file
fn get_marker_path() -> Option<PathBuf> {
    dirs::data_local_dir().map(|d| d.join("SwiftTunnel").join(TSO_MARKER_FILE))
}

/// Write TSO disabled marker with adapter name
///
/// Called when TSO is disabled on an adapter. Stores the adapter name
/// so we can restore it on crash recovery.
pub fn write_tso_marker(adapter_name: &str) {
    if let Some(marker_path) = get_marker_path() {
        // Ensure directory exists
        if let Some(parent) = marker_path.parent() {
            let _ = fs::create_dir_all(parent);
        }

        if let Err(e) = fs::write(&marker_path, adapter_name) {
            log::warn!("Failed to write TSO marker file: {}", e);
        } else {
            log::debug!("TSO marker written for adapter: {}", adapter_name);
        }
    }
}

/// Delete TSO marker file
///
/// Called when TSO is successfully re-enabled.
pub fn delete_tso_marker() {
    if let Some(marker_path) = get_marker_path() {
        if marker_path.exists() {
            if let Err(e) = fs::remove_file(&marker_path) {
                log::warn!("Failed to delete TSO marker file: {}", e);
            } else {
                log::debug!("TSO marker file deleted");
            }
        }
    }
}

/// Check if TSO marker exists and return adapter name if so
pub fn read_tso_marker() -> Option<String> {
    let marker_path = get_marker_path()?;
    if marker_path.exists() {
        // Trim whitespace for consistent handling across all callers
        fs::read_to_string(&marker_path)
            .ok()
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())
    } else {
        None
    }
}

/// Restore TSO settings for an adapter
///
/// Re-enables TCP Segmentation Offload and checksum offload on the specified adapter.
/// This is the same PowerShell command used in `enable_adapter_offload()`.
fn restore_tso_for_adapter(adapter_name: &str) -> bool {
    log::info!("Restoring TSO for adapter: {}", adapter_name);

    let script = format!(
        r#"
        $adapter = '{}'
        # Re-enable LSO v2
        Set-NetAdapterAdvancedProperty -Name $adapter -RegistryKeyword '*LsoV2IPv4' -RegistryValue 1 2>$null
        Set-NetAdapterAdvancedProperty -Name $adapter -RegistryKeyword '*LsoV2IPv6' -RegistryValue 1 2>$null
        # Re-enable checksum offload
        Set-NetAdapterAdvancedProperty -Name $adapter -RegistryKeyword '*TCPChecksumOffloadIPv4' -RegistryValue 3 2>$null
        Set-NetAdapterAdvancedProperty -Name $adapter -RegistryKeyword '*UDPChecksumOffloadIPv4' -RegistryValue 3 2>$null
        Set-NetAdapterAdvancedProperty -Name $adapter -RegistryKeyword '*TCPChecksumOffloadIPv6' -RegistryValue 3 2>$null
        Set-NetAdapterAdvancedProperty -Name $adapter -RegistryKeyword '*UDPChecksumOffloadIPv6' -RegistryValue 3 2>$null
        "#,
        adapter_name.replace('\'', "''") // Escape single quotes
    );

    match Command::new("powershell")
        .args(["-NoProfile", "-NonInteractive", "-Command", &script])
        .output()
    {
        Ok(output) => {
            if output.status.success() {
                log::info!("TSO restored successfully for adapter: {}", adapter_name);
                true
            } else {
                let stderr = String::from_utf8_lossy(&output.stderr);
                log::warn!("TSO restore may have failed: {}", stderr);
                // Still return true - the commands may partially succeed
                true
            }
        }
        Err(e) => {
            log::error!("Failed to run PowerShell for TSO restore: {}", e);
            false
        }
    }
}

/// Recover TSO settings on application startup
///
/// Call this early in main() to restore TSO if the app previously crashed
/// while TSO was disabled.
pub fn recover_tso_on_startup() {
    if let Some(adapter_name) = read_tso_marker() {
        log::warn!(
            "TSO marker found - app may have crashed while TSO was disabled. Adapter: {}",
            adapter_name
        );

        if restore_tso_for_adapter(&adapter_name) {
            delete_tso_marker();
            log::info!("TSO recovery complete");
        } else {
            log::error!("TSO recovery failed - user may need to re-enable manually or reboot");
            // Still delete marker to avoid repeated attempts
            delete_tso_marker();
        }
    }
}

/// Emergency TSO restore for panic handler
///
/// This is a simplified version that runs synchronously and doesn't log
/// (since logging may not work during panic). Best-effort attempt to
/// restore TSO before the process terminates.
pub fn emergency_tso_restore() {
    if let Some(marker_path) = get_marker_path() {
        if let Ok(adapter_name) = fs::read_to_string(&marker_path) {
            let adapter_name = adapter_name.trim();
            if !adapter_name.is_empty() {
                // Best-effort restore - no logging, just try
                let script = format!(
                    r#"
                    $adapter = '{}'
                    Set-NetAdapterAdvancedProperty -Name $adapter -RegistryKeyword '*LsoV2IPv4' -RegistryValue 1 2>$null
                    Set-NetAdapterAdvancedProperty -Name $adapter -RegistryKeyword '*LsoV2IPv6' -RegistryValue 1 2>$null
                    Set-NetAdapterAdvancedProperty -Name $adapter -RegistryKeyword '*TCPChecksumOffloadIPv4' -RegistryValue 3 2>$null
                    Set-NetAdapterAdvancedProperty -Name $adapter -RegistryKeyword '*UDPChecksumOffloadIPv4' -RegistryValue 3 2>$null
                    Set-NetAdapterAdvancedProperty -Name $adapter -RegistryKeyword '*TCPChecksumOffloadIPv6' -RegistryValue 3 2>$null
                    Set-NetAdapterAdvancedProperty -Name $adapter -RegistryKeyword '*UDPChecksumOffloadIPv6' -RegistryValue 3 2>$null
                    "#,
                    adapter_name.replace('\'', "''")
                );

                let _ = Command::new("powershell")
                    .args(["-NoProfile", "-NonInteractive", "-Command", &script])
                    .output();

                // Delete marker
                let _ = fs::remove_file(&marker_path);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_marker_path() {
        let path = get_marker_path();
        assert!(path.is_some());
        let path = path.unwrap();
        assert!(path.to_string_lossy().contains("SwiftTunnel"));
        assert!(path.to_string_lossy().contains(TSO_MARKER_FILE));
    }

    #[test]
    fn test_marker_write_read_delete() {
        let test_adapter = "TestAdapter123";

        // Write marker
        write_tso_marker(test_adapter);

        // Read it back
        let read_back = read_tso_marker();
        assert_eq!(read_back, Some(test_adapter.to_string()));

        // Delete it
        delete_tso_marker();

        // Should be gone
        let after_delete = read_tso_marker();
        assert_eq!(after_delete, None);
    }
}
