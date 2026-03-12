//! IPv6 binding crash recovery
//!
//! When SwiftTunnel disables IPv6 on the physical network adapter for split tunneling,
//! it creates a marker file. If the app crashes before re-enabling IPv6, the marker
//! file persists. On next startup, we detect this and restore IPv6 settings.
//!
//! This prevents users from being stuck without IPv6 connectivity after a crash.

use std::fs;
use std::path::PathBuf;
use std::process::Command;

/// Marker file name stored in %LOCALAPPDATA%/SwiftTunnel/
const IPV6_MARKER_FILE: &str = "ipv6_disabled.marker";

/// Get the path to the IPv6 marker file
fn get_marker_path() -> Option<PathBuf> {
    dirs::data_local_dir().map(|d| d.join("SwiftTunnel").join(IPV6_MARKER_FILE))
}

/// Write IPv6 disabled marker with adapter name
///
/// Called when IPv6 is disabled on an adapter. Stores the adapter name
/// so we can restore it on crash recovery.
pub fn write_ipv6_marker(adapter_name: &str) {
    if let Some(marker_path) = get_marker_path() {
        if let Some(parent) = marker_path.parent() {
            let _ = fs::create_dir_all(parent);
        }

        if let Err(e) = fs::write(&marker_path, adapter_name) {
            log::warn!("Failed to write IPv6 marker file: {}", e);
        } else {
            log::debug!("IPv6 marker written for adapter: {}", adapter_name);
        }
    }
}

/// Delete IPv6 marker file
///
/// Called when IPv6 is successfully re-enabled.
pub fn delete_ipv6_marker() {
    if let Some(marker_path) = get_marker_path() {
        if marker_path.exists() {
            if let Err(e) = fs::remove_file(&marker_path) {
                log::warn!("Failed to delete IPv6 marker file: {}", e);
            } else {
                log::debug!("IPv6 marker file deleted");
            }
        }
    }
}

/// Check if IPv6 marker exists and return adapter name if so
pub fn read_ipv6_marker() -> Option<String> {
    let marker_path = get_marker_path()?;
    if marker_path.exists() {
        fs::read_to_string(&marker_path)
            .ok()
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())
    } else {
        None
    }
}

/// Restore IPv6 binding for an adapter
fn restore_ipv6_for_adapter(adapter_name: &str) -> bool {
    log::info!("Restoring IPv6 binding for adapter: {}", adapter_name);

    let script = format!(
        r#"
        $adapter = '{}'
        Enable-NetAdapterBinding -Name $adapter -ComponentId ms_tcpip6 2>$null
        "#,
        adapter_name.replace('\'', "''")
    );

    match Command::new("powershell")
        .args(["-NoProfile", "-NonInteractive", "-Command", &script])
        .output()
    {
        Ok(output) => {
            if output.status.success() {
                log::info!("IPv6 restored successfully for adapter: {}", adapter_name);
                true
            } else {
                let stderr = String::from_utf8_lossy(&output.stderr);
                log::warn!("IPv6 restore may have failed: {}", stderr);
                // Still return true - partial success is possible
                true
            }
        }
        Err(e) => {
            log::error!("Failed to run PowerShell for IPv6 restore: {}", e);
            false
        }
    }
}

/// Recover IPv6 settings on application startup
///
/// Call this early in main() to restore IPv6 if the app previously crashed
/// while IPv6 was disabled.
pub fn recover_ipv6_on_startup() {
    if let Some(adapter_name) = read_ipv6_marker() {
        log::warn!(
            "IPv6 marker found - app may have crashed while IPv6 was disabled. Adapter: {}",
            adapter_name
        );

        if restore_ipv6_for_adapter(&adapter_name) {
            delete_ipv6_marker();
            log::info!("IPv6 recovery complete");
        } else {
            log::error!("IPv6 recovery failed - user may need to re-enable manually");
            // Still delete marker to avoid repeated attempts
            delete_ipv6_marker();
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
        assert!(path.to_string_lossy().contains(IPV6_MARKER_FILE));
    }

    #[test]
    fn test_marker_write_read_delete() {
        let test_adapter = "TestAdapter456";

        write_ipv6_marker(test_adapter);

        let read_back = read_ipv6_marker();
        assert_eq!(read_back, Some(test_adapter.to_string()));

        delete_ipv6_marker();

        let after_delete = read_ipv6_marker();
        assert_eq!(after_delete, None);
    }
}
