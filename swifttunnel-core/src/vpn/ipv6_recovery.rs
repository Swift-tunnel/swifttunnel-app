//! IPv6 binding crash recovery
//!
//! When SwiftTunnel disables IPv6 on the physical network adapter for split tunneling,
//! it stores the original binding state in a marker file. If the app crashes before
//! restoring that state, startup recovery restores the adapter to its exact prior
//! configuration instead of blindly enabling IPv6.

use serde::{Deserialize, Serialize};
use std::fs;
use std::path::PathBuf;

/// Marker file name stored in %LOCALAPPDATA%/SwiftTunnel/
const IPV6_MARKER_FILE: &str = "ipv6_disabled.marker";

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct Ipv6Marker {
    adapter_name: String,
    originally_enabled: Option<bool>,
}

impl Ipv6Marker {
    fn legacy(adapter_name: String) -> Self {
        Self {
            adapter_name,
            originally_enabled: None,
        }
    }

    pub fn adapter_name(&self) -> &str {
        &self.adapter_name
    }

    fn restore_command(&self) -> &'static str {
        match self.originally_enabled {
            Some(false) => {
                "Disable-NetAdapterBinding -Name $adapter -ComponentId ms_tcpip6 -Confirm:$false 2>$null"
            }
            _ => "Enable-NetAdapterBinding -Name $adapter -ComponentId ms_tcpip6 2>$null",
        }
    }
}

/// Get the path to the IPv6 marker file
fn get_marker_path() -> Option<PathBuf> {
    dirs::data_local_dir().map(|d| d.join("SwiftTunnel").join(IPV6_MARKER_FILE))
}

pub fn query_ipv6_binding_enabled(adapter_name: &str) -> Option<bool> {
    let script = format!(
        r#"
        $adapter = '{}'
        $binding = Get-NetAdapterBinding -Name $adapter -ComponentId ms_tcpip6 -ErrorAction SilentlyContinue |
            Select-Object -First 1 -ExpandProperty Enabled
        if ($null -eq $binding) {{ exit 0 }}
        Write-Output $binding
        "#,
        adapter_name.replace('\'', "''")
    );

    let output = crate::hidden_command("powershell")
        .args(["-NoProfile", "-NonInteractive", "-Command", &script])
        .output()
        .ok()?;

    if !output.status.success() {
        return None;
    }

    match String::from_utf8_lossy(&output.stdout)
        .lines()
        .map(str::trim)
        .find(|line| !line.is_empty())
    {
        Some(value) if value.eq_ignore_ascii_case("true") => Some(true),
        Some(value) if value.eq_ignore_ascii_case("false") => Some(false),
        _ => None,
    }
}

/// Write IPv6 disabled marker with adapter name and original binding state.
pub fn write_ipv6_marker(adapter_name: &str) {
    if let Some(marker_path) = get_marker_path() {
        if let Some(parent) = marker_path.parent() {
            let _ = fs::create_dir_all(parent);
        }

        let marker = Ipv6Marker {
            adapter_name: adapter_name.trim().to_string(),
            originally_enabled: query_ipv6_binding_enabled(adapter_name),
        };
        let payload =
            serde_json::to_vec(&marker).unwrap_or_else(|_| adapter_name.as_bytes().to_vec());

        if let Err(e) = fs::write(&marker_path, payload) {
            log::warn!("Failed to write IPv6 marker file: {}", e);
        } else {
            log::debug!("IPv6 marker written for adapter: {}", marker.adapter_name());
        }
    }
}

/// Delete IPv6 marker file
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

/// Check if IPv6 marker exists and return captured state if so.
pub fn read_ipv6_marker() -> Option<Ipv6Marker> {
    let marker_path = get_marker_path()?;
    if !marker_path.exists() {
        return None;
    }

    let raw = fs::read(&marker_path).ok()?;
    if let Ok(marker) = serde_json::from_slice::<Ipv6Marker>(&raw) {
        if !marker.adapter_name.trim().is_empty() {
            return Some(marker);
        }
    }

    let adapter_name = String::from_utf8_lossy(&raw).trim().to_string();
    if adapter_name.is_empty() {
        None
    } else {
        Some(Ipv6Marker::legacy(adapter_name))
    }
}

fn build_restore_script(marker: &Ipv6Marker) -> String {
    format!(
        r#"
        $adapter = '{}'
        {}
        Write-Host 'IPv6 restored'
        "#,
        marker.adapter_name().replace('\'', "''"),
        marker.restore_command()
    )
}

fn restore_ipv6_for_marker(marker: &Ipv6Marker) -> bool {
    let script = build_restore_script(marker);
    match crate::hidden_command("powershell")
        .args(["-NoProfile", "-NonInteractive", "-Command", &script])
        .output()
    {
        Ok(output) => {
            if output.status.success() {
                log::info!(
                    "IPv6 state restored successfully for adapter: {}",
                    marker.adapter_name()
                );
                true
            } else {
                let stderr = String::from_utf8_lossy(&output.stderr);
                log::warn!(
                    "IPv6 restore failed for adapter {}: {}",
                    marker.adapter_name(),
                    stderr
                );
                false
            }
        }
        Err(e) => {
            log::error!("Failed to run PowerShell for IPv6 restore: {}", e);
            false
        }
    }
}

/// Restore IPv6 state from the marker file if one exists.
pub fn restore_ipv6_from_marker() -> Option<bool> {
    let marker = read_ipv6_marker()?;
    Some(restore_ipv6_for_marker(&marker))
}

/// Recover IPv6 settings on application startup
pub fn recover_ipv6_on_startup() {
    if let Some(marker) = read_ipv6_marker() {
        log::warn!(
            "IPv6 marker found - app may have crashed while IPv6 was modified. Adapter: {}",
            marker.adapter_name()
        );

        if restore_ipv6_for_marker(&marker) {
            delete_ipv6_marker();
            log::info!("IPv6 recovery complete");
        } else {
            log::error!("IPv6 recovery failed - will retry on next launch");
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
        assert_eq!(
            read_back
                .as_ref()
                .map(|marker| marker.adapter_name().to_string()),
            Some(test_adapter.to_string())
        );

        delete_ipv6_marker();

        let after_delete = read_ipv6_marker();
        assert_eq!(after_delete, None);
    }
}
