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

/// Check via IP Helper API (no PowerShell, no WMI) whether the adapter at
/// `if_index` currently has IPv6 bound. Used as a fast pre-check before
/// attempting `Disable-NetAdapterBinding`, which can hang 30+ seconds on
/// Realtek / slow-WMI machines even when there is nothing to disable.
///
/// Returns:
/// - `Some(true)` → adapter has IPv6 stack bound (caller should proceed with
///   the disable call).
/// - `Some(false)` → adapter has no IPv6 binding (caller can skip entirely —
///   this is the case that saves ~22s on adapters like Realtek RTL8821CE).
/// - `None` → API failure; caller should fall through to the PowerShell path
///   rather than assume a state.
#[cfg(target_os = "windows")]
pub fn has_ipv6_binding_native(if_index: u32) -> Option<bool> {
    use windows::Win32::NetworkManagement::IpHelper::{
        GAA_FLAG_INCLUDE_PREFIX, GetAdaptersAddresses, IP_ADAPTER_ADDRESSES_LH,
    };
    use windows::Win32::Networking::WinSock::AF_INET6;

    // Hard cap on initial buffer so a huge machine doesn't make us allocate
    // unbounded memory; real-world values are a few KB.
    const MAX_BUFFER_BYTES: u32 = 256 * 1024;

    unsafe {
        let mut size: u32 = 0;
        // Probe size with AF_INET6 → only adapters that have the IPv6 stack
        // bound show up in the result set.
        let _ = GetAdaptersAddresses(
            AF_INET6.0 as u32,
            GAA_FLAG_INCLUDE_PREFIX,
            None,
            None,
            &mut size,
        );
        if size == 0 {
            // No adapter on the system has IPv6 bound at all — definitely not
            // ours.
            return Some(false);
        }
        if size > MAX_BUFFER_BYTES {
            return None;
        }

        let mut buffer = vec![0u8; size as usize];
        let adapter_addresses = buffer.as_mut_ptr() as *mut IP_ADAPTER_ADDRESSES_LH;
        let rc = GetAdaptersAddresses(
            AF_INET6.0 as u32,
            GAA_FLAG_INCLUDE_PREFIX,
            None,
            Some(adapter_addresses),
            &mut size,
        );
        if rc != 0 {
            return None;
        }

        let mut current = adapter_addresses;
        while !current.is_null() {
            let adapter = &*current;
            if adapter.Anonymous1.Anonymous.IfIndex == if_index {
                return Some(true);
            }
            current = adapter.Next;
        }
        Some(false)
    }
}

#[cfg(not(target_os = "windows"))]
pub fn has_ipv6_binding_native(_if_index: u32) -> Option<bool> {
    None
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

    #[cfg(not(target_os = "windows"))]
    #[test]
    fn test_has_ipv6_binding_native_returns_none_on_non_windows() {
        // On non-Windows the stub returns None so callers transparently fall
        // back to the PowerShell query path. If this regresses, the IPv6
        // disable fast-path would silently skip-or-not-skip in a
        // non-deterministic way on dev machines.
        assert_eq!(has_ipv6_binding_native(0), None);
        assert_eq!(has_ipv6_binding_native(999), None);
    }

    #[cfg(target_os = "windows")]
    #[test]
    fn test_has_ipv6_binding_native_handles_nonexistent_index() {
        // A very large, almost certainly unused if_index should produce
        // Some(false) — the IP Helper enumerates all IPv6 adapters and
        // doesn't find this one. If the API itself is broken we get None;
        // either way we must not panic.
        let result = has_ipv6_binding_native(0x7FFF_FFFF);
        assert!(
            matches!(result, Some(false) | None),
            "Expected Some(false) or None for bogus if_index, got {:?}",
            result
        );
    }
}
