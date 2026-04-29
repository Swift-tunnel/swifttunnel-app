//! TSO (TCP Segmentation Offload) crash recovery
//!
//! When SwiftTunnel disables TSO on the physical network adapter for split tunneling,
//! it writes the adapter's original offload settings to a marker file. If the app
//! crashes before restoring them, the marker persists and startup recovery restores
//! the exact previous adapter values instead of forcing generic defaults.

use serde::{Deserialize, Serialize};
use std::fs;
use std::path::PathBuf;

/// Marker file name stored in %LOCALAPPDATA%/SwiftTunnel/
const TSO_MARKER_FILE: &str = "tso_disabled.marker";

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct TsoMarker {
    adapter_name: String,
    lso_v2_ipv4: Option<u32>,
    lso_v2_ipv6: Option<u32>,
    tcp_checksum_offload_ipv4: Option<u32>,
    udp_checksum_offload_ipv4: Option<u32>,
    tcp_checksum_offload_ipv6: Option<u32>,
    udp_checksum_offload_ipv6: Option<u32>,
}

impl TsoMarker {
    fn legacy(adapter_name: String) -> Self {
        Self {
            adapter_name,
            ..Self::default()
        }
    }

    pub fn adapter_name(&self) -> &str {
        &self.adapter_name
    }

    fn restore_commands(&self) -> Vec<String> {
        let captured_commands = [
            ("*LsoV2IPv4", self.lso_v2_ipv4),
            ("*LsoV2IPv6", self.lso_v2_ipv6),
            ("*TCPChecksumOffloadIPv4", self.tcp_checksum_offload_ipv4),
            ("*UDPChecksumOffloadIPv4", self.udp_checksum_offload_ipv4),
            ("*TCPChecksumOffloadIPv6", self.tcp_checksum_offload_ipv6),
            ("*UDPChecksumOffloadIPv6", self.udp_checksum_offload_ipv6),
        ]
        .into_iter()
        .filter_map(|(keyword, value)| {
            value.map(|registry_value| {
                format!(
                    "Set-NetAdapterAdvancedProperty -Name $adapter -RegistryKeyword '{}' -RegistryValue {} 2>$null",
                    keyword, registry_value
                )
            })
        })
        .collect::<Vec<_>>();

        if !captured_commands.is_empty() {
            return captured_commands;
        }

        // Legacy / no-captured-values fallback. Only re-enable LSO — checksum
        // offload is no longer something we touch on connect, so we must not
        // forcibly re-enable it here either (a user who manually disabled
        // checksum offload for their own reasons would otherwise have it
        // silently restored on next disconnect).
        vec![
            "Set-NetAdapterAdvancedProperty -Name $adapter -RegistryKeyword '*LsoV2IPv4' -RegistryValue 1 2>$null".to_string(),
            "Set-NetAdapterAdvancedProperty -Name $adapter -RegistryKeyword '*LsoV2IPv6' -RegistryValue 1 2>$null".to_string(),
        ]
    }
}

/// Get the path to the TSO marker file
fn get_marker_path() -> Option<PathBuf> {
    dirs::data_local_dir().map(|d| d.join("SwiftTunnel").join(TSO_MARKER_FILE))
}

/// Per-query timeout for adapter offload probes.
///
/// 6 queries × 2s = 12s absolute worst case for a full marker capture. A hung
/// WMI provider on a flaky NIC (Realtek RTL8821CE in the 2026-04-19 incident)
/// can otherwise block `.output()` for 30–60s, freezing whichever thread
/// called us. Every call site now runs this off the connect path, but the
/// bound is still the right belt-and-braces.
const ADAPTER_QUERY_TIMEOUT_SECS: u64 = 2;

fn query_adapter_offload_value(adapter_name: &str, keyword: &str) -> Option<u32> {
    use std::io::Read;
    use std::time::{Duration, Instant};

    let script = format!(
        r#"
        $adapter = '{}'
        $value = Get-NetAdapterAdvancedProperty -Name $adapter -RegistryKeyword '{}' -ErrorAction SilentlyContinue |
            Select-Object -First 1 -ExpandProperty RegistryValue
        if ($null -eq $value) {{ exit 0 }}
        if ($value -is [Array]) {{ $value = $value[0] }}
        Write-Output $value
        "#,
        adapter_name.replace('\'', "''"),
        keyword
    );

    let mut child = crate::hidden_command("powershell")
        .args(["-NoProfile", "-NonInteractive", "-Command", &script])
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .ok()?;

    let start = Instant::now();
    let timeout = Duration::from_secs(ADAPTER_QUERY_TIMEOUT_SECS);

    loop {
        match child.try_wait() {
            Ok(Some(status)) => {
                if !status.success() {
                    return None;
                }
                let mut stdout = String::new();
                if let Some(mut pipe) = child.stdout.take() {
                    let _ = pipe.read_to_string(&mut stdout);
                }
                return stdout
                    .lines()
                    .map(str::trim)
                    .find(|line| !line.is_empty())
                    .and_then(|line| line.parse::<u32>().ok());
            }
            Ok(None) => {
                if start.elapsed() >= timeout {
                    log::warn!(
                        "TSO query for '{}' on '{}' timed out after {}s (WMI hung?), skipping",
                        keyword,
                        adapter_name,
                        ADAPTER_QUERY_TIMEOUT_SECS
                    );
                    let _ = child.kill();
                    let _ = child.wait();
                    return None;
                }
                std::thread::sleep(Duration::from_millis(50));
            }
            Err(_) => {
                let _ = child.kill();
                let _ = child.wait();
                return None;
            }
        }
    }
}

fn capture_tso_marker(adapter_name: &str) -> TsoMarker {
    // We only capture/restore LSO. Checksum-offload toggles are no longer
    // performed on connect (they triggered repeated NIC resets that dropped
    // the default route mid-connect), so capturing them would only cost
    // 4 extra Get-NetAdapterAdvancedProperty calls — each up to
    // ADAPTER_QUERY_TIMEOUT_SECS — for values we'll never use on restore.
    //
    // The struct still has the fields so on-disk markers from older builds
    // still deserialize cleanly; their restore commands still run via
    // `TsoMarker::restore_commands` so users upgrading mid-session don't end
    // up with checksum offload stuck disabled.
    TsoMarker {
        adapter_name: adapter_name.trim().to_string(),
        lso_v2_ipv4: query_adapter_offload_value(adapter_name, "*LsoV2IPv4"),
        lso_v2_ipv6: query_adapter_offload_value(adapter_name, "*LsoV2IPv6"),
        tcp_checksum_offload_ipv4: None,
        udp_checksum_offload_ipv4: None,
        tcp_checksum_offload_ipv6: None,
        udp_checksum_offload_ipv6: None,
    }
}

/// Write TSO disabled marker with adapter name and original offload settings.
pub fn write_tso_marker(adapter_name: &str) {
    if let Some(marker_path) = get_marker_path() {
        if let Some(parent) = marker_path.parent() {
            let _ = fs::create_dir_all(parent);
        }

        let marker = capture_tso_marker(adapter_name);
        let payload =
            serde_json::to_vec(&marker).unwrap_or_else(|_| adapter_name.as_bytes().to_vec());

        if let Err(e) = fs::write(&marker_path, payload) {
            log::warn!("Failed to write TSO marker file: {}", e);
        } else {
            log::debug!("TSO marker written for adapter: {}", marker.adapter_name());
        }
    }
}

/// Delete TSO marker file
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

/// Check if TSO marker exists and return captured state if so.
pub fn read_tso_marker() -> Option<TsoMarker> {
    let marker_path = get_marker_path()?;
    if !marker_path.exists() {
        return None;
    }

    let raw = fs::read(&marker_path).ok()?;
    if let Ok(marker) = serde_json::from_slice::<TsoMarker>(&raw) {
        if !marker.adapter_name.trim().is_empty() {
            return Some(marker);
        }
    }

    let adapter_name = String::from_utf8_lossy(&raw).trim().to_string();
    if adapter_name.is_empty() {
        None
    } else {
        Some(TsoMarker::legacy(adapter_name))
    }
}

fn build_restore_script(marker: &TsoMarker) -> String {
    let mut lines = vec![
        "$ErrorActionPreference = 'SilentlyContinue'".to_string(),
        format!("$adapter = '{}'", marker.adapter_name().replace('\'', "''")),
    ];
    lines.extend(marker.restore_commands());
    lines.push("Write-Host 'TSO restored'".to_string());
    lines.join("\n")
}

fn restore_tso_for_marker(marker: &TsoMarker) -> bool {
    let script = build_restore_script(marker);
    match crate::hidden_command("powershell")
        .args(["-NoProfile", "-NonInteractive", "-Command", &script])
        .output()
    {
        Ok(output) => {
            if output.status.success() {
                log::info!(
                    "TSO restored successfully for adapter: {}",
                    marker.adapter_name()
                );
                true
            } else {
                let stderr = String::from_utf8_lossy(&output.stderr);
                log::warn!(
                    "TSO restore failed for adapter {}: {}",
                    marker.adapter_name(),
                    stderr
                );
                false
            }
        }
        Err(e) => {
            log::error!("Failed to run PowerShell for TSO restore: {}", e);
            false
        }
    }
}

/// Restore TSO settings from the marker file if one exists.
pub fn restore_tso_from_marker() -> Option<bool> {
    let marker = read_tso_marker()?;
    Some(restore_tso_for_marker(&marker))
}

/// Recover TSO settings on application startup
pub fn recover_tso_on_startup() {
    if let Some(marker) = read_tso_marker() {
        log::warn!(
            "TSO marker found - app may have crashed while TSO was disabled. Adapter: {}",
            marker.adapter_name()
        );

        if restore_tso_for_marker(&marker) {
            delete_tso_marker();
            log::info!("TSO recovery complete");
        } else {
            log::error!("TSO recovery failed - will retry on next launch");
        }
    }
}

/// Emergency TSO restore for panic handler.
///
/// Best-effort restore without mutating the marker file so startup recovery can
/// retry if the process terminates before the adapter is fully restored.
pub fn emergency_tso_restore() {
    if let Some(marker) = read_tso_marker() {
        let script = build_restore_script(&marker);
        let _ = crate::hidden_command("powershell")
            .args(["-NoProfile", "-NonInteractive", "-Command", &script])
            .output();
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

        write_tso_marker(test_adapter);

        let read_back = read_tso_marker();
        assert_eq!(
            read_back
                .as_ref()
                .map(|marker| marker.adapter_name().to_string()),
            Some(test_adapter.to_string())
        );

        delete_tso_marker();

        let after_delete = read_tso_marker();
        assert_eq!(after_delete, None);
    }
}
