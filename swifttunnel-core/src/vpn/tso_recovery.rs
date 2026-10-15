//! TSO (TCP Segmentation Offload) crash recovery
//!
//! Older versions disabled TSO on the physical adapter and saved its original
//! values. Current connections leave offload settings alone; startup and Repair
//! still restore recovery records left by those older versions.

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
                    "Set-NetAdapterAdvancedProperty -Name $adapter -RegistryKeyword '{}' -RegistryValue {} -ErrorAction Stop",
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
            "Set-NetAdapterAdvancedProperty -Name $adapter -RegistryKeyword '*LsoV2IPv4' -RegistryValue 1 -ErrorAction Stop".to_string(),
            "Set-NetAdapterAdvancedProperty -Name $adapter -RegistryKeyword '*LsoV2IPv6' -RegistryValue 1 -ErrorAction Stop".to_string(),
        ]
    }
}

/// Get the path to the TSO marker file
fn get_marker_path() -> Option<PathBuf> {
    dirs::data_local_dir().map(|d| d.join("SwiftTunnel").join(TSO_MARKER_FILE))
}

/// Per-query timeout for adapter offload probes.
///
/// The diagnostic queries IPv4 and IPv6, each with a two-second deadline.
/// The shared runner bounds process time, output capture and inherited pipes.
const ADAPTER_QUERY_TIMEOUT_SECS: u64 = 2;

fn query_adapter_offload_value(adapter_name: &str, keyword: &str) -> Option<u32> {
    use std::time::Duration;

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

    let output = crate::run_hidden_command_with_timeout(
        "powershell",
        &["-NoProfile", "-NonInteractive", "-Command", &script],
        Duration::from_secs(ADAPTER_QUERY_TIMEOUT_SECS),
    );
    output
        .success
        .then_some(output.stdout)?
        .lines()
        .map(str::trim)
        .find(|line| !line.is_empty())?
        .parse()
        .ok()
}

/// Whether this adapter currently has large-send offload switched off.
///
/// `None` when the adapter cannot be queried or does not expose the setting.
///
/// Reported rather than acted on. Recovery here is entirely marker driven, so
/// an adapter that an older build left with offload disabled stays that way
/// forever once the marker is gone, which happens when the user clears
/// %APPDATA%, reinstalls, or an uninstall tidies it away. The machine then does
/// packet segmentation in software permanently, with SwiftTunnel not even
/// running, and the only symptom is that everything feels slightly worse than
/// it used to. Putting the real state in the log is how that becomes visible
/// instead of a guess.
///
/// Restoring it automatically is deliberately not done here: a user may have
/// turned offload off themselves, and silently changing a network adapter
/// setting we did not set is worse than reporting it.
pub fn large_send_offload_is_disabled(adapter_name: &str) -> Option<bool> {
    let v4 = query_adapter_offload_value(adapter_name, "*LsoV2IPv4");
    let v6 = query_adapter_offload_value(adapter_name, "*LsoV2IPv6");
    match (v4, v6) {
        (None, None) => None,
        // 0 means the offload is off. Either family being off costs CPU.
        (a, b) => Some(a == Some(0) || b == Some(0)),
    }
}

/// Delete TSO marker file
pub fn delete_tso_marker() {
    if let Some(marker_path) = get_marker_path()
        && marker_path.exists()
    {
        if let Err(e) = fs::remove_file(&marker_path) {
            log::warn!("Failed to delete TSO marker file: {}", e);
        } else {
            log::debug!("TSO marker file deleted");
        }
    }
}

/// Check if TSO marker exists and return captured state if so.
pub fn read_tso_marker() -> Option<TsoMarker> {
    read_marker_at(&get_marker_path()?).ok().flatten()
}

fn read_marker_at(path: &std::path::Path) -> std::io::Result<Option<TsoMarker>> {
    let text = match crate::utils::read_text_file_bounded(path, 4096, "Adapter recovery record") {
        Ok(text) => text,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(e),
    };
    let invalid = || {
        std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "Invalid adapter recovery record",
        )
    };
    let marker = if text.trim_start().starts_with('{') {
        serde_json::from_str::<TsoMarker>(&text).map_err(|_| invalid())?
    } else {
        TsoMarker::legacy(text.trim().to_owned())
    };
    if marker.adapter_name.trim().is_empty()
        || marker.adapter_name.len() > 256
        || marker.adapter_name.chars().any(char::is_control)
        || [marker.lso_v2_ipv4, marker.lso_v2_ipv6]
            .into_iter()
            .flatten()
            .any(|v| v > 1)
        || [
            marker.tcp_checksum_offload_ipv4,
            marker.udp_checksum_offload_ipv4,
            marker.tcp_checksum_offload_ipv6,
            marker.udp_checksum_offload_ipv6,
        ]
        .into_iter()
        .flatten()
        .any(|v| v > 3)
    {
        return Err(invalid());
    }
    Ok(Some(marker))
}

fn build_restore_script(marker: &TsoMarker) -> String {
    let mut lines = vec![
        "$ErrorActionPreference = 'Stop'".to_string(),
        format!("$adapter = '{}'", marker.adapter_name().replace('\'', "''")),
    ];
    lines.extend(marker.restore_commands());
    lines.push("Write-Host 'TSO restored'".to_string());
    lines.join("\n")
}

/// Deadline for the adapter tools driven here.
///
/// The query path above already polls with a timeout because WMI is known to
/// hang; the restore paths had no such bound, which meant a hung PowerShell
/// could block rollback indefinitely.
#[cfg(windows)]
const TSO_COMMAND_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(60);

fn restore_tso_for_marker(marker: &TsoMarker) -> bool {
    let script = build_restore_script(marker);
    match crate::run_hidden_command_with_timeout(
        "powershell",
        &["-NoProfile", "-NonInteractive", "-Command", &script],
        TSO_COMMAND_TIMEOUT,
    ) {
        output if !output.timed_out => {
            if output.success {
                log::info!(
                    "TSO restored successfully for adapter: {}",
                    marker.adapter_name()
                );
                true
            } else {
                let stderr = output.stderr.trim();
                log::warn!(
                    "TSO restore failed for adapter {}: {}",
                    marker.adapter_name(),
                    stderr
                );
                false
            }
        }
        _ => {
            log::error!(
                "TSO restore for adapter {} exceeded its deadline and was stopped",
                marker.adapter_name()
            );
            false
        }
    }
}

/// Restore TSO settings from the marker file if one exists.
pub fn restore_tso_from_marker() -> Option<bool> {
    let path = get_marker_path()?;
    match read_marker_at(&path) {
        Ok(marker) => marker.map(|marker| restore_tso_for_marker(&marker)),
        Err(e) => {
            log::warn!("Could not read adapter recovery record; it was kept: {e}");
            Some(false)
        }
    }
}

/// Recover TSO settings on application startup
pub fn recover_tso_on_startup() {
    if let Some(path) = get_marker_path()
        && let Err(e) = recover_marker_at(&path, restore_tso_for_marker)
    {
        log::warn!("Adapter recovery could not finish; its record was kept: {e}");
    }
}

fn recover_marker_at(
    path: &std::path::Path,
    restore: impl FnOnce(&TsoMarker) -> bool,
) -> std::io::Result<()> {
    if let Some(marker) = read_marker_at(path)? {
        log::warn!(
            "TSO marker found - app may have crashed while TSO was disabled. Adapter: {}",
            marker.adapter_name()
        );

        if restore(&marker) {
            fs::remove_file(path)?;
            log::info!("TSO recovery complete");
        } else {
            log::error!("TSO recovery failed - will retry on next launch");
        }
    }
    Ok(())
}

/// Emergency TSO restore for panic handler.
///
/// Best-effort restore without mutating the marker file so startup recovery can
/// retry if the process terminates before the adapter is fully restored.
pub fn emergency_tso_restore() {
    if let Some(marker) = read_tso_marker() {
        let script = build_restore_script(&marker);
        // Best effort on the way out, but still bounded: this runs during
        // shutdown, and a hang here would keep the process alive.
        let _ = crate::run_hidden_command_with_timeout(
            "powershell",
            &["-NoProfile", "-NonInteractive", "-Command", &script],
            TSO_COMMAND_TIMEOUT,
        );
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
    fn recovery_keeps_original_values_until_a_restore_succeeds() {
        let dir = Fixture::new();
        let path = dir.0.join("marker");
        let marker = TsoMarker {
            adapter_name: "Owned test fixture".into(),
            lso_v2_ipv4: Some(0),
            lso_v2_ipv6: Some(1),
            ..Default::default()
        };
        let bytes = serde_json::to_vec(&marker).unwrap();
        fs::write(&path, &bytes).unwrap();
        assert_eq!(read_marker_at(&path).unwrap(), Some(marker.clone()));
        recover_marker_at(&path, |actual| {
            assert_eq!(actual, &marker);
            false
        })
        .unwrap();
        assert_eq!(fs::read(&path).unwrap(), bytes);
        recover_marker_at(&path, |actual| {
            assert_eq!(actual, &marker);
            true
        })
        .unwrap();
        assert_eq!(read_marker_at(&path).unwrap(), None);
    }

    struct Fixture(PathBuf);
    impl Fixture {
        fn new() -> Self {
            let path =
                std::env::temp_dir().join(format!("swift-tso-{:016x}", rand::random::<u64>()));
            fs::create_dir(&path).unwrap();
            Self(path)
        }
    }
    impl Drop for Fixture {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    #[test]
    fn damaged_recovery_records_are_kept_and_never_treated_as_adapter_names() {
        let dir = Fixture::new();
        let path = dir.0.join("marker");
        for bytes in [
            b"{broken json".to_vec(),
            vec![b'a'; 4097],
            b"{\"adapter_name\":\"Test\",\"lso_v2_ipv4\":99}".to_vec(),
            b"Test\nAdapter".to_vec(),
            vec![0xff],
        ] {
            fs::write(&path, &bytes).unwrap();
            assert!(
                recover_marker_at(&path, |_| panic!(
                    "Damaged record must not change the adapter"
                ))
                .is_err()
            );
            assert_eq!(fs::read(&path).unwrap(), bytes);
        }
        fs::write(&path, b"Legacy Ethernet\r\n").unwrap();
        assert_eq!(
            read_marker_at(&path).unwrap().unwrap().adapter_name(),
            "Legacy Ethernet"
        );
    }

    #[cfg(windows)]
    #[test]
    fn failed_restore_command_stops_before_claiming_success() {
        let marker = TsoMarker {
            adapter_name: "Test".into(),
            lso_v2_ipv4: Some(0),
            lso_v2_ipv6: Some(1),
            ..Default::default()
        };
        // Shadow the cmdlet with an owned failure. Never touch a real adapter.
        let script = format!(
            "function Set-NetAdapterAdvancedProperty {{ throw 'owned restore failure' }}\n{}",
            build_restore_script(&marker)
        );
        let output = crate::run_hidden_command_with_timeout(
            "powershell",
            &["-NoProfile", "-NonInteractive", "-Command", &script],
            std::time::Duration::from_secs(5),
        );
        assert!(!output.success);
        assert!(output.stderr.contains("owned restore failure"));
        assert!(!output.stdout.contains("TSO restored"));
    }
}
