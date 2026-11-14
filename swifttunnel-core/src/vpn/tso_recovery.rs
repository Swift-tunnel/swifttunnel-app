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
#[cfg(not(test))]
fn get_marker_path() -> Option<PathBuf> {
    dirs::data_local_dir().map(|d| d.join("SwiftTunnel").join(TSO_MARKER_FILE))
}
#[cfg(test)]
fn get_marker_path() -> Option<PathBuf> {
    Some(crate::test_support::recovery_directory().join(TSO_MARKER_FILE))
}

/// Read the selected adapter's configured LSO values without starting WMI or
/// PowerShell. These are diagnostics only, never used to change an adapter.
/// Missing, unsupported, ambiguous or unreadable configuration stays unknown.
#[cfg(windows)]
pub fn large_send_offload_is_disabled(adapter_guid: &str) -> Option<bool> {
    use winreg::{
        RegKey,
        enums::{HKEY_LOCAL_MACHINE, KEY_ENUMERATE_SUB_KEYS, KEY_WOW64_64KEY},
    };
    let target = parse_adapter_guid(adapter_guid)?;
    let class = RegKey::predef(HKEY_LOCAL_MACHINE)
        .open_subkey_with_flags(
            r"SYSTEM\CurrentControlSet\Control\Class\{4d36e972-e325-11ce-bfc1-08002be10318}",
            KEY_ENUMERATE_SUB_KEYS | KEY_WOW64_64KEY,
        )
        .ok()?;
    offload_disabled_in_class(&class, target)
}

#[cfg(not(windows))]
pub fn large_send_offload_is_disabled(_adapter_guid: &str) -> Option<bool> {
    None
}

#[cfg(windows)]
fn parse_adapter_guid(value: &str) -> Option<windows::core::GUID> {
    windows::core::GUID::try_from(value.trim_matches(['{', '}'])).ok()
}

#[cfg(windows)]
fn offload_disabled_in_class(class: &winreg::RegKey, target: windows::core::GUID) -> Option<bool> {
    use winreg::enums::{KEY_QUERY_VALUE, KEY_WOW64_64KEY};
    let mut selected = None;
    for (index, name) in class.enum_keys().enumerate() {
        if index >= 1024 {
            return None;
        }
        let name = name.ok()?;
        // Device instance keys are numeric. Do not open unrelated class
        // metadata such as Properties, which can require extra privileges.
        if name.len() != 4 || !name.bytes().all(|b| b.is_ascii_digit()) {
            continue;
        }
        let Ok(adapter) = class.open_subkey_with_flags(&name, KEY_QUERY_VALUE | KEY_WOW64_64KEY)
        else {
            continue;
        };
        let guid = crate::registry_value::read::<String>(&adapter, "NetCfgInstanceId")
            .ok()
            .flatten()
            .and_then(|s| parse_adapter_guid(&s));
        if guid == Some(target) && selected.replace(adapter).is_some() {
            return None;
        }
    }
    let adapter = selected?;
    let values = ["*LsoV2IPv4", "*LsoV2IPv6"].map(|keyword| read_offload_value(&adapter, keyword));
    if values.contains(&Some(0)) {
        Some(true)
    } else if values.contains(&Some(1)) {
        Some(false)
    } else {
        None
    }
}

#[cfg(windows)]
fn read_offload_value(adapter: &winreg::RegKey, keyword: &str) -> Option<u32> {
    use winreg::{enums::RegType, types::FromRegValue};
    let raw = crate::registry_value::read_raw(adapter, keyword).ok()??;
    let value = match raw.vtype {
        RegType::REG_SZ => String::from_reg_value(&raw).ok()?.trim().parse().ok()?,
        RegType::REG_DWORD => u32::from_reg_value(&raw).ok()?,
        _ => return None,
    };
    (value <= 1).then_some(value)
}

#[cfg(all(test, windows))]
mod offload_query_tests {
    use super::*;
    use winreg::{
        RegKey, RegValue,
        enums::{HKEY_CURRENT_USER, RegType},
    };
    struct Fixture {
        path: String,
        class: RegKey,
    }
    impl Fixture {
        fn new() -> Self {
            let path = format!(
                r"Software\SwiftTunnel-Offload-{:032x}",
                rand::random::<u128>()
            );
            let (class, _) = RegKey::predef(HKEY_CURRENT_USER)
                .create_subkey(&path)
                .unwrap();
            Self { path, class }
        }
    }
    impl Drop for Fixture {
        fn drop(&mut self) {
            let _ = RegKey::predef(HKEY_CURRENT_USER).delete_subkey_all(&self.path);
        }
    }
    const TARGET: &str = "381b4222-f694-41f0-9685-ff5bb260df2e";
    #[test]
    fn native_offload_reads_only_the_exact_adapter_and_keeps_unknown_values_unknown() {
        let fixture = Fixture::new();
        let target = parse_adapter_guid(TARGET).unwrap();
        let query = || offload_disabled_in_class(&fixture.class, target);
        let (other, _) = fixture.class.create_subkey("0000").unwrap();
        other
            .set_value("NetCfgInstanceId", &"8c5e7fda-e8bf-4a96-9a85-a6e23a8c635c")
            .unwrap();
        other.set_value("*LsoV2IPv4", &"0").unwrap();
        assert_eq!(query(), None);
        let (selected, _) = fixture.class.create_subkey("0001").unwrap();
        selected
            .set_value(
                "NetCfgInstanceId",
                &format!("{{{}}}", TARGET.to_uppercase()),
            )
            .unwrap();
        assert_eq!(query(), None);
        selected.set_value("*LsoV2IPv4", &"1").unwrap();
        assert_eq!(query(), Some(false));
        selected.set_value("*LsoV2IPv6", &0u32).unwrap();
        assert_eq!(query(), Some(true));
        selected.set_value("*LsoV2IPv6", &7u32).unwrap();
        assert_eq!(query(), Some(false));
        selected.set_value("*LsoV2IPv4", &"invalid").unwrap();
        assert_eq!(query(), None);
        selected
            .set_raw_value(
                "*LsoV2IPv4",
                &RegValue {
                    vtype: RegType::REG_BINARY,
                    bytes: vec![0],
                },
            )
            .unwrap();
        assert_eq!(query(), None);
        selected
            .set_raw_value(
                "*LsoV2IPv4",
                &RegValue {
                    vtype: RegType::REG_SZ,
                    bytes: vec![0; crate::registry_value::MAX_VALUE_BYTES + 2],
                },
            )
            .unwrap();
        assert_eq!(query(), None);
        assert!(parse_adapter_guid("not-an-adapter-guid").is_none());
    }
    #[test]
    fn duplicate_adapter_ids_are_not_an_authoritative_offload_reading() {
        let fixture = Fixture::new();
        for name in ["0000", "0001"] {
            let (key, _) = fixture.class.create_subkey(name).unwrap();
            key.set_value("NetCfgInstanceId", &TARGET).unwrap();
            key.set_value("*LsoV2IPv4", &"0").unwrap();
        }
        assert_eq!(
            offload_disabled_in_class(&fixture.class, parse_adapter_guid(TARGET).unwrap()),
            None
        );
    }

    #[test]
    #[ignore = "read-only comparison against this machine's physical adapter settings"]
    fn compare_native_offload_with_local_netadapter_cmdlet() {
        #[derive(serde::Deserialize)]
        struct Row {
            guid: String,
            values: Vec<String>,
        }
        let script = r#"
            $ErrorActionPreference='Stop'
            $rows = @(Get-NetAdapter -Physical -ErrorAction Stop | ForEach-Object {
                $device = $_
                $values = @(Get-NetAdapterAdvancedProperty -Name ([Management.Automation.WildcardPattern]::Escape($device.Name)) -RegistryKeyword '*LsoV2IPv4','*LsoV2IPv6' -ErrorAction SilentlyContinue |
                    ForEach-Object { $_.RegistryValue } | ForEach-Object { [string]$_ })
                [pscustomobject]@{guid=[string]$device.InterfaceGuid;values=$values}
            })
            ConvertTo-Json -InputObject $rows -Compress -Depth 4
        "#;
        let output = crate::run_hidden_command_with_timeout(
            "powershell",
            &["-NoProfile", "-NonInteractive", "-Command", script],
            std::time::Duration::from_secs(15),
        );
        assert!(output.success, "{}", output.stderr);
        let rows: Vec<Row> = serde_json::from_str(output.stdout.trim()).unwrap();
        let mut known = 0;
        for row in &rows {
            let expected = if row.values.iter().any(|value| value == "0") {
                Some(true)
            } else if row.values.iter().any(|value| value == "1") {
                Some(false)
            } else {
                None
            };
            assert_eq!(large_send_offload_is_disabled(&row.guid), expected);
            known += usize::from(expected.is_some());
        }
        assert!(
            known > 0,
            "this comparison needs at least one supported physical adapter"
        );
        eprintln!(
            "Read-only offload comparison: {} adapter(s) matched, {known} with known LSO configuration",
            rows.len()
        );
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
    if let Err(e) = recover_tso_checked() {
        log::warn!("Adapter recovery could not finish; its record was kept: {e}");
    }
}

/// Explicit repairs must be able to distinguish a failed restore from success.
pub fn recover_tso_checked() -> std::io::Result<bool> {
    let path = get_marker_path().ok_or_else(|| {
        std::io::Error::other("Windows could not locate the adapter recovery record folder")
    })?;
    recover_marker_at(&path, restore_tso_for_marker)
}

fn recover_marker_at(
    path: &std::path::Path,
    restore: impl FnOnce(&TsoMarker) -> bool,
) -> std::io::Result<bool> {
    if let Some(marker) = read_marker_at(path)? {
        log::warn!(
            "TSO marker found - app may have crashed while TSO was disabled. Adapter: {}",
            marker.adapter_name()
        );

        if restore(&marker) {
            fs::remove_file(path)?;
            log::info!("TSO recovery complete");
        } else {
            return Err(std::io::Error::other(
                "Adapter offload settings could not be restored; their recovery record was kept",
            ));
        }
        return Ok(true);
    }
    Ok(false)
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

    #[cfg(windows)]
    #[test]
    fn recovery_reports_a_record_that_cannot_be_retired() {
        use std::os::windows::fs::OpenOptionsExt;
        let path = get_marker_path().unwrap();
        let bytes = b"Owned test adapter\r\n";
        fs::write(&path, bytes).unwrap();
        // Windows denies deletion while this owned fixture omits FILE_SHARE_DELETE.
        let held = fs::OpenOptions::new()
            .read(true)
            .share_mode(3)
            .open(&path)
            .unwrap();
        assert!(recover_marker_at(&path, |_| true).is_err());
        assert_eq!(fs::read(&path).unwrap(), bytes);
        drop(held);
        assert!(recover_marker_at(&path, |_| true).unwrap());
        assert!(!path.exists());
    }

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
        assert!(
            recover_marker_at(&path, |actual| {
                assert_eq!(actual, &marker);
                false
            })
            .is_err()
        );
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
