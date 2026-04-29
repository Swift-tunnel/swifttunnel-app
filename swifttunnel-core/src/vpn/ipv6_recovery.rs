//! IPv6 leak-prevention crash recovery
//!
//! While connected, SwiftTunnel installs a Windows Firewall rule that blocks
//! outbound IPv6. The marker file records that we did so (and which method we
//! used) so a startup recovery pass can clean up after a crash without
//! guessing at adapter state. Old installations used a different method
//! (`Disable-NetAdapterBinding ms_tcpip6`); we keep the deserialization shape
//! backwards-compatible so an upgrade across that boundary still recovers
//! cleanly.

pub const IPV6_BLOCK_RULE_NAME: &str = "SwiftTunnel-Block-IPv6-Outbound";
pub const IPV6_BLOCK_REMOTE_IPS: &str = "2000::/3,64:ff9b::/96";

use serde::{Deserialize, Serialize};
use std::fs;
use std::path::PathBuf;

/// Marker file name stored in %LOCALAPPDATA%/SwiftTunnel/
const IPV6_MARKER_FILE: &str = "ipv6_disabled.marker";

/// How SwiftTunnel prevented IPv6 leakage during the session this marker
/// belongs to.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub enum DisableMethod {
    /// Pre-2.0.15 method: `Disable-NetAdapterBinding -ComponentId ms_tcpip6`.
    /// Causes an NDIS rebind which physically takes the adapter offline for
    /// 2-10s on many real-world NICs (Realtek, USB-Ethernet, Parallels VirtIO,
    /// some Intel) — users see "my Ethernet just turned off." Default for
    /// markers that predate the method field.
    #[default]
    BindingDisable,
    /// Current method: a Windows Firewall outbound block rule named
    /// [`IPV6_BLOCK_RULE_NAME`] that drops public IPv6/NAT64 traffic. No
    /// adapter rebind, no WMI involvement.
    FirewallRule,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct Ipv6Marker {
    adapter_name: String,
    originally_enabled: Option<bool>,
    #[serde(default)]
    method: DisableMethod,
}

impl Ipv6Marker {
    fn legacy(adapter_name: String) -> Self {
        Self {
            adapter_name,
            originally_enabled: None,
            method: DisableMethod::BindingDisable,
        }
    }

    pub(crate) fn for_firewall_rule(adapter_name: String) -> Self {
        Self {
            adapter_name,
            originally_enabled: None,
            method: DisableMethod::FirewallRule,
        }
    }

    pub fn adapter_name(&self) -> &str {
        &self.adapter_name
    }

    pub fn method(&self) -> &DisableMethod {
        &self.method
    }

    fn restore_command(&self) -> String {
        match self.method {
            DisableMethod::FirewallRule => format!(
                r#"
        $name = "{}"
        $deleteOutput = & netsh.exe advfirewall firewall delete rule name="$name" 2>&1
        $deleteExit = $LASTEXITCODE
        $showOutput = & netsh.exe advfirewall firewall show rule name="$name" 2>&1
        $showExit = $LASTEXITCODE
        $deleteText = ($deleteOutput | Out-String).Trim()
        $showText = ($showOutput | Out-String).Trim()

        if ($showExit -eq 0) {{
            Write-Error ('IPv6 block firewall rule still exists after delete attempt. Delete exit=' + $deleteExit + '. Delete output: ' + $deleteText)
            exit 1
        }}

        if ($deleteExit -ne 0 -and $showText -notmatch 'No rules match') {{
            Write-Error ('Could not verify IPv6 block firewall rule removal. Delete exit=' + $deleteExit + '. Delete output: ' + $deleteText + '. Show output: ' + $showText)
            exit 1
        }}
        "#,
                IPV6_BLOCK_RULE_NAME
            ),
            DisableMethod::BindingDisable => match self.originally_enabled {
                Some(false) => {
                    "Disable-NetAdapterBinding -Name $adapter -ComponentId ms_tcpip6 -Confirm:$false 2>$null".to_string()
                }
                _ => "Enable-NetAdapterBinding -Name $adapter -ComponentId ms_tcpip6 2>$null"
                    .to_string(),
            },
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
/// `if_index` currently has an IPv6 address on it. Used as a fast pre-check
/// before attempting `Disable-NetAdapterBinding`, which can hang 30+ seconds on
/// Realtek / slow-WMI machines even when there is nothing to disable.
///
/// Strictly speaking, `GetAdaptersAddresses(AF_INET6)` filters by "has at
/// least one IPv6 address", not by binding state — but in practice the two are
/// equivalent on up-and-running adapters because the ms_tcpip6 binding auto-
/// configures a link-local `fe80::/10` address the moment it's enabled, and
/// tentative-DAD addresses are included in the enumeration. Edge cases (IPv6
/// stack globally disabled via `DisabledComponents`, adapter down) have no
/// routable v6 path anyway, so skipping the disable is safe.
///
/// Returns:
/// - `Some(true)` → adapter has an IPv6 address (caller should proceed with
///   the disable call).
/// - `Some(false)` → no IPv6 addresses on the system or not on this adapter
///   (caller can skip entirely — this is the case that saves ~22s on adapters
///   like Realtek RTL8821CE).
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

    // Win32 error codes (ERROR_SUCCESS=0, ERROR_BUFFER_OVERFLOW=111,
    // ERROR_NO_DATA=232). Inlined here to avoid pulling in winerror.
    const ERROR_SUCCESS: u32 = 0;
    const ERROR_BUFFER_OVERFLOW: u32 = 111;
    const ERROR_NO_DATA: u32 = 232;

    unsafe {
        let mut size: u32 = 0;
        // Probe size with AF_INET6. The API guarantees `*SizePointer` is only
        // updated on `ERROR_BUFFER_OVERFLOW`; on any other return value (including
        // transient failures) `size` stays 0 — we must NOT mis-interpret that as
        // "no IPv6 anywhere".
        let rc = GetAdaptersAddresses(
            AF_INET6.0 as u32,
            GAA_FLAG_INCLUDE_PREFIX,
            None,
            None,
            &mut size,
        );
        match rc {
            ERROR_BUFFER_OVERFLOW => {
                // Proceed to allocate + second call below.
            }
            ERROR_NO_DATA => {
                // Genuine "no IPv6 adapters on system" — safe to skip disable.
                return Some(false);
            }
            _ => {
                // Probe failed for a reason we can't distinguish from "adapter
                // exists but API had a hiccup". Punt to PowerShell.
                return None;
            }
        }

        if size == 0 || size > MAX_BUFFER_BYTES {
            return None;
        }

        // Allocate as `Vec<u64>` so the buffer has 8-byte alignment — required
        // by `IP_ADAPTER_ADDRESSES_LH` (which contains a `u64` union member).
        // `Vec<u8>::as_mut_ptr()` only guarantees 1-byte alignment per the
        // documented contract; casting that to `*mut IP_ADAPTER_ADDRESSES_LH`
        // and creating a reference through it is UB per the Rust Reference
        // even though `HeapAlloc` happens to return 16-byte-aligned blocks on
        // x64 Windows today. Miri flags the `Vec<u8>` form.
        let u64_elems = (size as usize + 7) / 8;
        let mut buffer: Vec<u64> = vec![0u64; u64_elems];
        let adapter_addresses = buffer.as_mut_ptr() as *mut IP_ADAPTER_ADDRESSES_LH;

        let rc = GetAdaptersAddresses(
            AF_INET6.0 as u32,
            GAA_FLAG_INCLUDE_PREFIX,
            None,
            Some(adapter_addresses),
            &mut size,
        );
        if rc != ERROR_SUCCESS {
            return None;
        }

        let mut current = adapter_addresses;
        while !current.is_null() {
            let adapter = &*current;
            // Both IfIndex (IPv4-ordinal) and Ipv6IfIndex are populated by
            // GetAdaptersAddresses. On physical NICs they are almost always
            // equal, but checking both costs nothing and defends against
            // callers that seeded `if_index` from an IPv6-specific source.
            if adapter.Anonymous1.Anonymous.IfIndex == if_index || adapter.Ipv6IfIndex == if_index {
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
    let marker = Ipv6Marker {
        adapter_name: adapter_name.trim().to_string(),
        originally_enabled: query_ipv6_binding_enabled(adapter_name),
        method: DisableMethod::BindingDisable,
    };
    write_marker(&marker);
}

/// Write a marker indicating the firewall-rule method was used to block IPv6.
/// Used by the modern disable path so a crash-recovery pass can run
/// `netsh advfirewall firewall delete rule` to clean up.
pub fn write_ipv6_marker_firewall(adapter_name: &str) {
    let marker = Ipv6Marker::for_firewall_rule(adapter_name.trim().to_string());
    write_marker(&marker);
}

fn write_marker(marker: &Ipv6Marker) {
    if let Some(marker_path) = get_marker_path() {
        if let Some(parent) = marker_path.parent() {
            let _ = fs::create_dir_all(parent);
        }

        let payload = serde_json::to_vec(marker)
            .unwrap_or_else(|_| marker.adapter_name().as_bytes().to_vec());

        if let Err(e) = fs::write(&marker_path, payload) {
            log::warn!("Failed to write IPv6 marker file: {}", e);
        } else {
            log::debug!(
                "IPv6 marker written for adapter: {} (method: {:?})",
                marker.adapter_name(),
                marker.method()
            );
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

    #[test]
    fn test_firewall_rule_restore_command_references_block_rule_name() {
        let marker = Ipv6Marker::for_firewall_rule("Ethernet".to_string());
        let cmd = marker.restore_command();
        assert!(cmd.contains(IPV6_BLOCK_RULE_NAME), "{}", cmd);
        assert!(cmd.contains("netsh.exe advfirewall firewall delete rule"));
        assert!(cmd.contains("netsh.exe advfirewall firewall show rule"));
        assert!(cmd.contains("exit 1"));
    }

    #[test]
    fn test_legacy_marker_round_trip_uses_binding_disable_method() {
        // Markers written by pre-2.0.15 builds do not include the `method`
        // field. They must deserialize as BindingDisable so the restore path
        // runs Enable-NetAdapterBinding (matching the original behavior).
        let legacy_payload = br#"{"adapter_name":"Ethernet","originally_enabled":true}"#;
        let marker: Ipv6Marker = serde_json::from_slice(legacy_payload).unwrap();
        assert_eq!(marker.method(), &DisableMethod::BindingDisable);
        assert_eq!(marker.adapter_name(), "Ethernet");
        assert!(marker.restore_command().contains("Enable-NetAdapterBinding"));
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

    #[cfg(target_os = "windows")]
    #[test]
    fn test_has_ipv6_binding_native_positive_path() {
        // Enumerate adapters ourselves, pick one with an IPv6 address, then
        // assert `has_ipv6_binding_native(that.IfIndex) == Some(true)`. This
        // is what protects the adapter-iteration loop from being deleted /
        // short-circuited to a bare `None` or `Some(false)` — the previous
        // `matches!(..., Some(false) | None)` assertion passed for every
        // trivially-broken implementation.
        //
        // Skip (not fail) if the host truly has no IPv6-bound adapter so CI
        // runners without IPv6 don't redden the suite.
        use windows::Win32::NetworkManagement::IpHelper::{
            GAA_FLAG_INCLUDE_PREFIX, GetAdaptersAddresses, IP_ADAPTER_ADDRESSES_LH,
        };
        use windows::Win32::Networking::WinSock::AF_INET6;

        const ERROR_BUFFER_OVERFLOW: u32 = 111;

        let if_index = unsafe {
            let mut size: u32 = 0;
            let rc = GetAdaptersAddresses(
                AF_INET6.0 as u32,
                GAA_FLAG_INCLUDE_PREFIX,
                None,
                None,
                &mut size,
            );
            if rc != ERROR_BUFFER_OVERFLOW || size == 0 {
                eprintln!(
                    "skipping positive-path test: no IPv6 adapter on this host (rc={}, size={})",
                    rc, size
                );
                return;
            }

            let u64_elems = (size as usize + 7) / 8;
            let mut buffer: Vec<u64> = vec![0u64; u64_elems];
            let adapter_addresses = buffer.as_mut_ptr() as *mut IP_ADAPTER_ADDRESSES_LH;
            let rc = GetAdaptersAddresses(
                AF_INET6.0 as u32,
                GAA_FLAG_INCLUDE_PREFIX,
                None,
                Some(adapter_addresses),
                &mut size,
            );
            if rc != 0 {
                eprintln!(
                    "skipping positive-path test: second GAA call failed rc={}",
                    rc
                );
                return;
            }

            let first = &*adapter_addresses;
            // Prefer Ipv6IfIndex when populated; fall back to IfIndex.
            if first.Ipv6IfIndex != 0 {
                first.Ipv6IfIndex
            } else {
                first.Anonymous1.Anonymous.IfIndex
            }
        };

        assert_eq!(
            has_ipv6_binding_native(if_index),
            Some(true),
            "expected Some(true) for a known-IPv6-bound adapter (if_index={})",
            if_index
        );
    }
}
