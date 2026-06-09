//! IPv6 leak-prevention crash recovery
//!
//! While connected, SwiftTunnel installs a WinpkFilter static drop filter that
//! blocks outbound public IPv6/NAT64. The marker file records that we did so
//! (and which method we used) so a startup recovery pass can clean up after a
//! crash without guessing at adapter state. Old installations used different
//! methods (`Disable-NetAdapterBinding ms_tcpip6` and a Windows Firewall rule);
//! we keep the deserialization shape backwards-compatible so an upgrade across
//! those boundaries still recovers cleanly.

pub const IPV6_BLOCK_RULE_NAME: &str = "SwiftTunnel-Block-IPv6-Outbound";
pub const IPV6_BLOCK_REMOTE_IPS: &str = "2000::/3,64:ff9b::/96";

use serde::{Deserialize, Serialize};
use std::fs;
use std::path::PathBuf;

#[cfg(target_os = "windows")]
use ndisapi::StaticFilterTable;
#[cfg(any(test, target_os = "windows"))]
use ndisapi::{
    DataLinkLayerFilter, DirectionFlags, FILTER_PACKET_DROP, FilterLayerFlags, IP_SUBNET_V6_TYPE,
    IPV6, IpAddressV6, IpAddressV6Union, IpSubnetV6, IpV6Filter, IpV6FilterFlags,
    NetworkLayerFilter, NetworkLayerFilterUnion, StaticFilter, TransportLayerFilter,
};
#[cfg(any(test, target_os = "windows"))]
use windows::Win32::Networking::WinSock::{IN6_ADDR, IN6_ADDR_0};

/// Outbound IPv6 destinations dropped while the IPv4-only tunnel is active:
/// global unicast (2000::/3), the NAT64 well-known prefix (64:ff9b::/96,
/// RFC 6052), and the NAT64 local-use prefix (64:ff9b:1::/48, RFC 8215).
/// Network-specific NAT64 prefixes carved out of provider global unicast
/// space already fall inside 2000::/3.
#[cfg(any(test, target_os = "windows"))]
const IPV6_PUBLIC_NETWORK: [u8; 16] = [0x20, 0x00, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
#[cfg(any(test, target_os = "windows"))]
const IPV6_PUBLIC_MASK: [u8; 16] = [0xe0, 0x00, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
#[cfg(any(test, target_os = "windows"))]
const IPV6_NAT64_NETWORK: [u8; 16] = [0x00, 0x64, 0xff, 0x9b, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
#[cfg(any(test, target_os = "windows"))]
const IPV6_NAT64_MASK: [u8; 16] = [
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0, 0, 0, 0,
];
#[cfg(any(test, target_os = "windows"))]
const IPV6_NAT64_LOCAL_NETWORK: [u8; 16] = [
    0x00, 0x64, 0xff, 0x9b, 0x00, 0x01, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
];
#[cfg(any(test, target_os = "windows"))]
const IPV6_NAT64_LOCAL_MASK: [u8; 16] = [
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
];

/// The exact destination subnets SwiftTunnel's IPv6 drop filters use. Filter
/// ownership during merge/cleanup is decided by matching these subnets plus
/// the full drop-filter shape — never by adapter handle (stale across
/// reboots) or table position.
#[cfg(any(test, target_os = "windows"))]
const SWIFTTUNNEL_IPV6_BLOCK_SUBNETS: [([u8; 16], [u8; 16]); 3] = [
    (IPV6_PUBLIC_NETWORK, IPV6_PUBLIC_MASK),
    (IPV6_NAT64_NETWORK, IPV6_NAT64_MASK),
    (IPV6_NAT64_LOCAL_NETWORK, IPV6_NAT64_LOCAL_MASK),
];

/// Generous upper bound for reading/merging the driver's static filter table.
/// SwiftTunnel installs 3 entries; anything near this limit means another
/// WinpkFilter consumer filled the table.
#[cfg(target_os = "windows")]
const STATIC_FILTER_TABLE_CAPACITY: usize = 256;

#[cfg(any(test, target_os = "windows"))]
fn in6_addr(bytes: [u8; 16]) -> IN6_ADDR {
    IN6_ADDR {
        u: IN6_ADDR_0 { Byte: bytes },
    }
}

#[cfg(any(test, target_os = "windows"))]
fn ipv6_subnet_filter_address(network: [u8; 16], mask: [u8; 16]) -> IpAddressV6 {
    IpAddressV6::new(
        IP_SUBNET_V6_TYPE,
        IpAddressV6Union {
            ip_subnet: IpSubnetV6::new(in6_addr(network), in6_addr(mask)),
        },
    )
}

#[cfg(any(test, target_os = "windows"))]
fn build_ipv6_block_filter(adapter_handle: u64, network: [u8; 16], mask: [u8; 16]) -> StaticFilter {
    StaticFilter::new(
        adapter_handle,
        DirectionFlags::PACKET_FLAG_ON_SEND,
        FILTER_PACKET_DROP,
        FilterLayerFlags::NETWORK_LAYER_VALID,
        DataLinkLayerFilter::default(),
        NetworkLayerFilter::new(
            IPV6,
            NetworkLayerFilterUnion {
                ipv6: IpV6Filter::new(
                    IpV6FilterFlags::IP_V6_FILTER_DEST_ADDRESS,
                    IpAddressV6::default(),
                    ipv6_subnet_filter_address(network, mask),
                    0,
                ),
            },
        ),
        TransportLayerFilter::default(),
    )
}

/// SwiftTunnel's outbound IPv6 drop filters for the selected adapter.
#[cfg(any(test, target_os = "windows"))]
pub(crate) fn swifttunnel_ipv6_block_filters(adapter_handle: u64) -> [StaticFilter; 3] {
    SWIFTTUNNEL_IPV6_BLOCK_SUBNETS
        .map(|(network, mask)| build_ipv6_block_filter(adapter_handle, network, mask))
}

/// Whether a static filter entry is one of SwiftTunnel's IPv6 drop filters.
///
/// Matches the full filter shape (outbound, drop, network-layer-only, IPv6
/// destination subnet equal to one of [`SWIFTTUNNEL_IPV6_BLOCK_SUBNETS`]).
/// A filter that differs in any of those fields belongs to someone else and
/// must be preserved.
#[cfg(any(test, target_os = "windows"))]
pub(crate) fn is_swifttunnel_ipv6_block_filter(filter: &StaticFilter) -> bool {
    // Copy fields out of the packed struct; taking references would be UB.
    let direction_flags = filter.direction_flags;
    let filter_action = filter.filter_action;
    let valid_fields = filter.valid_fields;
    if direction_flags != DirectionFlags::PACKET_FLAG_ON_SEND
        || filter_action != FILTER_PACKET_DROP
        || valid_fields != FilterLayerFlags::NETWORK_LAYER_VALID
    {
        return false;
    }

    let network_filter = filter.network_filter;
    if network_filter.union_selector != IPV6 {
        return false;
    }

    // SAFETY: union_selector == IPV6 guarantees the ipv6 arm is the live one.
    let ipv6_filter = unsafe { network_filter.network_layer.ipv6 };
    let ipv6_valid_fields = ipv6_filter.valid_fields;
    if ipv6_valid_fields != IpV6FilterFlags::IP_V6_FILTER_DEST_ADDRESS {
        return false;
    }

    let dest_address = ipv6_filter.dest_address;
    if dest_address.address_type != IP_SUBNET_V6_TYPE {
        return false;
    }

    // SAFETY: address_type == IP_SUBNET_V6_TYPE guarantees the subnet arm.
    let subnet = unsafe { dest_address.address.ip_subnet };
    let network = unsafe { subnet.ip.u.Byte };
    let mask = unsafe { subnet.ip_mask.u.Byte };
    SWIFTTUNNEL_IPV6_BLOCK_SUBNETS
        .iter()
        .any(|(n, m)| network == *n && mask == *m)
}

/// Split a filter table into (entries to keep, count of SwiftTunnel IPv6
/// drop entries removed).
#[cfg(any(test, target_os = "windows"))]
pub(crate) fn entries_without_swifttunnel_ipv6_block(
    entries: Vec<StaticFilter>,
) -> (Vec<StaticFilter>, usize) {
    let original = entries.len();
    let kept: Vec<StaticFilter> = entries
        .into_iter()
        .filter(|filter| !is_swifttunnel_ipv6_block_filter(filter))
        .collect();
    let removed = original - kept.len();
    (kept, removed)
}

/// Merge SwiftTunnel's IPv6 drop filters into an existing table snapshot,
/// replacing any stale SwiftTunnel entries (e.g. from a previous session)
/// while preserving everything else.
#[cfg(any(test, target_os = "windows"))]
pub(crate) fn merged_ipv6_block_entries(
    existing: Vec<StaticFilter>,
    adapter_handle: u64,
) -> Vec<StaticFilter> {
    let (mut entries, _) = entries_without_swifttunnel_ipv6_block(existing);
    entries.extend(swifttunnel_ipv6_block_filters(adapter_handle));
    entries
}

/// Marker file name stored in %LOCALAPPDATA%/SwiftTunnel/
const IPV6_MARKER_FILE: &str = "ipv6_disabled.marker";

/// Serializes tests (across modules) that touch the shared on-disk IPv6
/// marker file; without it, parallel test execution makes marker tests delete
/// each other's state and flake.
#[cfg(test)]
pub(crate) static IPV6_MARKER_TEST_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

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
    /// Intermediate method: a Windows Firewall outbound block rule named
    /// [`IPV6_BLOCK_RULE_NAME`] that drops public IPv6/NAT64 traffic. No
    /// adapter rebind, no WMI involvement.
    FirewallRule,
    /// Current method: WinpkFilter static filters drop outbound public
    /// IPv6/NAT64 traffic on the selected adapter. No Windows Firewall policy
    /// writes and no adapter rebind.
    WinpkFilterStaticFilter,
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

    pub(crate) fn for_winpkfilter_static_filter(adapter_name: String) -> Self {
        Self {
            adapter_name,
            originally_enabled: None,
            method: DisableMethod::WinpkFilterStaticFilter,
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
            DisableMethod::WinpkFilterStaticFilter => {
                "Write-Host 'WinpkFilter IPv6 filters are restored natively'".to_string()
            }
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
/// Kept for legacy callers/markers so crash recovery can still run
/// `netsh advfirewall firewall delete rule` to clean up.
pub fn write_ipv6_marker_firewall(adapter_name: &str) {
    let marker = Ipv6Marker::for_firewall_rule(adapter_name.trim().to_string());
    write_marker(&marker);
}

/// Write a marker indicating WinpkFilter static filters were used to block
/// IPv6. Used by the modern disable path so a crash-recovery pass can clear
/// the driver filter table.
pub fn write_ipv6_marker_winpkfilter(adapter_name: &str) {
    let marker = Ipv6Marker::for_winpkfilter_static_filter(adapter_name.trim().to_string());
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

fn restore_firewall_rule_marker(adapter_name: &str) -> bool {
    let name_arg = format!("name={IPV6_BLOCK_RULE_NAME}");

    let delete_output = crate::hidden_command("netsh")
        .args([
            "advfirewall",
            "firewall",
            "delete",
            "rule",
            name_arg.as_str(),
        ])
        .output();
    let delete_output = match delete_output {
        Ok(output) => output,
        Err(e) => {
            log::error!("Failed to run netsh for IPv6 firewall restore: {}", e);
            return false;
        }
    };

    let show_output = crate::hidden_command("netsh")
        .args(["advfirewall", "firewall", "show", "rule", name_arg.as_str()])
        .output();
    let show_output = match show_output {
        Ok(output) => output,
        Err(e) => {
            log::error!("Failed to verify IPv6 firewall restore with netsh: {}", e);
            return false;
        }
    };

    if show_output.status.success() {
        log::warn!(
            "IPv6 block firewall rule still exists after delete attempt for adapter {}",
            adapter_name
        );
        return false;
    }

    let show_text = format!(
        "{}{}",
        String::from_utf8_lossy(&show_output.stdout),
        String::from_utf8_lossy(&show_output.stderr)
    );

    if !delete_output.status.success() && !show_text.contains("No rules match") {
        log::warn!(
            "Could not verify IPv6 block firewall rule removal for adapter {}: {}",
            adapter_name,
            show_text.trim()
        );
        return false;
    }

    log::info!(
        "IPv6 firewall block rule removed successfully for adapter: {}",
        adapter_name
    );
    true
}

/// Read the driver's current static filter table as owned entries.
#[cfg(target_os = "windows")]
fn read_static_filter_entries(driver: &ndisapi::Ndisapi) -> Result<Vec<StaticFilter>, String> {
    let size = driver
        .get_packet_filter_table_size()
        .map_err(|e| format!("Failed to query WinpkFilter static filter table size: {e}"))?;
    if size == 0 {
        return Ok(Vec::new());
    }
    if size > STATIC_FILTER_TABLE_CAPACITY {
        return Err(format!(
            "WinpkFilter static filter table has {size} entries, more than the supported {STATIC_FILTER_TABLE_CAPACITY}"
        ));
    }

    // Boxed: the fixed-capacity table is ~48KB, too big to keep on the stack.
    let mut table = Box::new(StaticFilterTable::<STATIC_FILTER_TABLE_CAPACITY>::new());
    driver
        .get_packet_filter_table(table.as_mut())
        .map_err(|e| format!("Failed to read WinpkFilter static filter table: {e}"))?;

    let count = (table.table_size as usize).min(STATIC_FILTER_TABLE_CAPACITY);
    let base = std::ptr::addr_of!(table.static_filters).cast::<StaticFilter>();
    let mut entries = Vec::with_capacity(count);
    for i in 0..count {
        // SAFETY: i < count <= capacity; unaligned read because the table is
        // repr(C, packed).
        entries.push(unsafe { base.add(i).read_unaligned() });
    }
    Ok(entries)
}

/// Replace the driver's static filter table with exactly `entries`.
#[cfg(target_os = "windows")]
fn set_static_filter_entries(
    driver: &ndisapi::Ndisapi,
    entries: &[StaticFilter],
) -> Result<(), String> {
    if entries.len() > STATIC_FILTER_TABLE_CAPACITY {
        return Err(format!(
            "Refusing to write {} WinpkFilter static filter entries, more than the supported {STATIC_FILTER_TABLE_CAPACITY}",
            entries.len()
        ));
    }

    let mut table = Box::new(StaticFilterTable::<STATIC_FILTER_TABLE_CAPACITY>::new());
    table.table_size = entries.len() as u32;
    let base = std::ptr::addr_of_mut!(table.static_filters).cast::<StaticFilter>();
    for (i, entry) in entries.iter().enumerate() {
        // SAFETY: i < entries.len() <= capacity; unaligned write because the
        // table is repr(C, packed).
        unsafe { base.add(i).write_unaligned(*entry) };
    }
    driver
        .set_packet_filter_table(table.as_ref())
        .map_err(|e| format!("Failed to write WinpkFilter static filter table: {e}"))
}

/// Install SwiftTunnel's IPv6 drop filters, preserving any static filter
/// entries that are not SwiftTunnel's (another WinpkFilter consumer or a
/// future SwiftTunnel component may own them).
#[cfg(target_os = "windows")]
pub(crate) fn install_winpkfilter_ipv6_block_filters(
    driver: &ndisapi::Ndisapi,
    adapter_handle: u64,
) -> Result<(), String> {
    let existing = read_static_filter_entries(driver)?;
    let merged = merged_ipv6_block_entries(existing, adapter_handle);
    let preserved = merged.len() - SWIFTTUNNEL_IPV6_BLOCK_SUBNETS.len();
    if preserved > 0 {
        log::info!(
            "Preserving {preserved} existing WinpkFilter static filter entries alongside the SwiftTunnel IPv6 block"
        );
    }
    set_static_filter_entries(driver, &merged)
}

/// Remove SwiftTunnel's IPv6 drop filters from the driver's static filter
/// table, preserving entries owned by anyone else.
///
/// Cleanup must never leave IPv6 blocked: if the table cannot be read, this
/// falls back to a full table reset (the documented crash-recovery posture is
/// that recovery may over-clean) rather than leaving drop filters installed.
#[cfg(target_os = "windows")]
pub fn remove_winpkfilter_ipv6_block_filters() -> Result<(), String> {
    let driver = ndisapi::Ndisapi::new("NDISRD")
        .map_err(|e| format!("Failed to open WinpkFilter driver: {e}"))?;

    let entries = match read_static_filter_entries(&driver) {
        Ok(entries) => entries,
        Err(e) => {
            log::warn!(
                "Could not read WinpkFilter static filter table ({e}); falling back to a full reset"
            );
            return driver
                .reset_packet_filter_table()
                .map_err(|e| format!("Failed to reset WinpkFilter static filter table: {e}"));
        }
    };

    let (remaining, removed) = entries_without_swifttunnel_ipv6_block(entries);
    if removed == 0 {
        return Ok(());
    }
    if remaining.is_empty() {
        return driver
            .reset_packet_filter_table()
            .map_err(|e| format!("Failed to reset WinpkFilter static filter table: {e}"));
    }
    set_static_filter_entries(&driver, &remaining)
}

#[cfg(not(target_os = "windows"))]
pub fn remove_winpkfilter_ipv6_block_filters() -> Result<(), String> {
    Err("WinpkFilter IPv6 filter cleanup is only available on Windows.".to_string())
}

fn restore_winpkfilter_static_filter_marker(adapter_name: &str) -> bool {
    match remove_winpkfilter_ipv6_block_filters() {
        Ok(()) => {
            log::info!(
                "WinpkFilter IPv6 block filters removed successfully for adapter: {}",
                adapter_name
            );
            true
        }
        Err(e) => {
            log::warn!(
                "Failed to remove WinpkFilter IPv6 block filters for adapter {}: {}",
                adapter_name,
                e
            );
            false
        }
    }
}

fn restore_ipv6_for_marker(marker: &Ipv6Marker) -> bool {
    if marker.method() == &DisableMethod::FirewallRule {
        return restore_firewall_rule_marker(marker.adapter_name());
    }
    if marker.method() == &DisableMethod::WinpkFilterStaticFilter {
        return restore_winpkfilter_static_filter_marker(marker.adapter_name());
    }

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
        let _guard = IPV6_MARKER_TEST_LOCK
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
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

    fn dest_subnet(filter: &StaticFilter) -> ([u8; 16], [u8; 16]) {
        let network_filter = filter.network_filter;
        let union_selector = network_filter.union_selector;
        assert_eq!(union_selector, IPV6);
        let ipv6_filter = unsafe { network_filter.network_layer.ipv6 };
        let dest_address = ipv6_filter.dest_address;
        let address_type = dest_address.address_type;
        assert_eq!(address_type, IP_SUBNET_V6_TYPE);
        let subnet = unsafe { dest_address.address.ip_subnet };
        (unsafe { subnet.ip.u.Byte }, unsafe {
            subnet.ip_mask.u.Byte
        })
    }

    fn foreign_ipv4_drop_filter() -> StaticFilter {
        StaticFilter::new(
            0xAAAA,
            DirectionFlags::PACKET_FLAG_ON_SEND,
            FILTER_PACKET_DROP,
            FilterLayerFlags::NETWORK_LAYER_VALID,
            DataLinkLayerFilter::default(),
            NetworkLayerFilter::new(ndisapi::IPV4, NetworkLayerFilterUnion::default()),
            TransportLayerFilter::default(),
        )
    }

    /// Identical shape to SwiftTunnel's drop filters but for a ULA subnet
    /// (fc00::/7) SwiftTunnel never blocks — must never be claimed as ours.
    fn foreign_ipv6_ula_drop_filter() -> StaticFilter {
        let ula_network: [u8; 16] = [0xfc, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
        let ula_mask: [u8; 16] = [0xfe, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
        build_ipv6_block_filter(0xBBBB, ula_network, ula_mask)
    }

    #[test]
    fn test_swifttunnel_ipv6_block_filters_cover_public_and_nat64_prefixes() {
        let handle = 0x1234u64;
        let filters = swifttunnel_ipv6_block_filters(handle);

        assert_eq!(filters.len(), 3);
        let mut subnets = Vec::new();
        for filter in &filters {
            let adapter_handle = filter.adapter_handle;
            let direction_flags = filter.direction_flags;
            let filter_action = filter.filter_action;
            let valid_fields = filter.valid_fields;
            assert_eq!(adapter_handle, handle);
            assert_eq!(direction_flags, DirectionFlags::PACKET_FLAG_ON_SEND);
            assert_eq!(filter_action, FILTER_PACKET_DROP);
            assert_eq!(valid_fields, FilterLayerFlags::NETWORK_LAYER_VALID);
            let network_filter = filter.network_filter;
            let ipv6_filter = unsafe { network_filter.network_layer.ipv6 };
            let ipv6_valid_fields = ipv6_filter.valid_fields;
            assert_eq!(
                ipv6_valid_fields,
                IpV6FilterFlags::IP_V6_FILTER_DEST_ADDRESS
            );
            subnets.push(dest_subnet(filter));
            assert!(is_swifttunnel_ipv6_block_filter(filter));
        }

        assert_eq!(subnets.len(), SWIFTTUNNEL_IPV6_BLOCK_SUBNETS.len());
        for expected in SWIFTTUNNEL_IPV6_BLOCK_SUBNETS {
            assert!(subnets.contains(&expected), "missing subnet {expected:?}");
        }
    }

    #[test]
    fn test_is_swifttunnel_ipv6_block_filter_rejects_similar_foreign_filters() {
        // Same drop shape, different subnet: NOT ours.
        assert!(!is_swifttunnel_ipv6_block_filter(
            &foreign_ipv6_ula_drop_filter()
        ));
        // IPv4 drop filter: NOT ours.
        assert!(!is_swifttunnel_ipv6_block_filter(
            &foreign_ipv4_drop_filter()
        ));
        // Zeroed/default entry: NOT ours.
        assert!(!is_swifttunnel_ipv6_block_filter(&StaticFilter::default()));

        // Same subnet but inbound direction: NOT ours.
        let mut inbound = swifttunnel_ipv6_block_filters(0x1234)[0];
        inbound.direction_flags = DirectionFlags::PACKET_FLAG_ON_RECEIVE;
        assert!(!is_swifttunnel_ipv6_block_filter(&inbound));
    }

    #[test]
    fn test_merged_ipv6_block_entries_preserve_foreign_and_replace_stale_ours() {
        let stale_ours = swifttunnel_ipv6_block_filters(0x9999)[0];
        let existing = vec![
            foreign_ipv4_drop_filter(),
            stale_ours,
            foreign_ipv6_ula_drop_filter(),
        ];

        let merged = merged_ipv6_block_entries(existing, 0x1234);

        // 2 foreign preserved + 3 ours; the stale entry (old adapter handle)
        // was replaced, not duplicated.
        assert_eq!(merged.len(), 5);
        let ours: Vec<&StaticFilter> = merged
            .iter()
            .filter(|f| is_swifttunnel_ipv6_block_filter(f))
            .collect();
        assert_eq!(ours.len(), 3);
        for filter in ours {
            let adapter_handle = filter.adapter_handle;
            assert_eq!(adapter_handle, 0x1234);
        }
        let foreign_handles: Vec<u64> = merged
            .iter()
            .filter(|f| !is_swifttunnel_ipv6_block_filter(f))
            .map(|f| f.adapter_handle)
            .collect();
        assert_eq!(foreign_handles, vec![0xAAAA, 0xBBBB]);
    }

    #[test]
    fn test_entries_without_swifttunnel_ipv6_block_removes_only_ours() {
        let mut entries = vec![foreign_ipv4_drop_filter(), foreign_ipv6_ula_drop_filter()];
        entries.extend(swifttunnel_ipv6_block_filters(0x1234));

        let (kept, removed) = entries_without_swifttunnel_ipv6_block(entries);

        assert_eq!(removed, 3);
        assert_eq!(kept.len(), 2);
        assert!(kept.iter().all(|f| !is_swifttunnel_ipv6_block_filter(f)));
    }

    #[test]
    fn test_entries_without_swifttunnel_ipv6_block_keeps_foreign_only_table_intact() {
        let entries = vec![foreign_ipv4_drop_filter(), foreign_ipv6_ula_drop_filter()];

        let (kept, removed) = entries_without_swifttunnel_ipv6_block(entries);

        assert_eq!(removed, 0);
        assert_eq!(kept.len(), 2);
    }

    /// Real-driver smoke test for the install → merge → remove cycle.
    /// Mutates the machine-global WinpkFilter static filter table, so it is
    /// manual-run only (`cargo test -- --ignored`) on a box with the NDISRD
    /// driver, e.g. the split tunnel testbench. All driver operations happen
    /// before the assertions so a failing assertion cannot leave the IPv6
    /// drop filters installed.
    #[cfg(target_os = "windows")]
    #[test]
    #[ignore]
    fn driver_smoke_install_and_remove_ipv6_block_filters() {
        let driver = ndisapi::Ndisapi::new("NDISRD").expect("WinpkFilter driver not available");
        let adapters = driver
            .get_tcpip_bound_adapters_info()
            .expect("failed to enumerate adapters");
        let adapter = adapters.first().expect("no TCP/IP-bound adapters");
        let adapter_handle = adapter.get_handle().0 as usize as u64;

        let before = read_static_filter_entries(&driver).expect("read before install");
        let install_result = install_winpkfilter_ipv6_block_filters(&driver, adapter_handle);
        let with_block = read_static_filter_entries(&driver);
        let remove_result = remove_winpkfilter_ipv6_block_filters();
        let after = read_static_filter_entries(&driver);

        install_result.expect("install failed");
        let with_block = with_block.expect("read after install");
        remove_result.expect("remove failed");
        let after = after.expect("read after remove");

        let (foreign_before, _) = entries_without_swifttunnel_ipv6_block(before);
        let ours_installed = with_block
            .iter()
            .filter(|f| is_swifttunnel_ipv6_block_filter(f))
            .count();
        assert_eq!(ours_installed, 3, "expected all 3 IPv6 drop filters");
        assert_eq!(
            with_block.len(),
            foreign_before.len() + 3,
            "install must preserve foreign entries"
        );
        let ours_after = after
            .iter()
            .filter(|f| is_swifttunnel_ipv6_block_filter(f))
            .count();
        assert_eq!(ours_after, 0, "remove must clear all SwiftTunnel entries");
        assert_eq!(
            after.len(),
            foreign_before.len(),
            "remove must keep foreign entries"
        );
    }

    #[test]
    fn test_winpkfilter_static_filter_marker_round_trips() {
        let marker = Ipv6Marker::for_winpkfilter_static_filter("Ethernet".to_string());
        let payload = serde_json::to_vec(&marker).unwrap();
        let decoded: Ipv6Marker = serde_json::from_slice(&payload).unwrap();

        assert_eq!(decoded.method(), &DisableMethod::WinpkFilterStaticFilter);
        assert_eq!(decoded.adapter_name(), "Ethernet");
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
        assert!(
            marker
                .restore_command()
                .contains("Enable-NetAdapterBinding")
        );
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
