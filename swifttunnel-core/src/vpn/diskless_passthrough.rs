//! Kernel pass-through for the system disk traffic of diskless cafe PCs.
//!
//! Internet cafes (CCBoot/gcafe/iSCSI boot) run Windows from a NETWORK image:
//! every disk read is a LAN packet on the same NIC SwiftTunnel intercepts.
//! Putting that adapter into tunnel mode routes the machine's DISK I/O through
//! our user-mode packet pump — any stall (startup, contention, load) starves
//! the system disk, Windows can't page code back in, and the whole PC freezes.
//! Users reported exactly that: "it freezes the moment I start connecting".
//!
//! The fix never lets disk packets reach user mode at all: WinpkFilter's
//! static filter table is evaluated IN KERNEL before packets are queued to the
//! app, so `FILTER_PACKET_PASS` entries for the boot server's flows make the
//! driver hand them straight through. The disk endpoints are discovered from
//! the IP-helper tables: the boot/disk sessions are owned by the `System`
//! process (PID 4) and exist from boot, so a connect-time snapshot is stable
//! for the whole session.
//!
//! Game traffic can never match these filters: Roblox's flows are owned by
//! Roblox processes, not PID 4, and TCP/UDP ports are exclusive per protocol —
//! if System owns one, a game can't.

#[cfg(any(test, target_os = "windows"))]
use ndisapi::{
    DataLinkLayerFilter, DirectionFlags, FILTER_PACKET_PASS, FilterLayerFlags, IP_SUBNET_V4_TYPE,
    IPV4, IpAddressV4, IpAddressV4Union, IpSubnetV4, IpV4Filter, IpV4FilterFlags,
    NetworkLayerFilter, NetworkLayerFilterUnion, PortRange, StaticFilter, TCPUDP, TcpUdpFilter,
    TcpUdpFilterFlags, TransportLayerFilter, TransportLayerFilterUnion,
};
#[cfg(any(test, target_os = "windows"))]
use std::net::Ipv4Addr;
#[cfg(any(test, target_os = "windows"))]
use windows::Win32::Networking::WinSock::{IN_ADDR, IN_ADDR_0};

/// PID of the Windows kernel ("System") process that owns iSCSI/CCBoot/SMB
/// boot sessions.
#[cfg(any(test, target_os = "windows"))]
const SYSTEM_PID: u32 = 4;

/// Caps keep the static filter table comfortably inside its capacity (256,
/// shared with the 3 IPv6 block entries). A diskless client typically has 1-3
/// disk sessions. Exceeding a cap must refuse capture, rather than guessing
/// which System flow might be the boot disk.
#[cfg(any(test, target_os = "windows"))]
const MAX_TCP_ENDPOINTS: usize = 32;
#[cfg(any(test, target_os = "windows"))]
const MAX_UDP_PORTS: usize = 24;

const IPPROTO_TCP: u8 = 6;
const IPPROTO_UDP: u8 = 17;

/// The exact filters installed for this session, recorded so removal on
/// disconnect only deletes byte-identical entries (anything else in the table
/// belongs to someone else and is preserved).
#[cfg(target_os = "windows")]
static INSTALLED_FILTERS: std::sync::Mutex<Vec<StaticFilter>> = std::sync::Mutex::new(Vec::new());

#[cfg(any(test, target_os = "windows"))]
fn in_addr(ip: Ipv4Addr) -> IN_ADDR {
    IN_ADDR {
        S_un: IN_ADDR_0 {
            S_addr: u32::from_ne_bytes(ip.octets()),
        },
    }
}

/// Exact-host (/32) IPv4 match.
#[cfg(any(test, target_os = "windows"))]
fn host_address(ip: Ipv4Addr) -> IpAddressV4 {
    IpAddressV4::new(
        IP_SUBNET_V4_TYPE,
        IpAddressV4Union {
            ip_subnet: IpSubnetV4::new(in_addr(ip), in_addr(Ipv4Addr::new(255, 255, 255, 255))),
        },
    )
}

#[cfg(any(test, target_os = "windows"))]
fn single_port(port: u16) -> PortRange {
    PortRange::new(port, port)
}

/// PASS filters (both directions) for one System-owned TCP session to the
/// boot/disk server at `ip:port`.
#[cfg(any(test, target_os = "windows"))]
fn tcp_endpoint_pass_filters(adapter_handle: u64, ip: Ipv4Addr, port: u16) -> [StaticFilter; 2] {
    let outgoing = StaticFilter::new(
        adapter_handle,
        DirectionFlags::PACKET_FLAG_ON_SEND,
        FILTER_PACKET_PASS,
        FilterLayerFlags::NETWORK_LAYER_VALID | FilterLayerFlags::TRANSPORT_LAYER_VALID,
        DataLinkLayerFilter::default(),
        NetworkLayerFilter::new(
            IPV4,
            NetworkLayerFilterUnion {
                ipv4: IpV4Filter::new(
                    IpV4FilterFlags::IP_V4_FILTER_DEST_ADDRESS
                        | IpV4FilterFlags::IP_V4_FILTER_PROTOCOL,
                    IpAddressV4::default(),
                    host_address(ip),
                    IPPROTO_TCP,
                ),
            },
        ),
        TransportLayerFilter::new(
            TCPUDP,
            TransportLayerFilterUnion {
                tcp_udp: TcpUdpFilter::new(
                    TcpUdpFilterFlags::TCPUDP_DEST_PORT,
                    PortRange::default(),
                    single_port(port),
                    0,
                ),
            },
        ),
    );
    let incoming = StaticFilter::new(
        adapter_handle,
        DirectionFlags::PACKET_FLAG_ON_RECEIVE,
        FILTER_PACKET_PASS,
        FilterLayerFlags::NETWORK_LAYER_VALID | FilterLayerFlags::TRANSPORT_LAYER_VALID,
        DataLinkLayerFilter::default(),
        NetworkLayerFilter::new(
            IPV4,
            NetworkLayerFilterUnion {
                ipv4: IpV4Filter::new(
                    IpV4FilterFlags::IP_V4_FILTER_SRC_ADDRESS
                        | IpV4FilterFlags::IP_V4_FILTER_PROTOCOL,
                    host_address(ip),
                    IpAddressV4::default(),
                    IPPROTO_TCP,
                ),
            },
        ),
        TransportLayerFilter::new(
            TCPUDP,
            TransportLayerFilterUnion {
                tcp_udp: TcpUdpFilter::new(
                    TcpUdpFilterFlags::TCPUDP_SRC_PORT,
                    single_port(port),
                    PortRange::default(),
                    0,
                ),
            },
        ),
    );
    [outgoing, incoming]
}

/// PASS filters (both directions) for one System-owned UDP port (CCBoot-style
/// disk protocols ride UDP; the UDP table only exposes the local port).
#[cfg(any(test, target_os = "windows"))]
fn udp_port_pass_filters(adapter_handle: u64, local_port: u16) -> [StaticFilter; 2] {
    let outgoing = StaticFilter::new(
        adapter_handle,
        DirectionFlags::PACKET_FLAG_ON_SEND,
        FILTER_PACKET_PASS,
        FilterLayerFlags::NETWORK_LAYER_VALID | FilterLayerFlags::TRANSPORT_LAYER_VALID,
        DataLinkLayerFilter::default(),
        NetworkLayerFilter::new(
            IPV4,
            NetworkLayerFilterUnion {
                ipv4: IpV4Filter::new(
                    IpV4FilterFlags::IP_V4_FILTER_PROTOCOL,
                    IpAddressV4::default(),
                    IpAddressV4::default(),
                    IPPROTO_UDP,
                ),
            },
        ),
        TransportLayerFilter::new(
            TCPUDP,
            TransportLayerFilterUnion {
                tcp_udp: TcpUdpFilter::new(
                    TcpUdpFilterFlags::TCPUDP_SRC_PORT,
                    single_port(local_port),
                    PortRange::default(),
                    0,
                ),
            },
        ),
    );
    let incoming = StaticFilter::new(
        adapter_handle,
        DirectionFlags::PACKET_FLAG_ON_RECEIVE,
        FILTER_PACKET_PASS,
        FilterLayerFlags::NETWORK_LAYER_VALID | FilterLayerFlags::TRANSPORT_LAYER_VALID,
        DataLinkLayerFilter::default(),
        NetworkLayerFilter::new(
            IPV4,
            NetworkLayerFilterUnion {
                ipv4: IpV4Filter::new(
                    IpV4FilterFlags::IP_V4_FILTER_PROTOCOL,
                    IpAddressV4::default(),
                    IpAddressV4::default(),
                    IPPROTO_UDP,
                ),
            },
        ),
        TransportLayerFilter::new(
            TCPUDP,
            TransportLayerFilterUnion {
                tcp_udp: TcpUdpFilter::new(
                    TcpUdpFilterFlags::TCPUDP_DEST_PORT,
                    PortRange::default(),
                    single_port(local_port),
                    0,
                ),
            },
        ),
    );
    [outgoing, incoming]
}

/// Byte-level equality for the packed filter struct (no padding surprises:
/// `STATIC_FILTER` is `repr(C, packed)` end to end).
#[cfg(any(test, target_os = "windows"))]
fn filters_equal(a: &StaticFilter, b: &StaticFilter) -> bool {
    let size = std::mem::size_of::<StaticFilter>();
    // SAFETY: both references point at `size` valid bytes; u8 has no alignment
    // or validity requirements.
    unsafe {
        std::slice::from_raw_parts((a as *const StaticFilter).cast::<u8>(), size)
            == std::slice::from_raw_parts((b as *const StaticFilter).cast::<u8>(), size)
    }
}

/// Deduplicate every endpoint or fail; truncation can omit the boot disk.
#[cfg(any(test, target_os = "windows"))]
fn dedup_with_limit<T: PartialEq + Copy>(items: Vec<T>, cap: usize) -> Result<Vec<T>, String> {
    let mut out = Vec::new();
    for item in items {
        if !out.contains(&item) {
            if out.len() == cap {
                return Err(format!(
                    "System flow protection needs more than {cap} unique entries"
                ));
            }
            out.push(item);
        }
    }
    Ok(out)
}

/// Refuse to intercept a network-booted PC when disk protection is unavailable.
/// Zero flows from a successful query remains valid for local VHD boots, which
/// share the storage detector with network-backed virtual disks.
pub(super) fn prepare_capture(
    diskless: bool,
    physical_name: Option<&str>,
    install: impl FnOnce(&str) -> Result<usize, String>,
) -> super::VpnResult<usize> {
    if !diskless {
        return Ok(0);
    }
    let result = physical_name
        .ok_or_else(|| "Network adapter name is unavailable".to_string())
        .and_then(install);
    result.map_err(|reason| {
        log::error!("Network disk protection failed before packet capture: {reason}");
        super::VpnError::NetworkDiskProtectionUnavailable
    })
}

/// Endpoints worth protecting: skip loopback/unspecified (not on the wire) and
/// multicast/broadcast destinations.
#[cfg(any(test, target_os = "windows"))]
fn is_protectable_remote(ip: Ipv4Addr) -> bool {
    !(ip.is_loopback() || ip.is_unspecified() || ip.is_multicast() || ip.is_broadcast())
}

/// Snapshot the System-owned (PID 4) IPv4 flows: established TCP remote
/// endpoints and bound UDP local ports.
#[cfg(target_os = "windows")]
fn collect_system_flows() -> Result<(Vec<(Ipv4Addr, u16)>, Vec<u16>), String> {
    use windows::Win32::NetworkManagement::IpHelper::*;
    let mut tcp_endpoints = Vec::new();
    let mut udp_ports = Vec::new();
    super::owner_table::read_owner_rows(
        |buffer, size| unsafe {
            GetExtendedTcpTable(buffer, size, false, 2, TCP_TABLE_OWNER_PID_ALL, 0)
        },
        |entry: MIB_TCPROW_OWNER_PID| {
            if entry.dwOwningPid == SYSTEM_PID && entry.dwState == 5 {
                let remote_ip = Ipv4Addr::from(entry.dwRemoteAddr.to_ne_bytes());
                let remote_port = u16::from_be(entry.dwRemotePort as u16);
                if is_protectable_remote(remote_ip) && remote_port != 0 {
                    tcp_endpoints.push((remote_ip, remote_port));
                }
            }
        },
    )
    .map_err(|code| format!("Could not read System TCP flows (Windows code {code})"))?;
    super::owner_table::read_owner_rows(
        |buffer, size| unsafe {
            GetExtendedUdpTable(buffer, size, false, 2, UDP_TABLE_OWNER_PID, 0)
        },
        |entry: MIB_UDPROW_OWNER_PID| {
            let local_port = u16::from_be(entry.dwLocalPort as u16);
            if entry.dwOwningPid == SYSTEM_PID && local_port != 0 {
                udp_ports.push(local_port);
            }
        },
    )
    .map_err(|code| format!("Could not read System UDP flows (Windows code {code})"))?;
    Ok((
        dedup_with_limit(tcp_endpoints, MAX_TCP_ENDPOINTS)?,
        dedup_with_limit(udp_ports, MAX_UDP_PORTS)?,
    ))
}

/// Build the full pass-filter set for this machine's System flows.
#[cfg(any(test, target_os = "windows"))]
fn build_pass_filters(
    adapter_handle: u64,
    tcp_endpoints: &[(Ipv4Addr, u16)],
    udp_ports: &[u16],
) -> Vec<StaticFilter> {
    let mut filters = Vec::with_capacity(tcp_endpoints.len() * 2 + udp_ports.len() * 2);
    for &(ip, port) in tcp_endpoints {
        filters.extend(tcp_endpoint_pass_filters(adapter_handle, ip, port));
    }
    for &port in udp_ports {
        filters.extend(udp_port_pass_filters(adapter_handle, port));
    }
    filters
}

/// Install kernel PASS filters for the System disk flows on `physical_name`.
/// Returns the number of filters installed. Never required for correctness of
/// tunneling — callers should log failures and continue.
#[cfg(target_os = "windows")]
pub(crate) fn install_for_adapter(physical_name: &str) -> Result<usize, String> {
    let driver = ndisapi::Ndisapi::new("NDISRD")
        .map_err(|e| format!("Failed to open WinpkFilter driver: {e}"))?;
    let adapters = driver
        .get_tcpip_bound_adapters_info()
        .map_err(|e| format!("Failed to enumerate WinpkFilter adapters: {e}"))?;
    let Some(adapter) = adapters
        .iter()
        .find(|adapter| adapter.get_name() == physical_name)
    else {
        return Err(format!(
            "WinpkFilter adapter '{physical_name}' was not found for diskless pass-through"
        ));
    };
    let adapter_handle = adapter.get_handle().0 as usize as u64;

    let (tcp_endpoints, udp_ports) = collect_system_flows()?;
    if tcp_endpoints.is_empty() && udp_ports.is_empty() {
        return Ok(0);
    }
    log::info!(
        "Diskless pass-through: protecting {} System TCP endpoint(s) and {} System UDP port(s) from interception",
        tcp_endpoints.len(),
        udp_ports.len()
    );

    let new_filters = build_pass_filters(adapter_handle, &tcp_endpoints, &udp_ports);

    let existing = super::ipv6_recovery::read_static_filter_entries(&driver)?;
    // Replace any byte-identical leftovers from a previous session, keep
    // everything else (IPv6 block entries, other consumers).
    let mut merged: Vec<StaticFilter> = existing
        .into_iter()
        .filter(|entry| !new_filters.iter().any(|ours| filters_equal(entry, ours)))
        .collect();
    merged.extend(new_filters.iter().copied());

    if merged.len() > super::ipv6_recovery::STATIC_FILTER_TABLE_CAPACITY {
        return Err(format!(
            "Static filter table would need {} entries (capacity {})",
            merged.len(),
            super::ipv6_recovery::STATIC_FILTER_TABLE_CAPACITY
        ));
    }

    super::ipv6_recovery::set_static_filter_entries(&driver, &merged)?;

    let count = new_filters.len();
    match INSTALLED_FILTERS.lock() {
        Ok(mut installed) => *installed = new_filters,
        Err(e) => log::warn!("Diskless pass-through bookkeeping lock poisoned: {e}"),
    }
    Ok(count)
}

/// Remove the filters recorded by [`install_for_adapter`], preserving every
/// other table entry. Safe to call when nothing was installed.
#[cfg(target_os = "windows")]
pub(crate) fn remove_installed() {
    let ours: Vec<StaticFilter> = match INSTALLED_FILTERS.lock() {
        Ok(mut installed) => std::mem::take(&mut *installed),
        Err(e) => {
            log::warn!("Diskless pass-through bookkeeping lock poisoned during cleanup: {e}");
            return;
        }
    };
    if ours.is_empty() {
        return;
    }

    let result = (|| -> Result<(), String> {
        let driver = ndisapi::Ndisapi::new("NDISRD")
            .map_err(|e| format!("Failed to open WinpkFilter driver: {e}"))?;
        let entries = super::ipv6_recovery::read_static_filter_entries(&driver)?;
        let remaining: Vec<StaticFilter> = entries
            .into_iter()
            .filter(|entry| !ours.iter().any(|filter| filters_equal(entry, filter)))
            .collect();
        if remaining.is_empty() {
            driver
                .reset_packet_filter_table()
                .map_err(|e| format!("Failed to reset WinpkFilter static filter table: {e}"))
        } else {
            super::ipv6_recovery::set_static_filter_entries(&driver, &remaining)
        }
    })();

    match result {
        Ok(()) => log::info!(
            "Diskless pass-through: removed {} kernel pass filter(s)",
            ours.len()
        ),
        Err(e) => log::warn!("Diskless pass-through cleanup failed (harmless after reboot): {e}"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn disk_protection_failure_stops_admission_without_changing_local_boots() {
        assert_eq!(
            prepare_capture(false, None, |_| panic!(
                "local boot must not query/install disk filters"
            ))
            .unwrap(),
            0
        );
        assert_eq!(
            prepare_capture(true, Some("adapter"), |name| {
                assert_eq!(name, "adapter");
                Ok(8)
            })
            .unwrap(),
            8
        );
        assert_eq!(
            prepare_capture(true, Some("adapter"), |_| Ok(0)).unwrap(),
            0,
            "a successful empty query is normal for local VHD boots"
        );
        assert!(matches!(
            prepare_capture(true, None, |_| panic!("no adapter, no native mutation")),
            Err(super::super::VpnError::NetworkDiskProtectionUnavailable)
        ));
        let error = prepare_capture(true, Some("adapter"), |_| {
            Err("owned failure: native code 123, network disk at test endpoint".into())
        })
        .unwrap_err();
        assert!(matches!(
            error,
            super::super::VpnError::NetworkDiskProtectionUnavailable
        ));
        assert_eq!(error.support_code(), "network_disk_protection_failed");
        let message = super::super::error_messages::user_friendly_error(&error);
        assert!(message.contains("network disk"));
        assert!(message.contains("didn't start"));
        assert!(!message.contains("native code"));
        assert!(!message.contains("test endpoint"));
    }

    #[test]
    fn endpoint_limits_refuse_incomplete_disk_protection() {
        let items = vec![(Ipv4Addr::new(10, 0, 0, 1), 3260u16); 5];
        assert_eq!(dedup_with_limit(items, 4).unwrap().len(), 1);

        let many: Vec<u16> = (1..100).collect();
        let capped = dedup_with_limit(many, 24);
        assert!(
            capped.is_err(),
            "omitting System flows can omit the boot disk"
        );
        assert_eq!(dedup_with_limit(vec![3, 2, 3, 1], 3).unwrap(), [3, 2, 1]);
        assert!(dedup_with_limit(Vec::<u16>::new(), 0).unwrap().is_empty());
        assert!(dedup_with_limit(vec![1], 0).is_err());
    }

    #[test]
    fn protectable_remote_excludes_non_wire_addresses() {
        assert!(is_protectable_remote(Ipv4Addr::new(192, 168, 1, 10)));
        assert!(is_protectable_remote(Ipv4Addr::new(10, 0, 0, 5)));
        assert!(!is_protectable_remote(Ipv4Addr::new(127, 0, 0, 1)));
        assert!(!is_protectable_remote(Ipv4Addr::new(0, 0, 0, 0)));
        assert!(!is_protectable_remote(Ipv4Addr::new(224, 0, 0, 1)));
        assert!(!is_protectable_remote(Ipv4Addr::new(255, 255, 255, 255)));
    }

    #[test]
    fn pass_filters_have_expected_shape() {
        let boot_server = Ipv4Addr::new(192, 168, 1, 2);
        let [out_f, in_f] = tcp_endpoint_pass_filters(7, boot_server, 3260);

        // Copy packed fields out before asserting.
        let (out_dir, out_action) = (out_f.direction_flags, out_f.filter_action);
        assert_eq!(out_dir, DirectionFlags::PACKET_FLAG_ON_SEND);
        assert_eq!(out_action, FILTER_PACKET_PASS);
        let (in_dir, in_action) = (in_f.direction_flags, in_f.filter_action);
        assert_eq!(in_dir, DirectionFlags::PACKET_FLAG_ON_RECEIVE);
        assert_eq!(in_action, FILTER_PACKET_PASS);

        let udp = udp_port_pass_filters(7, 4011);
        for filter in udp {
            let action = filter.filter_action;
            assert_eq!(action, FILTER_PACKET_PASS);
        }
    }

    #[test]
    fn filters_equal_is_exact() {
        let a = tcp_endpoint_pass_filters(7, Ipv4Addr::new(192, 168, 1, 2), 3260);
        let b = tcp_endpoint_pass_filters(7, Ipv4Addr::new(192, 168, 1, 2), 3260);
        let c = tcp_endpoint_pass_filters(7, Ipv4Addr::new(192, 168, 1, 3), 3260);
        assert!(filters_equal(&a[0], &b[0]));
        assert!(!filters_equal(&a[0], &c[0]));
        assert!(!filters_equal(&a[0], &a[1]));
    }

    #[test]
    fn build_pass_filters_two_per_flow() {
        let filters =
            build_pass_filters(7, &[(Ipv4Addr::new(192, 168, 1, 2), 3260)], &[4011, 1000]);
        assert_eq!(filters.len(), 6);
    }
}
