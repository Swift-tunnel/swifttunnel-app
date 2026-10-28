//! Diskless / network-booted PC detection.
//!
//! Internet cafes (very common in Vietnam: CCBoot, gcafe, iSCSI boot) run
//! Windows from a NETWORK image: the "system disk" is a virtual disk cached in
//! RAM and backed by a LAN boot server. On such machines the standby list IS
//! the operating system's disk cache — purging it (or flushing modified pages,
//! or trimming every process's working set) forces each subsequent page access
//! back over the LAN and the whole PC freezes. RAM cleaning must be a no-op
//! there.
//!
//! Detection inspects the system volume's storage descriptor: a network or
//! file-backed virtual bus type, or a vendor/product string naming a known
//! diskless product, marks the machine as diskless.

use std::sync::OnceLock;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum SystemStorage {
    Local,
    Diskless,
    Unknown,
}

/// True when Windows itself runs from a network/RAM-backed virtual disk.
/// Cached for the process lifetime — the system disk cannot change while
/// Windows is running.
pub fn system_is_diskless() -> bool {
    system_storage() == SystemStorage::Diskless
}

fn system_storage() -> SystemStorage {
    static STORAGE: OnceLock<SystemStorage> = OnceLock::new();
    *STORAGE.get_or_init(|| {
        let storage = detect();
        if storage == SystemStorage::Diskless {
            log::info!(
                "Network-booted (diskless) system detected; RAM cleaning is disabled \
                 to protect the in-RAM system disk cache"
            );
        }
        if storage == SystemStorage::Unknown {
            log::warn!("Could not identify the system storage; RAM cleaning will be skipped");
        }
        storage
    })
}

pub(crate) fn ram_clean_skip_reason() -> Option<&'static str> {
    storage_skip_reason(system_storage())
}

fn storage_skip_reason(storage: SystemStorage) -> Option<&'static str> {
    match storage {
        SystemStorage::Local => None,
        SystemStorage::Diskless => Some(
            "Skipped on this PC: it boots from the network (internet-cafe diskless setup), and cleaning could freeze it.",
        ),
        SystemStorage::Unknown => Some(
            "Couldn't check how Windows is stored, so RAM cleaning was skipped. Restart SwiftTunnel to retry the check.",
        ),
    }
}

/// Identity markers of common diskless-boot products as they appear in the
/// system disk's vendor/product strings (the boot target is presented as a
/// virtual SCSI disk with a telltale name).
const DISKLESS_IDENTITY_MARKERS: &[&str] =
    &["ccboot", "gcafe", "icafe", "diskless", "vdisk", "netdisk"];

fn identity_indicates_diskless(identity_lower: &str) -> bool {
    DISKLESS_IDENTITY_MARKERS
        .iter()
        .any(|marker| identity_lower.contains(marker))
}

/// Bus types whose "disk" is not local storage. Values from STORAGE_BUS_TYPE:
/// 9 = iSCSI (network block device), 15 = file-backed virtual disk (the
/// RAM/LAN-cached images diskless setups mount as the system drive).
fn bus_type_indicates_diskless(bus_type: i32) -> bool {
    const BUS_TYPE_ISCSI: i32 = 9;
    const BUS_TYPE_FILE_BACKED_VIRTUAL: i32 = 15;
    matches!(bus_type, BUS_TYPE_ISCSI | BUS_TYPE_FILE_BACKED_VIRTUAL)
}

#[cfg(windows)]
fn detect() -> SystemStorage {
    use std::ffi::c_void;
    use windows::Win32::Foundation::CloseHandle;
    use windows::Win32::Storage::FileSystem::{
        CreateFileW, FILE_FLAGS_AND_ATTRIBUTES, FILE_SHARE_READ, FILE_SHARE_WRITE, OPEN_EXISTING,
    };
    use windows::Win32::System::IO::DeviceIoControl;
    use windows::Win32::System::Ioctl::{
        IOCTL_STORAGE_QUERY_PROPERTY, PropertyStandardQuery, STORAGE_PROPERTY_QUERY,
        StorageDeviceProperty,
    };
    use windows::core::PCWSTR;

    let system_drive = std::env::var("SystemDrive").unwrap_or_else(|_| "C:".to_string());
    let volume_path: Vec<u16> = format!(r"\\.\{system_drive}")
        .encode_utf16()
        .chain(std::iter::once(0))
        .collect();

    unsafe {
        // Desired access 0: device-property queries don't need read/write.
        let Ok(handle) = CreateFileW(
            PCWSTR(volume_path.as_ptr()),
            0,
            FILE_SHARE_READ | FILE_SHARE_WRITE,
            None,
            OPEN_EXISTING,
            FILE_FLAGS_AND_ATTRIBUTES(0),
            None,
        ) else {
            return SystemStorage::Unknown;
        };
        if handle.is_invalid() {
            return SystemStorage::Unknown;
        }

        let query = STORAGE_PROPERTY_QUERY {
            PropertyId: StorageDeviceProperty,
            QueryType: PropertyStandardQuery,
            AdditionalParameters: [0],
        };
        let storage = query_system_storage(|buffer| {
            let mut returned = 0u32;
            match DeviceIoControl(
                handle,
                IOCTL_STORAGE_QUERY_PROPERTY,
                Some(&query as *const _ as *const c_void),
                std::mem::size_of::<STORAGE_PROPERTY_QUERY>() as u32,
                Some(buffer.as_mut_ptr() as *mut c_void),
                buffer.len() as u32,
                Some(&mut returned),
                None,
            ) {
                Ok(()) => Some(returned as usize),
                Err(error) => {
                    log::debug!("System storage descriptor query failed: {error}");
                    None
                }
            }
        });
        let _ = CloseHandle(handle);
        storage
    }
}

#[cfg(not(windows))]
fn detect() -> SystemStorage {
    SystemStorage::Unknown
}

#[cfg(windows)]
fn query_system_storage(mut query: impl FnMut(&mut [u8]) -> Option<usize>) -> SystemStorage {
    use windows::Win32::System::Ioctl::{STORAGE_DESCRIPTOR_HEADER, STORAGE_DEVICE_DESCRIPTOR};
    // Descriptor strings are variable-length. Read the advertised size first.
    let mut header = [0u8; std::mem::size_of::<STORAGE_DESCRIPTOR_HEADER>()];
    if query(&mut header) != Some(header.len()) {
        return SystemStorage::Unknown;
    }
    let size = u32::from_le_bytes([header[4], header[5], header[6], header[7]]) as usize;
    if !(std::mem::size_of::<STORAGE_DEVICE_DESCRIPTOR>()..=64 * 1024).contains(&size) {
        return SystemStorage::Unknown;
    }
    let mut buffer = vec![0; size];
    let Some(returned) = query(&mut buffer) else {
        return SystemStorage::Unknown;
    };
    let Some(valid) = buffer
        .get(..returned)
        .filter(|bytes| bytes.len() >= std::mem::size_of::<STORAGE_DEVICE_DESCRIPTOR>())
    else {
        return SystemStorage::Unknown;
    };
    // A byte buffer does not promise native structure alignment.
    let descriptor =
        unsafe { std::ptr::read_unaligned(valid.as_ptr().cast::<STORAGE_DEVICE_DESCRIPTOR>()) };
    if descriptor.Size as usize > valid.len()
        || (descriptor.Size as usize) < std::mem::size_of::<STORAGE_DEVICE_DESCRIPTOR>()
    {
        return SystemStorage::Unknown;
    }
    if bus_type_indicates_diskless(descriptor.BusType.0) {
        return SystemStorage::Diskless;
    }
    let valid = &valid[..descriptor.Size as usize];
    let identity = [descriptor.VendorIdOffset, descriptor.ProductIdOffset]
        .iter()
        .filter_map(|&offset| ansi_string_at(valid, offset as usize))
        .collect::<Vec<_>>()
        .join(" ")
        .to_ascii_lowercase();
    if identity_indicates_diskless(&identity) {
        SystemStorage::Diskless
    } else if descriptor.BusType.0 == 0 {
        SystemStorage::Unknown
    } else {
        SystemStorage::Local
    }
}

/// Read a NUL-terminated ANSI string embedded in the descriptor buffer at
/// `offset` (0 means "not present").
#[cfg(windows)]
fn ansi_string_at(buffer: &[u8], offset: usize) -> Option<String> {
    if offset == 0 || offset >= buffer.len() {
        return None;
    }
    let bytes = &buffer[offset..];
    let end = bytes.iter().position(|&b| b == 0).unwrap_or(bytes.len());
    let text = String::from_utf8_lossy(&bytes[..end]).trim().to_string();
    if text.is_empty() { None } else { Some(text) }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_confirmed_local_storage_allows_ram_cleaning() {
        assert!(storage_skip_reason(SystemStorage::Local).is_none());
        assert!(
            storage_skip_reason(SystemStorage::Diskless)
                .unwrap()
                .contains("network")
        );
        let unknown = storage_skip_reason(SystemStorage::Unknown).unwrap();
        assert!(unknown.contains("skipped"));
        assert!(unknown.contains("Restart SwiftTunnel"));
    }

    #[cfg(windows)]
    fn descriptor(bus: i32, vendor: &[u8], size: usize) -> Vec<u8> {
        use windows::Win32::System::Ioctl::STORAGE_DEVICE_DESCRIPTOR;
        let offset = size - vendor.len() - 1;
        let mut bytes = vec![0u8; size];
        let mut native = STORAGE_DEVICE_DESCRIPTOR {
            Version: std::mem::size_of::<STORAGE_DEVICE_DESCRIPTOR>() as u32,
            Size: size as u32,
            VendorIdOffset: if vendor.is_empty() { 0 } else { offset as u32 },
            ..Default::default()
        };
        native.BusType.0 = bus;
        unsafe {
            std::ptr::write_unaligned(
                bytes.as_mut_ptr().cast::<STORAGE_DEVICE_DESCRIPTOR>(),
                native,
            );
        }
        bytes[offset..offset + vendor.len()].copy_from_slice(vendor);
        bytes
    }

    #[cfg(windows)]
    #[test]
    fn storage_query_uses_the_reported_size_and_recognizes_long_identity_data() {
        for (bus, vendor, size, expected) in [
            (17, b"NVME".as_slice(), 128, SystemStorage::Local),
            (9, b"".as_slice(), 128, SystemStorage::Diskless),
            (15, b"".as_slice(), 128, SystemStorage::Diskless),
            (17, b"CCBOOT".as_slice(), 2048, SystemStorage::Diskless),
            (0, b"".as_slice(), 128, SystemStorage::Unknown),
        ] {
            let body = descriptor(bus, vendor, size);
            let mut calls = 0;
            assert_eq!(
                query_system_storage(|buffer| {
                    calls += 1;
                    if calls == 1 {
                        assert_eq!(buffer.len(), 8);
                        buffer.copy_from_slice(&body[..8]);
                    } else {
                        assert_eq!(buffer.len(), size);
                        buffer.copy_from_slice(&body);
                    }
                    Some(buffer.len())
                }),
                expected
            );
            assert_eq!(calls, 2);
        }
    }

    #[cfg(windows)]
    #[test]
    fn failed_truncated_or_oversized_storage_queries_remain_unknown() {
        assert_eq!(query_system_storage(|_| None), SystemStorage::Unknown);
        assert_eq!(query_system_storage(|_| Some(4)), SystemStorage::Unknown);
        for size in [0u32, 16, 65537, u32::MAX] {
            let mut calls = 0;
            assert_eq!(
                query_system_storage(|buffer| {
                    calls += 1;
                    buffer[4..8].copy_from_slice(&size.to_le_bytes());
                    Some(buffer.len())
                }),
                SystemStorage::Unknown
            );
            assert_eq!(
                calls, 1,
                "invalid sizes must not allocate or repeat the query"
            );
        }
        for returned in [0, 16, 64, 129, usize::MAX] {
            let body = descriptor(17, b"NVME", 128);
            let mut calls = 0;
            assert_eq!(
                query_system_storage(|buffer| {
                    calls += 1;
                    if calls == 1 {
                        buffer.copy_from_slice(&body[..8]);
                        Some(8)
                    } else {
                        buffer.copy_from_slice(&body);
                        Some(returned)
                    }
                }),
                SystemStorage::Unknown
            );
        }
    }

    #[test]
    fn known_diskless_identities_match() {
        for identity in [
            "ccboot vdisk scsi disk device",
            "gcafe boot disk",
            "richtech icafe vdisk",
            "generic netdisk target",
            "vendor diskless image",
        ] {
            assert!(identity_indicates_diskless(identity), "{identity}");
        }
    }

    #[test]
    fn normal_disk_identities_do_not_match() {
        for identity in [
            "samsung ssd 990 pro 2tb",
            "wdc wd10ezex-08wn4a0",
            "nvme kingston snv2s1000g",
            "vmware virtual nvme disk", // plain VM: purging is safe there
            "",
        ] {
            assert!(!identity_indicates_diskless(identity), "{identity}");
        }
    }

    #[test]
    fn network_backed_bus_types_match() {
        assert!(bus_type_indicates_diskless(9)); // iSCSI
        assert!(bus_type_indicates_diskless(15)); // file-backed virtual
        for local in [0, 1, 3, 7, 8, 10, 11, 17] {
            assert!(!bus_type_indicates_diskless(local), "bus {local}");
        }
    }
}
