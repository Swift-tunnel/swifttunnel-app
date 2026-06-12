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

/// True when Windows itself runs from a network/RAM-backed virtual disk.
/// Cached for the process lifetime — the system disk cannot change while
/// Windows is running.
pub fn system_is_diskless() -> bool {
    static DISKLESS: OnceLock<bool> = OnceLock::new();
    *DISKLESS.get_or_init(|| {
        let diskless = detect();
        if diskless {
            log::info!(
                "Network-booted (diskless) system detected; RAM cleaning is disabled \
                 to protect the in-RAM system disk cache"
            );
        }
        diskless
    })
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
fn detect() -> bool {
    use std::ffi::c_void;
    use windows::Win32::Foundation::CloseHandle;
    use windows::Win32::Storage::FileSystem::{
        CreateFileW, FILE_FLAGS_AND_ATTRIBUTES, FILE_SHARE_READ, FILE_SHARE_WRITE, OPEN_EXISTING,
    };
    use windows::Win32::System::IO::DeviceIoControl;
    use windows::Win32::System::Ioctl::{
        IOCTL_STORAGE_QUERY_PROPERTY, PropertyStandardQuery, STORAGE_DEVICE_DESCRIPTOR,
        STORAGE_PROPERTY_QUERY, StorageDeviceProperty,
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
            return false;
        };
        if handle.is_invalid() {
            return false;
        }

        let query = STORAGE_PROPERTY_QUERY {
            PropertyId: StorageDeviceProperty,
            QueryType: PropertyStandardQuery,
            AdditionalParameters: [0],
        };
        let mut buffer = vec![0u8; 1024];
        let mut returned = 0u32;
        let ok = DeviceIoControl(
            handle,
            IOCTL_STORAGE_QUERY_PROPERTY,
            Some(&query as *const _ as *const c_void),
            std::mem::size_of::<STORAGE_PROPERTY_QUERY>() as u32,
            Some(buffer.as_mut_ptr() as *mut c_void),
            buffer.len() as u32,
            Some(&mut returned),
            None,
        )
        .is_ok();
        let _ = CloseHandle(handle);

        if !ok || (returned as usize) < std::mem::size_of::<STORAGE_DEVICE_DESCRIPTOR>() {
            return false;
        }
        let valid = &buffer[..returned as usize];

        let descriptor = &*(valid.as_ptr() as *const STORAGE_DEVICE_DESCRIPTOR);
        if bus_type_indicates_diskless(descriptor.BusType.0) {
            return true;
        }

        let identity = [descriptor.VendorIdOffset, descriptor.ProductIdOffset]
            .iter()
            .filter_map(|&offset| ansi_string_at(valid, offset as usize))
            .collect::<Vec<_>>()
            .join(" ")
            .to_ascii_lowercase();
        identity_indicates_diskless(&identity)
    }
}

#[cfg(not(windows))]
fn detect() -> bool {
    false
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
