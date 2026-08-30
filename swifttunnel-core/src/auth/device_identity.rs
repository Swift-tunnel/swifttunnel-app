//! Desktop hardware identity for server-side abuse controls.
//!
//! No raw identifier ever leaves the device. Each signal is hashed with its own
//! domain separator, so the API can correlate launches from the same machine
//! without receiving registry values, serial numbers, or anything that
//! identifies the hardware off-device.
//!
//! Several independent signals are collected and reported separately, so the
//! server decides what constitutes the same device. Which of them it weighs,
//! and how many must agree, is not decided here.
//!
//! None of this is unspoofable. The client runs on hardware the user controls,
//! so anything it reports is a claim rather than a fact. The goal is narrower
//! and achievable: make casual farming stop working and leave the rest rare
//! enough to handle case by case.
//!
//! Everything here uses the registry or a direct Win32 call. Nothing shells out,
//! so no console window can flash on a user's screen.

use std::sync::OnceLock;

use sha2::{Digest, Sha256};

const HWID_HASH_INFO: &[u8] = b"swifttunnel-desktop-hwid-v1";
const HWID_PREFIX: &str = "hwid:v1:";
const ZERO_MACHINE_GUID: &str = "00000000-0000-0000-0000-000000000000";

/// Hex characters kept from each component hash. 64 bits is plenty to correlate
/// a device across sessions while keeping the header small, and truncating
/// removes any temptation to treat these as reversible.
const COMPONENT_HEX_LEN: usize = 16;

/// A single fingerprint input, already reduced to a hash.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct DeviceSignal {
    /// Short stable key naming the source, e.g. `mg` for MachineGuid.
    pub key: &'static str,
    pub hash: String,
}

/// Hash one raw value under its own domain separator.
///
/// The separator means the same string read from two different sources cannot
/// produce the same component hash, so a device that reports (say) an identical
/// board product and system product does not look like a double match.
fn hash_signal(domain: &str, raw: &str) -> Option<String> {
    let normalized = raw.trim().to_ascii_lowercase();
    if is_useless_value(&normalized) {
        return None;
    }

    let mut hasher = Sha256::new();
    hasher.update(b"swifttunnel-device-v2");
    hasher.update([0xff]);
    hasher.update(domain.as_bytes());
    hasher.update([0xff]);
    hasher.update(normalized.as_bytes());
    let full = format!("{:x}", hasher.finalize());
    Some(full[..COMPONENT_HEX_LEN].to_string())
}

fn is_useless_value(value: &str) -> bool {
    const PLACEHOLDERS: &[&str] = &[
        "",
        "none",
        "n/a",
        "na",
        "null",
        "unknown",
        "default string",
        "to be filled by o.e.m.",
        "to be filled by oem",
        "system serial number",
        "system product name",
        "system manufacturer",
        "base board serial number",
        "not applicable",
        "not specified",
        "0",
        "00000000",
        "ffffffff",
        "swifttunnel-unknown-machine",
        ZERO_MACHINE_GUID,
        "00000000000000000000000000000000",
    ];
    PLACEHOLDERS.contains(&value) || value.chars().all(|c| c == '0' || c == '-' || c == ' ')
}

// ---------------------------------------------------------------------------
// Signal collection
// ---------------------------------------------------------------------------

#[cfg(windows)]
fn read_registry_string(hive_key: &str, value: &str) -> Option<String> {
    use winreg::RegKey;
    use winreg::enums::HKEY_LOCAL_MACHINE;

    let hklm = RegKey::predef(HKEY_LOCAL_MACHINE);
    let key = hklm.open_subkey(hive_key).ok()?;
    key.get_value::<String, _>(value).ok()
}

#[cfg(windows)]
fn read_registry_u32(hive_key: &str, value: &str) -> Option<u32> {
    use winreg::RegKey;
    use winreg::enums::HKEY_LOCAL_MACHINE;

    let hklm = RegKey::predef(HKEY_LOCAL_MACHINE);
    let key = hklm.open_subkey(hive_key).ok()?;
    key.get_value::<u32, _>(value).ok()
}

#[cfg(windows)]
fn read_machine_guid() -> Option<String> {
    read_registry_string("SOFTWARE\\Microsoft\\Cryptography", "MachineGuid")
}

#[cfg(not(windows))]
fn read_machine_guid() -> Option<String> {
    None
}

#[cfg(windows)]
fn read_boot_volume_serial() -> Option<String> {
    use windows::Win32::Storage::FileSystem::GetVolumeInformationW;
    use windows::core::PCWSTR;

    let root: Vec<u16> = "C:\\\0".encode_utf16().collect();
    let mut serial: u32 = 0;

    // SAFETY: `root` is a NUL-terminated UTF-16 buffer that outlives the call,
    // and `serial` is a live stack slot for the single out-parameter we ask for.
    let ok = unsafe {
        GetVolumeInformationW(
            PCWSTR(root.as_ptr()),
            None,
            Some(&mut serial),
            None,
            None,
            None,
        )
    };

    if ok.is_err() || serial == 0 {
        return None;
    }
    Some(format!("{serial:08x}"))
}

#[cfg(not(windows))]
fn read_boot_volume_serial() -> Option<String> {
    None
}

/// Collect every available signal, skipping ones this machine cannot supply.
#[cfg(windows)]
fn collect_signals() -> Vec<DeviceSignal> {
    const BIOS: &str = "HARDWARE\\DESCRIPTION\\System\\BIOS";
    const WINDOWS_NT: &str = "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion";
    const HW_PROFILE: &str =
        "SYSTEM\\CurrentControlSet\\Control\\IDConfigDB\\Hardware Profiles\\0001";

    let mut signals = Vec::new();
    let mut push = |key: &'static str, domain: &str, raw: Option<String>| {
        if let Some(hash) = raw.as_deref().and_then(|v| hash_signal(domain, v)) {
            signals.push(DeviceSignal { key, hash });
        }
    };

    push("mg", "machine-guid", read_machine_guid());

    let install = match (
        read_registry_string(WINDOWS_NT, "ProductId"),
        read_registry_u32(WINDOWS_NT, "InstallDate"),
    ) {
        (Some(id), Some(date)) => Some(format!("{id}:{date}")),
        (Some(id), None) => Some(id),
        (None, Some(date)) => Some(date.to_string()),
        (None, None) => None,
    };
    push("wi", "windows-install", install);

    let board = match (
        read_registry_string(BIOS, "BaseBoardManufacturer"),
        read_registry_string(BIOS, "BaseBoardProduct"),
    ) {
        (Some(m), Some(p)) => Some(format!("{m}:{p}")),
        (Some(v), None) | (None, Some(v)) => Some(v),
        (None, None) => None,
    };
    push("bb", "base-board", board);

    let system = match (
        read_registry_string(BIOS, "SystemManufacturer"),
        read_registry_string(BIOS, "SystemProductName"),
    ) {
        (Some(m), Some(p)) => Some(format!("{m}:{p}")),
        (Some(v), None) | (None, Some(v)) => Some(v),
        (None, None) => None,
    };
    push("sp", "system-product", system);

    push("vs", "volume-serial", read_boot_volume_serial());
    push(
        "hp",
        "hw-profile",
        read_registry_string(HW_PROFILE, "HwProfileGuid"),
    );

    signals
}

#[cfg(not(windows))]
fn collect_signals() -> Vec<DeviceSignal> {
    Vec::new()
}

// ---------------------------------------------------------------------------
// Public surface
// ---------------------------------------------------------------------------

pub(crate) fn desktop_hwid_from_machine_guid(machine_guid: &str) -> Option<String> {
    let normalized = machine_guid.trim().to_ascii_lowercase();
    if is_useless_value(&normalized) {
        return None;
    }

    let mut hasher = Sha256::new();
    hasher.update(HWID_HASH_INFO);
    hasher.update([0xff]);
    hasher.update(normalized.as_bytes());
    Some(format!("{}{:x}", HWID_PREFIX, hasher.finalize()))
}

/// The v1 identity. Still sent so the API keeps working unchanged while the
/// server learns to read the richer v2 header.
pub(crate) fn desktop_hwid() -> Option<String> {
    read_machine_guid()
        .as_deref()
        .and_then(desktop_hwid_from_machine_guid)
}

/// Render collected signals as a header value: `v2 mg=<hash> wi=<hash> ...`
///
/// Order is fixed by collection order so the same machine always produces a
/// byte-identical string.
pub(crate) fn format_device_fingerprint(signals: &[DeviceSignal]) -> Option<String> {
    if signals.is_empty() {
        return None;
    }
    let mut out = String::from("v2");
    for signal in signals {
        out.push(' ');
        out.push_str(signal.key);
        out.push('=');
        out.push_str(&signal.hash);
    }
    Some(out)
}

/// Device fingerprint for this machine, computed once per process.
///
/// Hardware does not change while the app runs, and this is read on every API
/// request, so the registry and Win32 work happens a single time.
pub(crate) fn device_fingerprint() -> Option<&'static str> {
    static FINGERPRINT: OnceLock<Option<String>> = OnceLock::new();
    FINGERPRINT
        .get_or_init(|| format_device_fingerprint(&collect_signals()))
        .as_deref()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn desktop_hwid_is_stable_and_hashes_raw_guid() {
        let first = desktop_hwid_from_machine_guid("  ABCDEF12-3456-7890-ABCD-EF1234567890  ")
            .expect("valid hwid");
        let second = desktop_hwid_from_machine_guid("abcdef12-3456-7890-abcd-ef1234567890")
            .expect("valid hwid");

        assert_eq!(first, second);
        assert!(first.starts_with("hwid:v1:"));
        assert_eq!(first.len(), "hwid:v1:".len() + 64);
        assert!(!first.contains("abcdef12"));
    }

    #[test]
    fn desktop_hwid_ignores_missing_or_fallback_guid() {
        assert!(desktop_hwid_from_machine_guid("").is_none());
        assert!(desktop_hwid_from_machine_guid("   ").is_none());
        assert!(desktop_hwid_from_machine_guid("swifttunnel-unknown-machine").is_none());
        assert!(desktop_hwid_from_machine_guid(ZERO_MACHINE_GUID).is_none());
        assert!(desktop_hwid_from_machine_guid("00000000000000000000000000000000").is_none());
        assert!(desktop_hwid_from_machine_guid("unknown").is_none());
        assert!(desktop_hwid_from_machine_guid("N/A").is_none());
    }

    #[test]
    fn signal_hashing_is_stable_and_case_insensitive() {
        let a = hash_signal("base-board", "  ASUS:PRIME-B450M  ").expect("hashable");
        let b = hash_signal("base-board", "asus:prime-b450m").expect("hashable");
        assert_eq!(a, b);
        assert_eq!(a.len(), COMPONENT_HEX_LEN);
        assert!(!a.contains("asus"));
    }

    #[test]
    fn same_value_under_different_domains_does_not_collide() {
        // Otherwise a machine reporting the same string for two sources would
        // look like two independent matches instead of one.
        let board = hash_signal("base-board", "acme:x1").expect("hashable");
        let system = hash_signal("system-product", "acme:x1").expect("hashable");
        assert_ne!(board, system);
    }

    #[test]
    fn oem_placeholders_are_rejected() {
        // These would otherwise collapse thousands of unrelated machines onto
        // one fingerprint, which is worse than reporting nothing.
        for junk in [
            "To Be Filled By O.E.M.",
            "Default string",
            "System Product Name",
            "None",
            "00000000",
            "0000-0000",
        ] {
            assert!(
                hash_signal("base-board", junk).is_none(),
                "expected {junk:?} to be rejected"
            );
        }
    }

    #[test]
    fn fingerprint_format_is_stable_and_parseable() {
        let signals = vec![
            DeviceSignal {
                key: "mg",
                hash: "0123456789abcdef".to_string(),
            },
            DeviceSignal {
                key: "vs",
                hash: "fedcba9876543210".to_string(),
            },
        ];
        let rendered = format_device_fingerprint(&signals).expect("some signals");
        assert_eq!(rendered, "v2 mg=0123456789abcdef vs=fedcba9876543210");
    }

    #[test]
    fn fingerprint_is_none_when_nothing_could_be_read() {
        assert!(format_device_fingerprint(&[]).is_none());
    }
}
