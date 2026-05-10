//! Desktop hardware identity for server-side abuse controls.
//!
//! The raw Windows MachineGuid never leaves the device. We send a stable,
//! domain-separated hash so the API can correlate desktop launches from the
//! same machine without receiving the registry value itself.

use sha2::{Digest, Sha256};

const HWID_HASH_INFO: &[u8] = b"swifttunnel-desktop-hwid-v1";
const HWID_PREFIX: &str = "hwid:v1:";

#[cfg(windows)]
fn read_machine_guid() -> Option<String> {
    use winreg::RegKey;
    use winreg::enums::HKEY_LOCAL_MACHINE;

    let hklm = RegKey::predef(HKEY_LOCAL_MACHINE);
    let key = hklm.open_subkey("SOFTWARE\\Microsoft\\Cryptography").ok()?;
    key.get_value::<String, _>("MachineGuid").ok()
}

#[cfg(not(windows))]
fn read_machine_guid() -> Option<String> {
    None
}

pub(crate) fn desktop_hwid_from_machine_guid(machine_guid: &str) -> Option<String> {
    let normalized = machine_guid.trim().to_ascii_lowercase();
    if normalized.is_empty() || normalized == "swifttunnel-unknown-machine" {
        return None;
    }

    let mut hasher = Sha256::new();
    hasher.update(HWID_HASH_INFO);
    hasher.update([0xff]);
    hasher.update(normalized.as_bytes());
    Some(format!("{}{:x}", HWID_PREFIX, hasher.finalize()))
}

pub(crate) fn desktop_hwid() -> Option<String> {
    read_machine_guid()
        .as_deref()
        .and_then(desktop_hwid_from_machine_guid)
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
    }
}
