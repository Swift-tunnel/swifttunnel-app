//! Clearing an orphaned SwiftTunnel MSI registration.
//!
//! # The problem this exists for
//!
//! An MSI major upgrade removes the old version before installing the new one,
//! and to do that Windows Installer needs the *original* .msi the old version
//! was installed from. It keeps a copy under `C:\Windows\Installer` for exactly
//! this, and falls back to the path the package was installed from.
//!
//! Users who run PC cleanup utilities lose the cached copy, and the fallback
//! path is usually gone too: it was either a Downloads folder they tidied, or
//! the auto-updater's temp directory, which Windows wipes on its own. With
//! neither available the upgrade stops on:
//!
//!   "The feature you are trying to use is on a network resource that is
//!    unavailable"
//!
//! The install is then unwinnable from the UI. Windows still believes
//! SwiftTunnel is installed, so a fresh install turns into an upgrade and hits
//! the same wall, and uninstalling fails for the same reason.
//!
//! # Why this is a library
//!
//! It cannot run from inside the MSI. The repair has to happen before
//! `msiexec` starts, so it is called from two places that run *ahead* of it:
//! `swifttunnel-setup`, the launcher the website serves, and the desktop app's
//! updater. Both are already elevated when they call this; the registry writes
//! need administrator and fail cleanly without it.
//!
//! Attempting this as a WiX custom action was tried and abandoned. An immediate
//! action runs impersonating an unelevated user and cannot write HKLM, and a
//! deferred one runs as SYSTEM but cannot be sequenced ahead of
//! RemoveExistingProducts, which permits no action between itself and its
//! anchor. Moving the removal later makes the old product's uninstall delete
//! the new install's files.

use std::path::Path;

use windows_registry::{CURRENT_USER, LOCAL_MACHINE};

/// Where Windows records per-machine installed products.
/// Every account's installed-product list, not just the machine account's.
///
/// This used to point straight at `S-1-5-18`, the machine account, which is
/// where a per-machine install registers. An install done per-user registers
/// under that user's own SID instead and was invisible here, so the repair
/// reported a healthy machine and the upgrade failed anyway.
const USERDATA: &str = r"SOFTWARE\Microsoft\Windows\CurrentVersion\Installer\UserData";
const CLASSES_PRODUCTS: &str = r"SOFTWARE\Classes\Installer\Products";
const CLASSES_FEATURES: &str = r"SOFTWARE\Classes\Installer\Features";
const UNINSTALL: &str = r"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall";

#[derive(Debug, Clone)]
pub struct Orphan {
    /// Which account's product list this was found under.
    pub sid: String,
    /// Registry-form (packed) product id, as used by the Installer keys.
    pub packed: String,
    /// Human product code, `{XXXXXXXX-....}`, as used by the Uninstall key.
    pub product_code: String,
    pub display_name: String,
    pub display_version: String,
    pub local_package: String,
}

/// SwiftTunnel registrations whose cached installer package no longer exists.
///
/// A registration whose package is still on disk is healthy and is skipped, so
/// running this on a working machine finds nothing and changes nothing.
pub fn find_orphans() -> windows_registry::Result<Vec<Orphan>> {
    let userdata = LOCAL_MACHINE.open(USERDATA)?;
    let mut out = Vec::new();

    for sid in userdata.keys()? {
        let Ok(products) = userdata.open(format!(r"{sid}\Products")) else {
            continue;
        };
        let Ok(packed_keys) = products.keys() else {
            continue;
        };

        for packed in packed_keys {
            let Ok(props) = products.open(format!(r"{packed}\InstallProperties")) else {
                continue;
            };

            let display_name = props.get_string("DisplayName").unwrap_or_default();
            if !display_name.to_lowercase().contains("swifttunnel") {
                continue;
            }

            let local_package = props.get_string("LocalPackage").unwrap_or_default();
            if package_is_usable(&local_package) {
                continue;
            }

            out.push(Orphan {
                sid: sid.clone(),
                product_code: unpack_guid(&packed),
                packed,
                display_name,
                display_version: props.get_string("DisplayVersion").unwrap_or_default(),
                local_package,
            });
        }
    }

    Ok(out)
}

/// Whether the cached package is one Windows Installer could actually use.
///
/// Existing is not the same as usable. Cleanup tools truncate files as often as
/// they delete them, and a zero-length or half-written package passes a plain
/// existence check while Windows still refuses it and asks for the original,
/// which is the failure this whole crate exists to prevent.
///
/// An MSI is an OLE compound document, so the first eight bytes are a fixed
/// signature. Checking them costs one short read and rules out both an empty
/// file and something that is not a package at all.
///
/// Only a package we can prove is bad counts as bad. Saying "not usable" gets a
/// registration deleted, and this now runs on every launch rather than only
/// when someone is already installing, so the cost of being wrong changed. A
/// file we cannot read is not evidence of anything: `C:\Windows\Installer` is
/// readable only by SYSTEM and administrators, and antivirus holds a package
/// open often enough to deny a share. Both look identical to a deleted file
/// through `exists()`, which reports false when metadata is denied. Treating
/// either as missing would unregister a perfectly healthy install, silently, on
/// a machine where nothing was ever wrong.
fn package_is_usable(path: &str) -> bool {
    if path.is_empty() {
        return false;
    }

    // Absent is the one thing worth acting on. Anything else that stops us
    // looking is unknown, and unknown must leave the registration alone.
    match std::fs::metadata(Path::new(path)) {
        Ok(_) => {}
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return false,
        Err(_) => return true,
    }

    const OLE_SIGNATURE: [u8; 8] = [0xD0, 0xCF, 0x11, 0xE0, 0xA1, 0xB1, 0x1A, 0xE1];
    match std::fs::File::open(path) {
        Ok(mut file) => {
            use std::io::Read;
            let mut head = [0u8; 8];
            // A file too short to hold the signature cannot be a package.
            file.read_exact(&mut head).is_ok() && head == OLE_SIGNATURE
        }
        // It is there but we cannot open it. That is a lock or an ACL, not a
        // missing package, so assume the installer will manage.
        Err(_) => true,
    }
}

/// Remove every key that makes Windows believe the product is installed.
pub fn clear_registration(orphan: &Orphan) -> Result<(), String> {
    // Each delete is independent and a missing key is not worth aborting on:
    // a half-cleaned machine should still end up fully cleaned.
    let _ = LOCAL_MACHINE.remove_tree(format!(
        r"{USERDATA}\{}\Products\{}",
        orphan.sid, orphan.packed
    ));
    let _ = LOCAL_MACHINE.remove_tree(format!(r"{CLASSES_PRODUCTS}\{}", orphan.packed));
    let _ = LOCAL_MACHINE.remove_tree(format!(r"{CLASSES_FEATURES}\{}", orphan.packed));
    if !orphan.product_code.is_empty() {
        let _ = LOCAL_MACHINE.remove_tree(format!(r"{UNINSTALL}\{}", orphan.product_code));
        // A per-user install lists itself under the user's own hive, and
        // leaving that behind keeps a dead entry in Add/Remove Programs.
        let _ = CURRENT_USER.remove_tree(format!(r"{UNINSTALL}\{}", orphan.product_code));
    }

    // Verify the one that actually gates upgrades is gone. The rest is
    // bookkeeping; this is the key `RemoveExistingProducts` consults, so
    // reporting success while it survives would send the user round the same
    // loop again.
    if LOCAL_MACHINE
        .open(format!(
            r"{USERDATA}\{}\Products\{}",
            orphan.sid, orphan.packed
        ))
        .is_ok()
    {
        return Err("the registration key could not be removed".to_string());
    }
    Ok(())
}

/// Find and clear every orphaned registration, returning what was cleared.
///
/// A no-op on a healthy machine, so callers can run it unconditionally before
/// an install rather than trying to detect the broken state themselves.
pub fn repair() -> Result<Vec<Orphan>, String> {
    let orphans =
        find_orphans().map_err(|e| format!("could not read the installer registry: {e}"))?;
    for orphan in &orphans {
        clear_registration(orphan)?;
    }
    Ok(orphans)
}

/// Convert a packed installer id back into a readable product code.
///
/// Windows stores product codes with the first three GUID fields byte-reversed
/// and the remaining eight bytes nibble-swapped, which is why these keys look
/// like nonsense next to the GUID they represent. The Uninstall key uses the
/// readable form, so both are needed to clean up fully.
pub fn unpack_guid(packed: &str) -> String {
    if packed.len() != 32 || !packed.chars().all(|c| c.is_ascii_hexdigit()) {
        return String::new();
    }
    let b = packed.as_bytes();
    let rev = |from: usize, len: usize| -> String {
        (0..len).rev().map(|i| b[from + i] as char).collect()
    };
    let swap_pairs = |from: usize, len: usize| -> String {
        (0..len)
            .step_by(2)
            .flat_map(|i| [b[from + i + 1] as char, b[from + i] as char])
            .collect()
    };

    format!(
        "{{{}-{}-{}-{}-{}}}",
        rev(0, 8),
        rev(8, 4),
        rev(12, 4),
        swap_pairs(16, 4),
        swap_pairs(20, 12),
    )
}

#[cfg(test)]
mod tests {
    use super::{package_is_usable, unpack_guid};

    /// Taken from a real SwiftTunnel 3.0.4 install, so the transformation is
    /// pinned against an actual Windows-generated key rather than my reading of
    /// the format.
    #[test]
    fn unpacks_a_real_product_code() {
        assert_eq!(
            unpack_guid("D128028F38FA27944BA0B4B4D4359AE2"),
            "{F820821D-AF83-4972-B40A-4B4B4D53A92E}"
        );
    }

    #[test]
    fn rejects_anything_that_is_not_a_packed_guid() {
        assert_eq!(unpack_guid(""), "");
        assert_eq!(unpack_guid("not-a-guid"), "");
        // Right length, wrong alphabet.
        assert_eq!(unpack_guid("Z128028F38FA27944BA0B4B4D4359AE2"), "");
    }

    const OLE: [u8; 8] = [0xD0, 0xCF, 0x11, 0xE0, 0xA1, 0xB1, 0x1A, 0xE1];

    fn temp_file(name: &str, bytes: &[u8]) -> std::path::PathBuf {
        use std::io::Write;
        let path = std::env::temp_dir().join(format!("swifttunnel-repair-test-{name}"));
        let mut file = std::fs::File::create(&path).expect("create temp file");
        file.write_all(bytes).expect("write temp file");
        path
    }

    #[test]
    fn a_real_package_is_usable() {
        let mut bytes = OLE.to_vec();
        bytes.extend_from_slice(&[0u8; 512]);
        let path = temp_file("good.msi", &bytes);
        assert!(package_is_usable(path.to_str().unwrap()));
        let _ = std::fs::remove_file(path);
    }

    /// A package we are not allowed to read must not be called missing.
    ///
    /// This decides whether a registration gets deleted, and it now runs on
    /// every launch rather than only when someone is installing. The real
    /// cached packages live in `C:\Windows\Installer`, which only SYSTEM and
    /// administrators can read, and antivirus takes an exclusive handle on
    /// them often enough to matter. Answering "missing" to either would
    /// unregister a healthy install on a machine where nothing was wrong.
    #[cfg(windows)]
    #[test]
    fn a_package_we_cannot_open_is_left_alone() {
        use std::os::windows::fs::OpenOptionsExt;

        let mut bytes = OLE.to_vec();
        bytes.extend_from_slice(&[0u8; 512]);
        let path = temp_file("locked.msi", &bytes);

        // share_mode(0) denies every other open, which is exactly the
        // sharing violation a scanner produces.
        let locked = std::fs::OpenOptions::new()
            .read(true)
            .share_mode(0)
            .open(&path)
            .expect("take an exclusive handle");

        assert!(
            package_is_usable(path.to_str().unwrap()),
            "a locked package must be treated as present, not deleted"
        );

        drop(locked);
        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn a_truncated_package_is_not() {
        // The case that made this necessary. Cleanup tools truncate as often
        // as they delete, and the old check only asked whether the path
        // existed, so a nine byte file counted as a healthy install while
        // Windows still refused it and demanded the original.
        let path = temp_file("truncated.msi", b"broken");
        assert!(!package_is_usable(path.to_str().unwrap()));
        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn an_empty_package_is_not() {
        let path = temp_file("empty.msi", b"");
        assert!(!package_is_usable(path.to_str().unwrap()));
        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn something_that_is_not_a_package_is_not() {
        // Right length, wrong contents.
        let path = temp_file("wrong.msi", &[0u8; 4096]);
        assert!(!package_is_usable(path.to_str().unwrap()));
        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn a_missing_or_unnamed_package_is_not() {
        assert!(!package_is_usable(""));
        assert!(!package_is_usable("C:/definitely/not/here/nope.msi"));
    }
}
