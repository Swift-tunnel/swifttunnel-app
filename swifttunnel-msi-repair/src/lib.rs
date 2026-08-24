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

use windows_registry::LOCAL_MACHINE;

/// Where Windows records per-machine installed products.
const USERDATA_PRODUCTS: &str =
    r"SOFTWARE\Microsoft\Windows\CurrentVersion\Installer\UserData\S-1-5-18\Products";
const CLASSES_PRODUCTS: &str = r"SOFTWARE\Classes\Installer\Products";
const CLASSES_FEATURES: &str = r"SOFTWARE\Classes\Installer\Features";
const UNINSTALL: &str = r"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall";

#[derive(Debug, Clone)]
pub struct Orphan {
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
    let products = LOCAL_MACHINE.open(USERDATA_PRODUCTS)?;
    let mut out = Vec::new();

    for packed in products.keys()? {
        let Ok(props) = products.open(format!(r"{packed}\InstallProperties")) else {
            continue;
        };

        let display_name = props.get_string("DisplayName").unwrap_or_default();
        if !display_name.to_lowercase().contains("swifttunnel") {
            continue;
        }

        let local_package = props.get_string("LocalPackage").unwrap_or_default();
        if !local_package.is_empty() && Path::new(&local_package).exists() {
            continue;
        }

        out.push(Orphan {
            product_code: unpack_guid(&packed),
            packed,
            display_name,
            display_version: props.get_string("DisplayVersion").unwrap_or_default(),
            local_package,
        });
    }

    Ok(out)
}

/// Remove every key that makes Windows believe the product is installed.
pub fn clear_registration(orphan: &Orphan) -> Result<(), String> {
    // Each delete is independent and a missing key is not worth aborting on:
    // a half-cleaned machine should still end up fully cleaned.
    let _ = LOCAL_MACHINE.remove_tree(format!(r"{USERDATA_PRODUCTS}\{}", orphan.packed));
    let _ = LOCAL_MACHINE.remove_tree(format!(r"{CLASSES_PRODUCTS}\{}", orphan.packed));
    let _ = LOCAL_MACHINE.remove_tree(format!(r"{CLASSES_FEATURES}\{}", orphan.packed));
    if !orphan.product_code.is_empty() {
        let _ = LOCAL_MACHINE.remove_tree(format!(r"{UNINSTALL}\{}", orphan.product_code));
    }

    // Verify the one that actually gates upgrades is gone. The rest is
    // bookkeeping; this is the key `RemoveExistingProducts` consults, so
    // reporting success while it survives would send the user round the same
    // loop again.
    if LOCAL_MACHINE
        .open(format!(r"{USERDATA_PRODUCTS}\{}", orphan.packed))
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
    use super::unpack_guid;

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
}
