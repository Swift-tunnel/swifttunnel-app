//! Clears an orphaned SwiftTunnel MSI registration.
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
//! the same wall, and uninstalling fails for the same reason. Users are stuck
//! with an app they can neither update nor remove.
//!
//! # What this does
//!
//! Finds SwiftTunnel's MSI registration, checks whether the cached package it
//! points at still exists, and if it does not, deletes the registration. The
//! next install then runs as a clean first install rather than an upgrade.
//!
//! It deliberately does nothing when the cached package is present, so running
//! it on a healthy machine is a no-op rather than a way to break one.
//!
//! # Why not just delete the registry keys by hand
//!
//! That is the workaround circulating in support channels, and it works, but
//! `HKLM\SOFTWARE\Classes\Installer\Products` holds an entry for every MSI on
//! the machine under an opaque packed GUID. Picking the wrong one breaks
//! unrelated software. This matches on SwiftTunnel's own DisplayName and
//! verifies the package is genuinely missing first.

use std::path::Path;

use windows_registry::LOCAL_MACHINE;

/// Where Windows records per-machine installed products.
const USERDATA_PRODUCTS: &str =
    r"SOFTWARE\Microsoft\Windows\CurrentVersion\Installer\UserData\S-1-5-18\Products";
const CLASSES_PRODUCTS: &str = r"SOFTWARE\Classes\Installer\Products";
const CLASSES_FEATURES: &str = r"SOFTWARE\Classes\Installer\Features";
const UNINSTALL: &str = r"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall";

struct Orphan {
    /// Registry-form (packed) product id, as used by the Installer keys.
    packed: String,
    /// Human product code, `{XXXXXXXX-....}`, as used by the Uninstall key.
    product_code: String,
    display_name: String,
    display_version: String,
    local_package: String,
}

fn main() {
    let dry_run = std::env::args().any(|a| a == "--dry-run");

    println!("SwiftTunnel MSI repair");
    println!("======================");

    let orphans = match find_orphans() {
        Ok(o) => o,
        Err(e) => {
            eprintln!("Could not read the installer registry: {e}");
            eprintln!("Try running this as Administrator.");
            std::process::exit(2);
        }
    };

    if orphans.is_empty() {
        println!();
        println!("Nothing to repair. Either SwiftTunnel is not installed, or its");
        println!("installer package is still present and upgrades will work normally.");
        return;
    }

    for orphan in &orphans {
        println!();
        println!("Found a broken registration:");
        println!(
            "  Product      : {} {}",
            orphan.display_name, orphan.display_version
        );
        println!("  Product code : {}", orphan.product_code);
        println!("  Missing file : {}", orphan.local_package);

        if dry_run {
            println!("  -> --dry-run given, leaving it alone.");
            continue;
        }

        match clear_registration(orphan) {
            Ok(()) => println!("  -> Cleared. Install SwiftTunnel again and it will work."),
            Err(e) => {
                eprintln!("  -> Failed: {e}");
                eprintln!("     This needs Administrator. Right-click and Run as administrator.");
                std::process::exit(3);
            }
        }
    }
}

/// SwiftTunnel registrations whose cached installer package no longer exists.
fn find_orphans() -> windows_registry::Result<Vec<Orphan>> {
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

        // A registration whose package is still on disk is healthy. Upgrades
        // and uninstalls will find what they need, so leave it completely alone.
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
fn clear_registration(orphan: &Orphan) -> Result<(), String> {
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

/// Convert a packed installer id back into a readable product code.
///
/// Windows stores product codes with the first three GUID fields byte-reversed
/// and the remaining eight bytes nibble-swapped, which is why these keys look
/// like nonsense next to the GUID they represent. The Uninstall key uses the
/// readable form, so both are needed to clean up fully.
fn unpack_guid(packed: &str) -> String {
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
