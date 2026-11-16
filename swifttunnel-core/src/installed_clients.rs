//! Which SwiftTunnel clients this machine has.
//!
//! The full app and Lite are separate products that share a machine, a packet
//! filter driver, a settings file and an account. Anything an uninstall tears
//! down has to ask whether the other one still needs it first, or removing
//! either leaves the survivor subtly broken with nothing pointing at the cause:
//! the uninstall reports success, the remaining client still launches and looks
//! healthy, and the damage only shows later.
//!
//! Two callers so far. The driver removal, where getting this wrong left the
//! survivor unable to connect at all, and the autostart entries, where it
//! silently stopped the survivor launching at login.

/// The display name of the client that is *not* the one running `exe_name`.
///
/// Split out and pure because the one thing that can silently invert every
/// caller is easy to get wrong: "SwiftTunnel" is a prefix of "SwiftTunnel
/// Lite". Match those loosely and each client finds itself, concludes the other
/// is installed, and nothing is ever cleaned up by anyone.
pub fn other_client_name(exe_name: &str) -> &'static str {
    if exe_name.to_ascii_lowercase().contains("swifttunnel-lite") {
        FULL_APP
    } else {
        LITE
    }
}

pub const FULL_APP: &str = "SwiftTunnel";
pub const LITE: &str = "SwiftTunnel Lite";

/// The other SwiftTunnel client, if it is still registered here.
///
/// Which client counts as "other" comes from the running binary, not from
/// counting registrations. During an uninstall our own entry may or may not
/// still exist depending on where in the sequence this runs, so a count would
/// flip the answer for reasons that have nothing to do with the other client.
#[cfg(windows)]
pub fn other_client_still_installed() -> Result<Option<&'static str>, String> {
    let exe = std::env::current_exe()
        .map_err(|error| format!("Could not identify this SwiftTunnel executable: {error}"))?;
    let name = exe
        .file_name()
        .ok_or("Could not identify this SwiftTunnel executable.")?;

    let other = other_client_name(&name.to_string_lossy());
    product_is_registered(other).map(|present| present.then_some(other))
}

#[cfg(not(windows))]
pub fn other_client_still_installed() -> Result<Option<&'static str>, String> {
    Ok(None)
}

#[cfg(any(windows, test))]
const MAX_PRODUCTS_PER_VIEW: usize = 4096;

#[cfg(any(windows, test))]
fn scan_product_names(
    display_name: &str,
    names: impl IntoIterator<Item = std::io::Result<Option<String>>>,
) -> std::io::Result<bool> {
    for (index, name) in names.into_iter().enumerate() {
        if index >= MAX_PRODUCTS_PER_VIEW {
            return Err(std::io::Error::other(
                "Too many installed-application records",
            ));
        }
        if name?.is_some_and(|name| name.trim().eq_ignore_ascii_case(display_name)) {
            return Ok(true);
        }
    }
    Ok(false)
}

#[cfg(any(windows, test))]
fn registration_in_views(
    views: impl IntoIterator<Item = std::io::Result<bool>>,
) -> std::io::Result<bool> {
    let mut first_error = None;
    for result in views {
        match result {
            Ok(true) => return Ok(true),
            Ok(false) => {}
            Err(error) => {
                first_error.get_or_insert(error);
            }
        }
    }
    first_error.map_or(Ok(false), Err)
}

/// Whether a product with exactly this display name is registered.
///
/// Exact, case-insensitive comparison on purpose, for the prefix reason above.
#[cfg(windows)]
pub fn product_is_registered(display_name: &str) -> Result<bool, String> {
    use std::io::ErrorKind;
    use winreg::RegKey;
    use winreg::enums::{
        HKEY_CURRENT_USER, HKEY_LOCAL_MACHINE, KEY_READ, KEY_WOW64_32KEY, KEY_WOW64_64KEY,
    };

    const UNINSTALL: &str = r"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall";
    // Select both registry views explicitly, including per-user installs.
    // A missing hive/vanished product is normal; a denied or unreadable one
    // cannot establish that the survivor no longer needs shared components.
    let views = [
        (HKEY_LOCAL_MACHINE, KEY_WOW64_64KEY),
        (HKEY_LOCAL_MACHINE, KEY_WOW64_32KEY),
        (HKEY_CURRENT_USER, KEY_WOW64_64KEY),
        (HKEY_CURRENT_USER, KEY_WOW64_32KEY),
    ]
    .into_iter()
    .map(|(root, view)| {
        let key = match RegKey::predef(root).open_subkey_with_flags(UNINSTALL, KEY_READ | view) {
            Ok(key) => key,
            Err(error) if error.kind() == ErrorKind::NotFound => return Ok(false),
            Err(error) => return Err(error),
        };
        scan_product_names(
            display_name,
            key.enum_keys().map(|entry| {
                let entry = entry?;
                let product = match key.open_subkey_with_flags(entry, KEY_READ | view) {
                    Ok(product) => product,
                    Err(error) if error.kind() == ErrorKind::NotFound => return Ok(None),
                    Err(error) => return Err(error),
                };
                crate::registry_value::read::<String>(&product, "DisplayName")
            }),
        )
    });
    registration_in_views(views)
        .map_err(|error| format!("Could not fully check SwiftTunnel installations: {error}"))
}

#[cfg(not(windows))]
pub fn product_is_registered(_display_name: &str) -> Result<bool, String> {
    Ok(false)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unreadable_registration_never_becomes_a_confirmed_absence() {
        let denied = || std::io::Error::from(std::io::ErrorKind::PermissionDenied);
        assert!(registration_in_views([Ok(false), Err(denied()), Ok(false)]).is_err());
        assert!(registration_in_views([Ok(false), Ok(false)]).is_ok_and(|present| !present));
        // A positively identified survivor is sufficient even if another
        // registry view cannot be read.
        assert!(registration_in_views([Err(denied()), Ok(true)]).unwrap());
        assert!(scan_product_names(LITE, [Err(denied())]).is_err());
        assert!(
            scan_product_names(LITE, [Ok(None), Ok(Some(" SwiftTunnel Lite ".into()))]).unwrap()
        );
        assert!(!scan_product_names(FULL_APP, [Ok(Some(LITE.into()))]).unwrap());
    }

    #[test]
    fn registration_scan_has_a_work_budget_and_stops_at_a_match() {
        use std::cell::Cell;
        let reads = Cell::new(0usize);
        let names = (0..10_000).map(|_| {
            reads.set(reads.get() + 1);
            Ok(None)
        });
        assert!(scan_product_names(LITE, names).is_err());
        assert_eq!(reads.get(), MAX_PRODUCTS_PER_VIEW + 1);
        let names = std::iter::once(Ok(Some(FULL_APP.into()))).chain(std::iter::from_fn(|| {
            panic!("a confirmed match must stop the registry scan")
        }));
        assert!(scan_product_names(FULL_APP, names).unwrap());
    }

    /// Each client must look for the *other* one, never itself.
    ///
    /// Everything shared is torn down on this answer, so getting it backwards
    /// means each client finds its own registration, decides the other is
    /// present, and nothing is ever removed by anything.
    #[test]
    fn each_client_looks_for_the_other_one() {
        assert_eq!(other_client_name("swifttunnel-lite.exe"), FULL_APP);
        assert_eq!(other_client_name("swifttunnel-desktop.exe"), LITE);
        // Casing and full paths are both real: the name comes from
        // current_exe(), and Windows is not consistent about either.
        assert_eq!(
            other_client_name(r"C:\Program Files\SwiftTunnel Lite\SwiftTunnel-Lite.EXE"),
            FULL_APP
        );
        // Anything unrecognised is treated as the full app, so the fallback
        // guards Lite. Lite is the newer product and the likelier survivor,
        // and erring towards keeping something is the cheaper mistake.
        assert_eq!(other_client_name("msiexec.exe"), LITE);
    }

    /// "SwiftTunnel" is a prefix of "SwiftTunnel Lite".
    ///
    /// The registry lookup compares display names exactly for this reason. A
    /// `contains` would make the full app match Lite's entry and conclude a
    /// second client is installed when only one is.
    #[test]
    fn the_two_display_names_are_never_confused() {
        assert_ne!(FULL_APP, LITE);
        assert!(
            LITE.starts_with(FULL_APP),
            "the prefix relationship is the whole hazard; if this stops being \
             true the exact-match requirement should be revisited"
        );
        assert!(!FULL_APP.eq_ignore_ascii_case(LITE));
    }
}
