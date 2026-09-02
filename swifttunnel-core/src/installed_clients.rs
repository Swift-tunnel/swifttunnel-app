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
pub fn other_client_still_installed() -> Option<&'static str> {
    let exe = std::env::current_exe()
        .ok()
        .and_then(|path| {
            path.file_name()
                .map(|name| name.to_string_lossy().into_owned())
        })
        .unwrap_or_default();

    let other = other_client_name(&exe);
    product_is_registered(other).then_some(other)
}

#[cfg(not(windows))]
pub fn other_client_still_installed() -> Option<&'static str> {
    None
}

/// Whether a product with exactly this display name is registered.
///
/// Exact, case-insensitive comparison on purpose, for the prefix reason above.
#[cfg(windows)]
pub fn product_is_registered(display_name: &str) -> bool {
    use winreg::RegKey;
    use winreg::enums::{HKEY_CURRENT_USER, HKEY_LOCAL_MACHINE};

    const UNINSTALL: &str = r"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall";
    // A 32-bit install lands under WOW6432Node and a per-user one under HKCU.
    // Missing either would tear down something the survivor still needs.
    const UNINSTALL_WOW: &str = r"SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall";

    for (root, path) in [
        (HKEY_LOCAL_MACHINE, UNINSTALL),
        (HKEY_LOCAL_MACHINE, UNINSTALL_WOW),
        (HKEY_CURRENT_USER, UNINSTALL),
    ] {
        let Ok(key) = RegKey::predef(root).open_subkey(path) else {
            continue;
        };
        for entry in key.enum_keys().flatten() {
            let Ok(product) = key.open_subkey(&entry) else {
                continue;
            };
            let name: String = product.get_value("DisplayName").unwrap_or_default();
            if name.trim().eq_ignore_ascii_case(display_name) {
                return true;
            }
        }
    }
    false
}

#[cfg(not(windows))]
pub fn product_is_registered(_display_name: &str) -> bool {
    false
}

#[cfg(test)]
mod tests {
    use super::*;

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
