//! Removing Lite from the machine.
//!
//! Lite arrives two ways and only one of them can be removed on its own. The
//! standalone installer registers "SwiftTunnel Lite" as its own product, which
//! has an uninstaller. The full app's installer ships Lite as part of itself,
//! and there is no separate product to remove: taking Lite away there means
//! uninstalling SwiftTunnel. Saying so is better than offering a button that
//! quietly does nothing.

use windows_registry::{CURRENT_USER, LOCAL_MACHINE};

const UNINSTALL: &str = r"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall";

/// How Lite got here, and what can be done about it.
pub enum Installed {
    /// Its own product, with this product code.
    Standalone(String),
    /// Part of the full app's installation.
    WithTheFullApp,
}

/// Find Lite's own registration, if it has one.
///
/// Both hives are searched: a per-user install lists itself under the user's
/// own, and looking only in the machine hive would report "bundled" for an
/// install that is perfectly removable.
pub fn how_installed() -> &'static Installed {
    // Answered once. Nothing can move Lite between the two cases while it is
    // running, and this is read on every poll.
    static ANSWER: std::sync::OnceLock<Installed> = std::sync::OnceLock::new();
    ANSWER.get_or_init(look_for_registration)
}

fn look_for_registration() -> Installed {
    for root in [&LOCAL_MACHINE, &CURRENT_USER] {
        let Ok(key) = root.open(UNINSTALL) else {
            continue;
        };
        let Ok(entries) = key.keys() else {
            continue;
        };
        for entry in entries {
            let Ok(props) = key.open(&entry) else {
                continue;
            };
            let name = props.get_string("DisplayName").unwrap_or_default();
            // "SwiftTunnel Lite" and not "SwiftTunnel": the full app must not
            // be mistaken for the small one and offered up for removal.
            if name.eq_ignore_ascii_case("SwiftTunnel Lite") {
                return Installed::Standalone(entry);
            }
        }
    }
    Installed::WithTheFullApp
}

/// Undo every system change, then hand over to the uninstaller.
///
/// The cleanup runs here rather than from a custom action inside the MSI, for
/// the same reason the full app does it this way: the elevated binary is
/// certainly present at this moment, and a custom action that loses elevation
/// or is skipped leaves driver bindings and hosts entries behind on exactly the
/// machines whose owner is uninstalling because something is already wrong.
pub fn start(product_code: &str) -> Result<(), String> {
    if let Err(error) = swifttunnel_core::network_booster::cleanup_all_system_state() {
        // Not fatal. Leaving the user unable to uninstall would be worse than
        // leaving some state behind, and the uninstaller makes its own attempt.
        log::warn!("cleanup before uninstall failed, continuing: {error}");
    }

    // /x by product code, and let msiexec own the UI from here. Spawned rather
    // than waited on: this process is about to be removed by the thing it just
    // started.
    std::process::Command::new("msiexec")
        .arg("/x")
        .arg(product_code)
        .spawn()
        .map(|_| ())
        .map_err(|e| format!("Could not start the uninstaller: {e}"))
}
