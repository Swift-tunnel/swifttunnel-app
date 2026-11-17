//! Removing Lite from the machine.
//!
//! Lite arrives two ways and only one of them can be removed on its own. The
//! standalone installer registers "SwiftTunnel Lite" as its own product, which
//! has an uninstaller. The full app's installer ships Lite as part of itself,
//! and there is no separate product to remove: taking Lite away there means
//! uninstalling SwiftTunnel. Saying so is better than offering a button that
//! quietly does nothing.

/// How Lite got here, and what can be done about it.
#[derive(Clone)]
pub enum Installed {
    Unknown(String),
    /// Its own product, with this product code.
    Standalone(String),
    /// Part of the full app's installation.
    WithTheFullApp,
    /// Lite's own files, with nothing in Windows Installer that can remove
    /// them: either no record at all (older builds cleared it at startup) or a
    /// record whose installer package has gone.
    Unregistered,
}

/// Find Lite's own registration, if it has one.
///
/// Windows Installer supplies the product family and installation directory.
/// Ambiguous records never authorize uninstalling a different copy.
pub fn how_installed() -> &'static Installed {
    // Answered once. Nothing can move Lite between the two cases while it is
    // running, and this is read on every poll.
    static ANSWER: std::sync::OnceLock<Installed> = std::sync::OnceLock::new();
    ANSWER.get_or_init(look_for_registration)
}

fn look_for_registration() -> Installed {
    use swifttunnel_core::direct_uninstall::{self, Client};
    let Ok(exe) = std::env::current_exe() else {
        return Installed::Unknown("Could not locate this Lite installation.".into());
    };
    if direct_uninstall::lite_is_bundled(&exe) {
        return Installed::WithTheFullApp;
    }
    match registered_product() {
        // Windows cannot uninstall through a record whose package is missing.
        // Offer the direct removal instead of a button that opens an error.
        Ok(Some(code))
            if direct_uninstall::registration_is_broken(Client::Lite, &exe, &code) == Ok(true) =>
        {
            Installed::Unregistered
        }
        Ok(Some(code)) => Installed::Standalone(code),
        // No Lite product is registered. That used to be read as "came with
        // the full app" in every case, which told the owner of an unregistered
        // standalone copy to remove a SwiftTunnel they may not even have.
        Ok(None) => match direct_uninstall::is_standard_install(Client::Lite, &exe) {
            Ok(true) => Installed::Unregistered,
            Ok(false) => Installed::Unknown(
                "Windows has no uninstall record for this copy. Use SwiftTunnel Setup to repair it first.".into(),
            ),
            Err(error) => Installed::Unknown(error),
        },
        Err(error) => Installed::Unknown(error),
    }
}

/// Undo every system change, then remove Lite's own files and shortcuts.
///
/// For a copy Windows has no record of. Returns once the files that can go now
/// are gone and the executable is scheduled to follow; the caller exits.
pub fn remove_directly() -> Result<(), String> {
    use swifttunnel_core::direct_uninstall::{self, Client};
    // Refuses a development build, a bundled copy, and any copy Windows still
    // lists, before anything is touched.
    let plan = direct_uninstall::plan_for_running_client(Client::Lite)?;
    swifttunnel_core::network_booster::cleanup_all_system_state()
        .map_err(|error| format!("Network cleanup could not finish. Retry uninstall after running Internet recovery. {error}"))?;
    direct_uninstall::finish(plan)
}

fn registered_product() -> Result<Option<String>, String> {
    let exe = std::env::current_exe()
        .map_err(|_| "Could not locate this Lite installation.".to_string())?;
    let folder = exe
        .parent()
        .ok_or("Could not locate this Lite installation.")?;
    swifttunnel_core::msi_uninstall::lite_product_code(folder)
}

/// Undo every system change, then hand over to the uninstaller.
///
/// The cleanup runs here rather than from a custom action inside the MSI, for
/// the same reason the full app does it this way: the elevated binary is
/// certainly present at this moment, and a custom action that loses elevation
/// or is skipped leaves driver bindings and hosts entries behind on exactly the
/// machines whose owner is uninstalling because something is already wrong.
pub fn start(product_code: &str) -> Result<(), String> {
    // Recheck the registered product family immediately before any cleanup.
    // A writable display name is not proof of product identity.
    if !registered_product()?.is_some_and(|code| code.eq_ignore_ascii_case(product_code)) {
        return Err(
            "This installation changed. Reopen Lite or use Windows Settings > Apps.".into(),
        );
    }
    let msiexec = swifttunnel_installer_cache::windows_installer_path()
        .map_err(|e| format!("Could not locate Windows Installer: {e}"))?;
    if let Err(error) = swifttunnel_core::network_booster::cleanup_all_system_state() {
        // Not fatal. Leaving the user unable to uninstall would be worse than
        // leaving some state behind, and the uninstaller makes its own attempt.
        log::warn!("cleanup before uninstall failed, continuing: {error}");
    }

    // /x by product code, and let msiexec own the UI from here. Spawned rather
    // than waited on: this process is about to be removed by the thing it just
    // started.
    std::process::Command::new(msiexec)
        .arg("/x")
        .arg(product_code)
        .spawn()
        .map(|_| ())
        .map_err(|e| format!("Could not start the uninstaller: {e}"))
}
