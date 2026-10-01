//! Removing Lite from the machine.
//!
//! Lite arrives two ways and only one of them can be removed on its own. The
//! standalone installer registers "SwiftTunnel Lite" as its own product, which
//! has an uninstaller. The full app's installer ships Lite as part of itself,
//! and there is no separate product to remove: taking Lite away there means
//! uninstalling SwiftTunnel. Saying so is better than offering a button that
//! quietly does nothing.

/// How Lite got here, and what can be done about it.
pub enum Installed {
    Unknown(String),
    /// Its own product, with this product code.
    Standalone(String),
    /// Part of the full app's installation.
    WithTheFullApp,
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
    match registered_product() {
        Ok(Some(code)) => Installed::Standalone(code),
        Ok(None) => Installed::WithTheFullApp,
        Err(error) => Installed::Unknown(error),
    }
}

fn registered_product() -> Result<Option<String>, String> {
    let exe = std::env::current_exe()
        .map_err(|_| "Could not locate this Lite installation.".to_string())?;
    let folder = exe
        .parent()
        .ok_or("Could not locate this Lite installation.")?;
    swifttunnel_core::msi_uninstall::lite_product_code(folder)
}

pub async fn after_disconnect(
    disconnect: impl std::future::Future<Output = Result<(), String>>,
    uninstall: impl FnOnce() -> Result<(), String> + Send + 'static,
) -> Result<(), String> {
    disconnect.await?;
    tokio::task::spawn_blocking(uninstall).await.map_err(|_| {
        "Uninstall preparation failed. Retry or use Windows Settings > Apps.".to_string()
    })?
}

#[cfg(test)]
mod tests {
    use super::*;
    #[tokio::test]
    async fn disconnect_finishes_before_uninstall_starts() {
        let finished = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
        let check = finished.clone();
        after_disconnect(
            async {
                tokio::task::yield_now().await;
                finished.store(true, std::sync::atomic::Ordering::SeqCst);
                Ok(())
            },
            move || {
                assert!(check.load(std::sync::atomic::Ordering::SeqCst));
                Ok(())
            },
        )
        .await
        .unwrap();
    }
    #[tokio::test]
    async fn failed_disconnect_prevents_cleanup_and_uninstall() {
        let result = after_disconnect(async { Err("disconnect failed".into()) }, || {
            panic!("must not uninstall")
        })
        .await;
        assert_eq!(result.unwrap_err(), "disconnect failed");
    }
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
