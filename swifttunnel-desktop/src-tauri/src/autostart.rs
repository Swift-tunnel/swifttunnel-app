//! Starting the full app with Windows.
//!
//! The registry work is in core, because SwiftTunnel Lite offers the same
//! switch and neither client should have its own idea of how to write a Run
//! entry. What stays here is the value name this client registers under and
//! the Tauri-shaped signature its caller expects.

use tauri::AppHandle;

static STARTUP_PUBLICATION: parking_lot::Mutex<()> = parking_lot::Mutex::new(());

pub(crate) struct StartupPublication(parking_lot::MutexGuard<'static, ()>);

pub(crate) fn begin_startup_publication() -> StartupPublication {
    StartupPublication(STARTUP_PUBLICATION.lock())
}

impl StartupPublication {
    pub(crate) fn sync(&self, enabled: bool) -> Result<(), String> {
        let _guard = &self.0;
        sync(RUN_VALUE_APP, enabled)
    }
}

// Re-exported under the names this crate already used, so the uninstall and
// driver-install paths that snapshot the entry keep working unchanged.
pub(crate) use swifttunnel_core::autostart::RUN_VALUE_APP as RUN_VALUE_NAME;
pub use swifttunnel_core::autostart::{RUN_KEY_PATH, launched_from_startup_flag};
use swifttunnel_core::autostart::{RUN_VALUE_APP, sync_run_on_startup as sync};

pub fn sync_run_on_startup(_app: &AppHandle, enabled: bool) -> Result<(), String> {
    begin_startup_publication().sync(enabled)
}
