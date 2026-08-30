//! Starting the full app with Windows.
//!
//! The registry work is in core, because SwiftTunnel Lite offers the same
//! switch and neither client should have its own idea of how to write a Run
//! entry. What stays here is the value name this client registers under and
//! the Tauri-shaped signature its caller expects.

use tauri::AppHandle;

// Re-exported under the names this crate already used, so the uninstall and
// driver-install paths that snapshot the entry keep working unchanged.
pub(crate) use swifttunnel_core::autostart::RUN_VALUE_APP as RUN_VALUE_NAME;
pub use swifttunnel_core::autostart::{RUN_KEY_PATH, launched_from_startup_flag};
use swifttunnel_core::autostart::{RUN_VALUE_APP, sync_run_on_startup as sync};

pub fn sync_run_on_startup(_app: &AppHandle, enabled: bool) -> Result<(), String> {
    sync(RUN_VALUE_APP, enabled)
}
