//! Starting the full app with Windows.
//!
//! The registry work is in core, because SwiftTunnel Lite offers the same
//! switch and neither client should have its own idea of how to write a Run
//! entry. What stays here is the value name this client registers under and
//! the Tauri-shaped signature its caller expects.

use tauri::AppHandle;

static STARTUP_PREFERENCE: std::sync::atomic::AtomicU8 = std::sync::atomic::AtomicU8::new(0);
static STARTUP_GENERATION: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);

static STARTUP_PUBLICATION: parking_lot::Mutex<()> = parking_lot::Mutex::new(());

pub(crate) struct StartupPublication(parking_lot::MutexGuard<'static, ()>);

pub(crate) fn begin_startup_publication() -> StartupPublication {
    StartupPublication(STARTUP_PUBLICATION.lock())
}

fn note_startup_preference(
    previous: &std::sync::atomic::AtomicU8,
    generation: &std::sync::atomic::AtomicU64,
    enabled: bool,
) {
    use std::sync::atomic::Ordering;
    let preference = if enabled { 2 } else { 1 };
    if previous.swap(preference, Ordering::Relaxed) != preference {
        generation.fetch_add(1, Ordering::Relaxed);
    }
}

impl StartupPublication {
    pub(crate) fn generation(&self) -> u64 {
        std::sync::atomic::AtomicU64::load(
            &STARTUP_GENERATION,
            std::sync::atomic::Ordering::Relaxed,
        )
    }

    pub(crate) fn sync(&self, enabled: bool) -> Result<(), String> {
        let _guard = &self.0;
        // Count preference transitions, including Off -> On -> Off. A stale
        // Repair undo must not overwrite a later choice that happens to match
        // its old registry value. Theme saves of the same preference do not
        // invalidate undo. The publication lock serializes these atomics.
        note_startup_preference(&STARTUP_PREFERENCE, &STARTUP_GENERATION, enabled);
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

#[cfg(test)]
mod tests {
    #[test]
    fn only_preference_transitions_invalidate_a_startup_undo() {
        use std::sync::atomic::{AtomicU8, AtomicU64, Ordering};
        let previous = AtomicU8::new(0);
        let generation = AtomicU64::new(0);
        super::note_startup_preference(&previous, &generation, true);
        super::note_startup_preference(&previous, &generation, true);
        assert_eq!(generation.load(Ordering::Relaxed), 1);
        super::note_startup_preference(&previous, &generation, false);
        super::note_startup_preference(&previous, &generation, true);
        assert_eq!(generation.load(Ordering::Relaxed), 3);
    }
}
