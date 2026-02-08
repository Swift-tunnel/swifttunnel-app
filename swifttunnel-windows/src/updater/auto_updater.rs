//! Velopack-based auto-updater
//!
//! Checks for updates from GitHub Releases via Velopack's HttpSource.
//! Falls back gracefully when not installed via Velopack (dev/debug builds).

use super::types::{UpdateInfo, UpdateState};
use log::{info, warn, error};
use std::sync::{Arc, Mutex};

/// GitHub Releases base URL for update feed
/// Velopack expects releases.{channel}.json at this URL
const RELEASES_URL: &str = "https://github.com/Swift-tunnel/swifttunnel-app/releases/latest/download";

/// Result of the auto-update check
#[derive(Clone)]
pub enum AutoUpdateResult {
    NoUpdate,
    UpdateInstalled,
    Failed(String),
    Skipped,
}

/// Run the auto-updater at startup
///
/// With Velopack, pending updates are applied automatically by VelopackApp::build().run()
/// in main(). This function just checks for NEW updates in the background.
/// No splash screen needed - the check is fast and non-blocking.
pub fn run_auto_updater() -> AutoUpdateResult {
    info!("Checking for updates via Velopack...");

    // Try to create UpdateManager - will fail if not installed via Velopack
    let um = match create_update_manager() {
        Some(um) => um,
        None => {
            info!("Not installed via Velopack (dev mode), skipping update check");
            return AutoUpdateResult::Skipped;
        }
    };

    // Check for updates synchronously (this is fast - just fetches a JSON file)
    match um.check_for_updates() {
        Ok(velopack::UpdateCheck::UpdateAvailable(update)) => {
            let version = update.TargetFullRelease.Version.to_string();
            info!("Update available: v{}", version);

            // Download and apply immediately at startup
            info!("Downloading update...");
            match um.download_updates(&update, None) {
                Ok(()) => {
                    info!("Update downloaded, applying and restarting...");
                    match um.apply_updates_and_restart(&update) {
                        Ok(()) => {
                            // This line should not be reached - process restarts
                            AutoUpdateResult::UpdateInstalled
                        }
                        Err(e) => {
                            error!("Failed to apply update: {}", e);
                            AutoUpdateResult::Failed(format!("Failed to apply update: {}", e))
                        }
                    }
                }
                Err(e) => {
                    error!("Failed to download update: {}", e);
                    AutoUpdateResult::Failed(format!("Download failed: {}", e))
                }
            }
        }
        Ok(velopack::UpdateCheck::NoUpdateAvailable) => {
            info!("Already on latest version");
            AutoUpdateResult::NoUpdate
        }
        Ok(velopack::UpdateCheck::RemoteIsEmpty) => {
            info!("No releases found");
            AutoUpdateResult::NoUpdate
        }
        Err(e) => {
            warn!("Update check failed: {}", e);
            AutoUpdateResult::Failed(format!("Update check failed: {}", e))
        }
    }
}

/// Create a Velopack UpdateManager, returning None if not installed via Velopack
fn create_update_manager() -> Option<velopack::UpdateManager> {
    let source = velopack::sources::HttpSource::new(RELEASES_URL);
    match velopack::UpdateManager::new(source, None, None) {
        Ok(um) => Some(um),
        Err(e) => {
            info!("Velopack UpdateManager unavailable: {} (expected in dev mode)", e);
            None
        }
    }
}

/// Check for updates in the background and update shared state
/// Used by the GUI for manual update checks
pub fn check_for_updates_background(update_state: Arc<Mutex<UpdateState>>) {
    std::thread::spawn(move || {
        let um = match create_update_manager() {
            Some(um) => um,
            None => {
                if let Ok(mut state) = update_state.lock() {
                    *state = UpdateState::Failed("Not installed via Velopack".to_string());
                }
                return;
            }
        };

        match um.check_for_updates() {
            Ok(velopack::UpdateCheck::UpdateAvailable(update)) => {
                let version = update.TargetFullRelease.Version.to_string();
                info!("Update available: v{}", version);
                if let Ok(mut state) = update_state.lock() {
                    *state = UpdateState::Available(UpdateInfo {
                        version,
                    });
                }
            }
            Ok(_) => {
                info!("Already on latest version");
                if let Ok(mut state) = update_state.lock() {
                    *state = UpdateState::UpToDate;
                }
            }
            Err(e) => {
                error!("Update check failed: {}", e);
                if let Ok(mut state) = update_state.lock() {
                    *state = UpdateState::Failed(e.to_string());
                }
            }
        }
    });
}

/// Download and apply an update in the background
/// Updates shared state with progress
pub fn download_and_apply_update(update_state: Arc<Mutex<UpdateState>>, version: String) {
    std::thread::spawn(move || {
        let um = match create_update_manager() {
            Some(um) => um,
            None => {
                if let Ok(mut state) = update_state.lock() {
                    *state = UpdateState::Failed("Not installed via Velopack".to_string());
                }
                return;
            }
        };

        // Re-check to get the update info
        let update = match um.check_for_updates() {
            Ok(velopack::UpdateCheck::UpdateAvailable(u)) => u,
            _ => {
                if let Ok(mut state) = update_state.lock() {
                    *state = UpdateState::Failed("Update no longer available".to_string());
                }
                return;
            }
        };

        let info = UpdateInfo { version: version.clone() };

        // Set downloading state
        if let Ok(mut state) = update_state.lock() {
            *state = UpdateState::Downloading {
                info: info.clone(),
                progress: 0.0,
            };
        }

        // Create progress channel
        let (tx, rx) = std::sync::mpsc::channel::<i16>();
        let progress_state = Arc::clone(&update_state);
        let progress_info = info.clone();

        // Spawn progress monitor thread
        let progress_thread = std::thread::spawn(move || {
            while let Ok(pct) = rx.recv() {
                let progress = pct as f32 / 100.0;
                if let Ok(mut state) = progress_state.lock() {
                    *state = UpdateState::Downloading {
                        info: progress_info.clone(),
                        progress,
                    };
                }
            }
        });

        // Download using Velopack's sync Sender wrapper
        // Note: Velopack uses std::sync::mpsc::Sender<i16> for progress
        match um.download_updates(&update, Some(tx)) {
            Ok(()) => {
                // Wait for progress thread to finish
                let _ = progress_thread.join();

                info!("Update downloaded, applying and restarting...");
                match um.apply_updates_and_restart(&update) {
                    Ok(()) => {
                        // Process should restart - this line shouldn't be reached
                    }
                    Err(e) => {
                        error!("Failed to apply update: {}", e);
                        if let Ok(mut state) = update_state.lock() {
                            *state = UpdateState::Failed(format!("Failed to apply: {}", e));
                        }
                    }
                }
            }
            Err(e) => {
                error!("Download failed: {}", e);
                let _ = progress_thread.join();
                if let Ok(mut state) = update_state.lock() {
                    *state = UpdateState::Failed(format!("Download failed: {}", e));
                }
            }
        }
    });
}
