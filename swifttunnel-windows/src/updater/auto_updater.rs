//! Discord-like auto-updater that runs before the main app
//!
//! Shows a splash screen while checking/downloading updates,
//! then auto-installs and restarts if an update is available.

use super::{UpdateChecker, download_update, download_checksum, verify_checksum, install_update};
use eframe::egui;
use log::{info, error};
use std::sync::{Arc, Mutex};
use std::path::PathBuf;

/// Auto-updater state
#[derive(Clone, Debug)]
pub enum AutoUpdateState {
    Checking,
    NoUpdate,
    Downloading { progress: f32, downloaded: u64, total: u64 },
    Verifying,
    Installing,
    Failed(String),
    RestartRequired(PathBuf),
}

/// Result of the auto-update check
#[derive(Clone)]
pub enum AutoUpdateResult {
    NoUpdate,
    UpdateInstalled,
    Failed(String),
    Skipped, // User chose to skip or updates disabled
}

/// Run the auto-updater splash screen
/// Returns true if app should continue, false if it should exit (for restart)
pub fn run_auto_updater() -> AutoUpdateResult {
    // Create tokio runtime for async operations
    let rt = tokio::runtime::Runtime::new().expect("Failed to create tokio runtime");

    // Shared state for the updater UI
    let state = Arc::new(Mutex::new(AutoUpdateState::Checking));
    let state_clone = Arc::clone(&state);
    let result = Arc::new(Mutex::new(None::<AutoUpdateResult>));
    let result_clone = Arc::clone(&result);

    // Start the update check in background
    let state_for_task = Arc::clone(&state);
    let result_for_task = Arc::clone(&result);

    rt.spawn(async move {
        match check_and_update(state_for_task).await {
            Ok(update_result) => {
                if let Ok(mut r) = result_for_task.lock() {
                    *r = Some(update_result);
                }
            }
            Err(e) => {
                if let Ok(mut r) = result_for_task.lock() {
                    *r = Some(AutoUpdateResult::Failed(e));
                }
            }
        }
    });

    // Create minimal splash window
    let options = eframe::NativeOptions {
        viewport: egui::ViewportBuilder::default()
            .with_title("SwiftTunnel")
            .with_inner_size([400.0, 150.0])
            .with_resizable(false)
            .with_decorations(false)
            .with_transparent(false)
            .with_always_on_top(),
        renderer: eframe::Renderer::Glow,
        ..Default::default()
    };

    let app = UpdaterSplash {
        state: state_clone,
        result: result_clone,
        should_close: false,
    };

    // Run the splash screen
    let _ = eframe::run_native(
        "SwiftTunnel Updater",
        options,
        Box::new(move |_cc| Ok(Box::new(app))),
    );

    // Get the result - must save to variable to avoid borrow issues
    let final_result = {
        if let Ok(r) = result.lock() {
            r.clone().unwrap_or(AutoUpdateResult::NoUpdate)
        } else {
            AutoUpdateResult::NoUpdate
        }
    };
    final_result
}

/// Check for updates and download/install if available
async fn check_and_update(state: Arc<Mutex<AutoUpdateState>>) -> Result<AutoUpdateResult, String> {
    // Small delay to show the "Checking" state
    tokio::time::sleep(tokio::time::Duration::from_millis(500)).await;

    // Check for updates
    let checker = UpdateChecker::new();
    let update_info = match checker.check_for_update().await {
        Ok(Some(info)) => info,
        Ok(None) => {
            info!("No updates available");
            if let Ok(mut s) = state.lock() {
                *s = AutoUpdateState::NoUpdate;
            }
            tokio::time::sleep(tokio::time::Duration::from_millis(300)).await;
            return Ok(AutoUpdateResult::NoUpdate);
        }
        Err(e) => {
            // Don't block app launch on update check failure
            error!("Update check failed: {}", e);
            if let Ok(mut s) = state.lock() {
                *s = AutoUpdateState::NoUpdate;
            }
            return Ok(AutoUpdateResult::NoUpdate);
        }
    };

    info!("Update available: v{}", update_info.version);

    // Extract filename from URL
    let filename = update_info.download_url
        .split('/')
        .last()
        .unwrap_or("SwiftTunnel-update.msi")
        .to_string();

    // Update state to downloading
    if let Ok(mut s) = state.lock() {
        *s = AutoUpdateState::Downloading { progress: 0.0, downloaded: 0, total: update_info.size };
    }

    // Download with progress
    let state_for_progress = Arc::clone(&state);

    let progress_callback = Box::new(move |downloaded: u64, total: u64| {
        let progress = if total > 0 {
            downloaded as f32 / total as f32
        } else {
            0.0
        };
        if let Ok(mut s) = state_for_progress.lock() {
            *s = AutoUpdateState::Downloading { progress, downloaded, total };
        }
    });

    let msi_path = download_update(&update_info.download_url, &filename, Some(progress_callback))
        .await
        .map_err(|e| format!("Download failed: {}", e))?;

    // Verify checksum if available
    if let Some(checksum_url) = &update_info.checksum_url {
        if let Ok(mut s) = state.lock() {
            *s = AutoUpdateState::Verifying;
        }

        match download_checksum(checksum_url).await {
            Ok(expected_hash) => {
                match verify_checksum(&msi_path, &expected_hash).await {
                    Ok(true) => {
                        info!("Checksum verified");
                    }
                    Ok(false) => {
                        // Clean up bad file
                        let _ = std::fs::remove_file(&msi_path);
                        if let Ok(mut s) = state.lock() {
                            *s = AutoUpdateState::Failed("Checksum verification failed".to_string());
                        }
                        return Err("Checksum verification failed".to_string());
                    }
                    Err(e) => {
                        // Continue anyway if checksum verification had I/O error
                        info!("Checksum verification error: {}", e);
                    }
                }
            }
            Err(e) => {
                // Continue anyway if checksum download fails
                info!("Could not verify checksum: {}", e);
            }
        }
    }

    // Install update
    if let Ok(mut s) = state.lock() {
        *s = AutoUpdateState::Installing;
    }

    tokio::time::sleep(tokio::time::Duration::from_millis(500)).await;

    match install_update(&msi_path) {
        Ok(()) => {
            info!("Update installer launched");
            if let Ok(mut s) = state.lock() {
                *s = AutoUpdateState::RestartRequired(msi_path);
            }
            Ok(AutoUpdateResult::UpdateInstalled)
        }
        Err(e) => {
            error!("Failed to install update: {}", e);
            if let Ok(mut s) = state.lock() {
                *s = AutoUpdateState::Failed(e.clone());
            }
            Err(e)
        }
    }
}

/// Splash screen app for the updater
struct UpdaterSplash {
    state: Arc<Mutex<AutoUpdateState>>,
    result: Arc<Mutex<Option<AutoUpdateResult>>>,
    should_close: bool,
}

impl eframe::App for UpdaterSplash {
    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        // Check if we should close
        if let Ok(r) = self.result.lock() {
            if r.is_some() && !self.should_close {
                self.should_close = true;
                // Give a moment to show final state
                ctx.request_repaint_after(std::time::Duration::from_millis(300));
            }
        }

        if self.should_close {
            ctx.send_viewport_cmd(egui::ViewportCommand::Close);
            return;
        }

        // Dark theme colors
        let bg_color = egui::Color32::from_rgb(30, 30, 35);
        let text_color = egui::Color32::from_rgb(230, 230, 230);
        let accent_color = egui::Color32::from_rgb(88, 166, 255);
        let progress_bg = egui::Color32::from_rgb(50, 50, 55);

        egui::CentralPanel::default()
            .frame(egui::Frame::none().fill(bg_color).inner_margin(30.0))
            .show(ctx, |ui| {
                ui.vertical_centered(|ui| {
                    // App title
                    ui.add_space(10.0);
                    ui.label(egui::RichText::new("SwiftTunnel")
                        .size(24.0)
                        .color(text_color)
                        .strong());

                    ui.add_space(20.0);

                    // Status based on state
                    let current_state = self.state.lock().map(|s| s.clone()).unwrap_or(AutoUpdateState::Checking);

                    match current_state {
                        AutoUpdateState::Checking => {
                            ui.label(egui::RichText::new("Checking for updates...")
                                .size(14.0)
                                .color(text_color));
                            ui.add_space(15.0);
                            ui.spinner();
                        }
                        AutoUpdateState::NoUpdate => {
                            ui.label(egui::RichText::new("Starting...")
                                .size(14.0)
                                .color(text_color));
                            ui.add_space(15.0);
                            ui.spinner();
                        }
                        AutoUpdateState::Downloading { progress, downloaded, total } => {
                            ui.label(egui::RichText::new("Downloading update...")
                                .size(14.0)
                                .color(text_color));
                            ui.add_space(10.0);

                            // Progress bar
                            let progress_rect = ui.available_rect_before_wrap();
                            let bar_height = 8.0;
                            let bar_rect = egui::Rect::from_min_size(
                                egui::pos2(progress_rect.left() + 20.0, progress_rect.top()),
                                egui::vec2(progress_rect.width() - 40.0, bar_height),
                            );

                            ui.painter().rect_filled(bar_rect, 4.0, progress_bg);

                            let filled_width = bar_rect.width() * progress;
                            let filled_rect = egui::Rect::from_min_size(
                                bar_rect.min,
                                egui::vec2(filled_width, bar_height),
                            );
                            ui.painter().rect_filled(filled_rect, 4.0, accent_color);

                            ui.add_space(bar_height + 10.0);

                            // Progress text
                            let mb_downloaded = downloaded as f64 / 1_000_000.0;
                            let mb_total = total as f64 / 1_000_000.0;
                            ui.label(egui::RichText::new(format!("{:.1} / {:.1} MB", mb_downloaded, mb_total))
                                .size(11.0)
                                .color(egui::Color32::from_rgb(150, 150, 150)));
                        }
                        AutoUpdateState::Verifying => {
                            ui.label(egui::RichText::new("Verifying update...")
                                .size(14.0)
                                .color(text_color));
                            ui.add_space(15.0);
                            ui.spinner();
                        }
                        AutoUpdateState::Installing => {
                            ui.label(egui::RichText::new("Installing update...")
                                .size(14.0)
                                .color(text_color));
                            ui.add_space(15.0);
                            ui.spinner();
                        }
                        AutoUpdateState::Failed(msg) => {
                            ui.label(egui::RichText::new("Update failed")
                                .size(14.0)
                                .color(egui::Color32::from_rgb(255, 100, 100)));
                            ui.add_space(5.0);
                            ui.label(egui::RichText::new(&msg)
                                .size(11.0)
                                .color(egui::Color32::from_rgb(150, 150, 150)));
                        }
                        AutoUpdateState::RestartRequired(_) => {
                            ui.label(egui::RichText::new("Restarting...")
                                .size(14.0)
                                .color(text_color));
                            ui.add_space(15.0);
                            ui.spinner();
                        }
                    }
                });
            });

        // Request continuous repaints for smooth progress
        ctx.request_repaint();
    }
}
