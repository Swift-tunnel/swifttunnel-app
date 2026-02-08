//! System tray integration for SwiftTunnel
//!
//! Allows the app to run in the background with a system tray icon

use log::info;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;
use tray_icon::menu::{Menu, MenuEvent, MenuItem, PredefinedMenuItem};
use tray_icon::{Icon, TrayIcon, TrayIconBuilder, TrayIconEvent};

/// System tray manager
pub struct SystemTray {
    _tray_icon: TrayIcon,
    pub show_window: Arc<AtomicBool>,
    pub quit_requested: Arc<AtomicBool>,
    pub toggle_optimizations: Arc<AtomicBool>,
    /// Whether minimize to tray is enabled
    pub minimize_to_tray: Arc<AtomicBool>,
    /// Stop flag for background threads
    stop_threads: Arc<AtomicBool>,
}

impl SystemTray {
    /// Create and initialize the system tray
    pub fn new(optimizations_active: bool) -> Result<Self, String> {
        // Create menu items
        let show_item = MenuItem::new("Show SwiftTunnel", true, None);
        let toggle_text = if optimizations_active {
            "Disable Optimizations"
        } else {
            "Enable Optimizations"
        };
        let toggle_item = MenuItem::new(toggle_text, true, None);
        let separator = PredefinedMenuItem::separator();
        let quit_item = MenuItem::new("Quit", true, None);

        // Build menu
        let menu = Menu::new();
        menu.append(&show_item).map_err(|e| e.to_string())?;
        menu.append(&toggle_item).map_err(|e| e.to_string())?;
        menu.append(&separator).map_err(|e| e.to_string())?;
        menu.append(&quit_item).map_err(|e| e.to_string())?;

        // Create tray icon (simple colored square as placeholder)
        let icon = create_default_icon()?;

        // Build tray
        let tray_icon = TrayIconBuilder::new()
            .with_menu(Box::new(menu))
            .with_tooltip("SwiftTunnel FPS Booster")
            .with_icon(icon)
            .build()
            .map_err(|e| format!("Failed to create tray icon: {}", e))?;

        let show_window = Arc::new(AtomicBool::new(false));
        let quit_requested = Arc::new(AtomicBool::new(false));
        let toggle_optimizations = Arc::new(AtomicBool::new(false));
        let minimize_to_tray = Arc::new(AtomicBool::new(true)); // Enabled by default
        let stop_threads = Arc::new(AtomicBool::new(false));

        // Clone for menu event handler
        let show_clone = Arc::clone(&show_window);
        let quit_clone = Arc::clone(&quit_requested);
        let toggle_clone = Arc::clone(&toggle_optimizations);
        let stop_clone1 = Arc::clone(&stop_threads);

        // Store menu item IDs for event handling
        let show_id = show_item.id().clone();
        let toggle_id = toggle_item.id().clone();
        let quit_id = quit_item.id().clone();

        // Spawn menu event handler thread with timeout-based polling
        std::thread::spawn(move || {
            let receiver = MenuEvent::receiver();
            loop {
                // Check stop flag
                if stop_clone1.load(Ordering::SeqCst) {
                    info!("Tray menu event thread stopping");
                    break;
                }

                // Use recv_timeout to allow periodic stop flag checks
                if let Ok(event) = receiver.recv_timeout(Duration::from_millis(500)) {
                    if event.id == show_id {
                        info!("Tray: Show window requested");
                        show_clone.store(true, Ordering::SeqCst);
                        restore_window();
                    } else if event.id == toggle_id {
                        info!("Tray: Toggle optimizations requested");
                        toggle_clone.store(true, Ordering::SeqCst);
                    } else if event.id == quit_id {
                        info!("Tray: Quit requested");
                        quit_clone.store(true, Ordering::SeqCst);

                        // Fallback: Force exit after 2s if GUI doesn't respond (window may be hidden)
                        std::thread::spawn(|| {
                            std::thread::sleep(std::time::Duration::from_secs(2));
                            log::warn!("Tray: Fallback exit - GUI did not process quit in time");
                            std::process::exit(0);
                        });
                    }
                }
            }
        });

        // Clone for tray icon click handler
        let show_click_clone = Arc::clone(&show_window);
        let stop_clone2 = Arc::clone(&stop_threads);

        // Spawn tray icon click handler thread with timeout-based polling
        std::thread::spawn(move || {
            let receiver = TrayIconEvent::receiver();
            loop {
                // Check stop flag
                if stop_clone2.load(Ordering::SeqCst) {
                    info!("Tray click event thread stopping");
                    break;
                }

                // Use recv_timeout to allow periodic stop flag checks
                if let Ok(event) = receiver.recv_timeout(Duration::from_millis(500)) {
                    // Show window on double-click (or single click on Windows)
                    match event {
                        TrayIconEvent::Click { button: tray_icon::MouseButton::Left, button_state: tray_icon::MouseButtonState::Up, .. } => {
                            info!("Tray: Icon clicked, showing window");
                            show_click_clone.store(true, Ordering::SeqCst);
                            restore_window();
                        }
                        TrayIconEvent::DoubleClick { button: tray_icon::MouseButton::Left, .. } => {
                            info!("Tray: Icon double-clicked, showing window");
                            show_click_clone.store(true, Ordering::SeqCst);
                            restore_window();
                        }
                        _ => {}
                    }
                }
            }
        });

        info!("System tray initialized");

        Ok(Self {
            _tray_icon: tray_icon,
            show_window,
            quit_requested,
            toggle_optimizations,
            minimize_to_tray,
            stop_threads,
        })
    }

    /// Signal background threads to stop
    pub fn shutdown(&self) {
        info!("Shutting down system tray threads...");
        self.stop_threads.store(true, Ordering::SeqCst);
    }

    /// Set whether minimize to tray is enabled
    pub fn set_minimize_to_tray(&self, enabled: bool) {
        self.minimize_to_tray.store(enabled, Ordering::SeqCst);
    }

    /// Check if minimize to tray is enabled
    pub fn is_minimize_to_tray_enabled(&self) -> bool {
        self.minimize_to_tray.load(Ordering::SeqCst)
    }

    /// Check if show window was requested and reset the flag
    pub fn check_show_window(&self) -> bool {
        self.show_window.swap(false, Ordering::SeqCst)
    }

    /// Check if quit was requested and reset the flag
    pub fn check_quit_requested(&self) -> bool {
        self.quit_requested.swap(false, Ordering::SeqCst)
    }

    /// Check if toggle optimizations was requested and reset the flag
    pub fn check_toggle_optimizations(&self) -> bool {
        self.toggle_optimizations.swap(false, Ordering::SeqCst)
    }
}

impl Drop for SystemTray {
    fn drop(&mut self) {
        info!("SystemTray dropping, signaling threads to stop...");
        self.stop_threads.store(true, Ordering::SeqCst);
        // Give threads a moment to notice the stop flag
        std::thread::sleep(Duration::from_millis(100));
    }
}

/// Restore the window using Win32 APIs directly.
///
/// This is called from tray event handler threads so that window restoration
/// works even when the eframe `update()` loop is not running (i.e., when the
/// window is hidden via `ViewportCommand::Visible(false)`).
#[cfg(target_os = "windows")]
fn restore_window() {
    use windows::Win32::UI::WindowsAndMessaging::{
        FindWindowW, SetForegroundWindow, ShowWindow, SW_RESTORE, SW_SHOW,
    };
    use windows::core::PCWSTR;

    let class_name: Vec<u16> = "eframe\0".encode_utf16().collect();
    unsafe {
        if let Ok(hwnd) = FindWindowW(PCWSTR(class_name.as_ptr()), PCWSTR::null()) {
            if !hwnd.is_invalid() {
                let _ = ShowWindow(hwnd, SW_RESTORE);
                let _ = ShowWindow(hwnd, SW_SHOW);
                let _ = SetForegroundWindow(hwnd);
            }
        }
    }
}

/// Create the system tray icon from embedded PNG
fn create_default_icon() -> Result<Icon, String> {
    // Load the embedded logo PNG
    let logo_bytes = include_bytes!("../assets/logo.png");

    let img = image::load_from_memory(logo_bytes)
        .map_err(|e| format!("Failed to decode logo PNG: {}", e))?;

    // Resize to 32x32 for system tray
    let resized = img.resize_exact(32, 32, image::imageops::FilterType::Lanczos3);
    let rgba = resized.to_rgba8();

    Icon::from_rgba(rgba.into_raw(), 32, 32)
        .map_err(|e| format!("Failed to create tray icon: {}", e))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_create_default_icon() {
        let icon = create_default_icon();
        assert!(icon.is_ok());
    }
}
