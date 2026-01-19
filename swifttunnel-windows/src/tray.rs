//! System tray integration for SwiftTunnel
//!
//! Allows the app to run in the background with a system tray icon

use log::info;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
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

        // Clone for menu event handler
        let show_clone = Arc::clone(&show_window);
        let quit_clone = Arc::clone(&quit_requested);
        let toggle_clone = Arc::clone(&toggle_optimizations);

        // Store menu item IDs for event handling
        let show_id = show_item.id().clone();
        let toggle_id = toggle_item.id().clone();
        let quit_id = quit_item.id().clone();

        // Spawn menu event handler thread
        std::thread::spawn(move || {
            let receiver = MenuEvent::receiver();
            loop {
                if let Ok(event) = receiver.recv() {
                    if event.id == show_id {
                        info!("Tray: Show window requested");
                        show_clone.store(true, Ordering::SeqCst);
                    } else if event.id == toggle_id {
                        info!("Tray: Toggle optimizations requested");
                        toggle_clone.store(true, Ordering::SeqCst);
                    } else if event.id == quit_id {
                        info!("Tray: Quit requested");
                        quit_clone.store(true, Ordering::SeqCst);
                    }
                }
            }
        });

        // Clone for tray icon click handler
        let show_click_clone = Arc::clone(&show_window);

        // Spawn tray icon click handler thread (double-click to show window)
        std::thread::spawn(move || {
            let receiver = TrayIconEvent::receiver();
            loop {
                if let Ok(event) = receiver.recv() {
                    // Show window on double-click (or single click on Windows)
                    match event {
                        TrayIconEvent::Click { button: tray_icon::MouseButton::Left, button_state: tray_icon::MouseButtonState::Up, .. } => {
                            info!("Tray: Icon clicked, showing window");
                            show_click_clone.store(true, Ordering::SeqCst);
                        }
                        TrayIconEvent::DoubleClick { button: tray_icon::MouseButton::Left, .. } => {
                            info!("Tray: Icon double-clicked, showing window");
                            show_click_clone.store(true, Ordering::SeqCst);
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
        })
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

    /// Check if quit was requested
    pub fn check_quit_requested(&self) -> bool {
        self.quit_requested.load(Ordering::SeqCst)
    }

    /// Check if toggle optimizations was requested and reset the flag
    pub fn check_toggle_optimizations(&self) -> bool {
        self.toggle_optimizations.swap(false, Ordering::SeqCst)
    }
}

/// Create a simple default icon (blue square)
fn create_default_icon() -> Result<Icon, String> {
    // Create a simple 32x32 blue icon
    let size = 32u32;
    let mut rgba = vec![0u8; (size * size * 4) as usize];

    // SwiftTunnel blue: #3b82f6 = RGB(59, 130, 246)
    for y in 0..size {
        for x in 0..size {
            let idx = ((y * size + x) * 4) as usize;

            // Create a rounded square effect
            let cx = x as f32 - size as f32 / 2.0;
            let cy = y as f32 - size as f32 / 2.0;
            let dist = (cx * cx + cy * cy).sqrt();

            if dist < (size as f32 / 2.0 - 2.0) {
                // Inner color: SwiftTunnel blue
                rgba[idx] = 59;      // R
                rgba[idx + 1] = 130; // G
                rgba[idx + 2] = 246; // B
                rgba[idx + 3] = 255; // A
            } else if dist < (size as f32 / 2.0) {
                // Border: slightly darker blue
                rgba[idx] = 37;      // R
                rgba[idx + 1] = 99;  // G
                rgba[idx + 2] = 235; // B
                rgba[idx + 3] = 255; // A
            } else {
                // Transparent
                rgba[idx] = 0;
                rgba[idx + 1] = 0;
                rgba[idx + 2] = 0;
                rgba[idx + 3] = 0;
            }
        }
    }

    Icon::from_rgba(rgba, size, size).map_err(|e| format!("Failed to create icon: {}", e))
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
