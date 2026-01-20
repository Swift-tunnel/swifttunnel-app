//! Settings page - App configuration
//!
//! General settings, account, and about information.

use eframe::egui::{self, Ui, Vec2};
use crate::gui::theme::*;
use crate::gui::animations::AnimationManager;
use crate::gui::components::{section_card, toggle_switch, ToggleStyle, key_value_row};
use crate::auth::UserInfo;

/// Settings section tabs
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum SettingsSection {
    General,
    Account,
    About,
}

/// Settings page state
pub struct SettingsPageState<'a> {
    pub minimize_to_tray: bool,
    pub auto_update: bool,
    pub user_info: Option<&'a UserInfo>,
    pub current_section: SettingsSection,
    pub version: &'a str,
}

/// Actions from settings page
pub enum SettingsPageAction {
    None,
    ToggleMinimizeToTray,
    ToggleAutoUpdate,
    Logout,
    CheckForUpdates,
    SwitchSection(SettingsSection),
}

/// Render the settings page
pub fn render_settings_page(
    ui: &mut Ui,
    state: &SettingsPageState,
    animations: &mut AnimationManager,
) -> SettingsPageAction {
    let mut action = SettingsPageAction::None;

    // Section tabs
    ui.horizontal(|ui| {
        let sections = [
            (SettingsSection::General, "⚙", "General"),
            (SettingsSection::Account, "👤", "Account"),
            (SettingsSection::About, "ℹ", "About"),
        ];

        for (section, icon, label) in sections {
            let is_active = state.current_section == section;
            let button = egui::Button::new(
                egui::RichText::new(format!("{} {}", icon, label))
                    .size(12.0)
                    .color(if is_active { TEXT_PRIMARY } else { TEXT_SECONDARY })
            )
            .fill(if is_active { ACCENT_PRIMARY } else { BG_ELEVATED })
            .rounding(8.0)
            .min_size(Vec2::new(100.0, 32.0));

            if ui.add(button).clicked() && !is_active {
                action = SettingsPageAction::SwitchSection(section);
            }
        }
    });

    ui.add_space(16.0);

    // Section content
    match state.current_section {
        SettingsSection::General => {
            action = render_general_settings(ui, state, animations);
        }
        SettingsSection::Account => {
            action = render_account_settings(ui, state, animations);
        }
        SettingsSection::About => {
            render_about_section(ui, state);
        }
    }

    action
}

/// Render general settings
fn render_general_settings(
    ui: &mut Ui,
    state: &SettingsPageState,
    animations: &mut AnimationManager,
) -> SettingsPageAction {
    let mut action = SettingsPageAction::None;

    section_card(ui, "APPLICATION", Some("🖥"), None, |ui| {
        // Minimize to tray
        ui.horizontal(|ui| {
            ui.vertical(|ui| {
                ui.label(egui::RichText::new("Minimize to tray")
                    .size(13.0)
                    .color(TEXT_PRIMARY));
                ui.label(egui::RichText::new("Hide to system tray instead of closing")
                    .size(11.0)
                    .color(TEXT_MUTED));
            });
            ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                if toggle_switch(ui, "minimize_to_tray", state.minimize_to_tray, animations, ToggleStyle::Standard) {
                    action = SettingsPageAction::ToggleMinimizeToTray;
                }
            });
        });

        ui.add_space(12.0);

        // Auto update
        ui.horizontal(|ui| {
            ui.vertical(|ui| {
                ui.label(egui::RichText::new("Auto-update")
                    .size(13.0)
                    .color(TEXT_PRIMARY));
                ui.label(egui::RichText::new("Automatically check for updates on startup")
                    .size(11.0)
                    .color(TEXT_MUTED));
            });
            ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                if toggle_switch(ui, "auto_update", state.auto_update, animations, ToggleStyle::Standard) {
                    action = SettingsPageAction::ToggleAutoUpdate;
                }
            });
        });
    });

    ui.add_space(16.0);

    section_card(ui, "UPDATES", Some("🔄"), None, |ui| {
        ui.horizontal(|ui| {
            ui.label(egui::RichText::new(format!("Current version: v{}", state.version))
                .size(12.0)
                .color(TEXT_SECONDARY));

            ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                if ui.add(
                    egui::Button::new(egui::RichText::new("Check for Updates").size(12.0).color(TEXT_PRIMARY))
                        .fill(BG_ELEVATED)
                        .rounding(6.0)
                ).clicked() {
                    action = SettingsPageAction::CheckForUpdates;
                }
            });
        });
    });

    action
}

/// Render account settings
fn render_account_settings(
    ui: &mut Ui,
    state: &SettingsPageState,
    animations: &mut AnimationManager,
) -> SettingsPageAction {
    let mut action = SettingsPageAction::None;

    section_card(ui, "ACCOUNT", Some("👤"), None, |ui| {
        if let Some(user) = state.user_info {
            // User info
            ui.horizontal(|ui| {
                // Avatar placeholder
                let (rect, _) = ui.allocate_exact_size(Vec2::new(48.0, 48.0), egui::Sense::hover());
                ui.painter().circle_filled(rect.center(), 22.0, ACCENT_PRIMARY.gamma_multiply(0.3));
                ui.painter().circle_stroke(rect.center(), 22.0, egui::Stroke::new(2.0, ACCENT_PRIMARY));

                let font = egui::FontId::proportional(20.0);
                let initial = user.email.chars().next().unwrap_or('?').to_uppercase().to_string();
                let galley = ui.painter().layout_no_wrap(initial, font, ACCENT_PRIMARY);
                let icon_pos = egui::Pos2::new(
                    rect.center().x - galley.size().x / 2.0,
                    rect.center().y - galley.size().y / 2.0,
                );
                ui.painter().galley(icon_pos, galley, ACCENT_PRIMARY);

                ui.add_space(12.0);

                ui.vertical(|ui| {
                    ui.label(egui::RichText::new(&user.email)
                        .size(14.0)
                        .color(TEXT_PRIMARY)
                        .strong());
                    ui.label(egui::RichText::new(&user.id)
                        .size(10.0)
                        .color(TEXT_MUTED));
                });
            });

            ui.add_space(16.0);

            // Logout button
            if ui.add(
                egui::Button::new(egui::RichText::new("Sign Out").size(13.0).color(STATUS_ERROR))
                    .fill(STATUS_ERROR.gamma_multiply(0.15))
                    .stroke(egui::Stroke::new(1.0, STATUS_ERROR.gamma_multiply(0.3)))
                    .rounding(8.0)
                    .min_size(Vec2::new(100.0, 36.0))
            ).clicked() {
                action = SettingsPageAction::Logout;
            }
        } else {
            ui.label(egui::RichText::new("Not signed in")
                .size(13.0)
                .color(TEXT_MUTED));
        }
    });

    action
}

/// Render about section
fn render_about_section(ui: &mut Ui, state: &SettingsPageState) {
    section_card(ui, "ABOUT SWIFTTUNNEL", Some("ℹ"), None, |ui| {
        ui.vertical_centered(|ui| {
            // Logo
            ui.label(egui::RichText::new("🚀").size(48.0));

            ui.add_space(8.0);

            ui.label(egui::RichText::new("SwiftTunnel")
                .size(20.0)
                .color(TEXT_PRIMARY)
                .strong());

            ui.label(egui::RichText::new("Game Booster")
                .size(12.0)
                .color(TEXT_SECONDARY));

            ui.add_space(4.0);

            ui.label(egui::RichText::new(format!("Version {}", state.version))
                .size(11.0)
                .color(TEXT_MUTED));

            ui.add_space(16.0);
        });

        // Info rows
        key_value_row(ui, "Platform", "Windows");
        ui.add_space(4.0);
        key_value_row(ui, "Architecture", "x64");
        ui.add_space(4.0);
        key_value_row(ui, "VPN Protocol", "WireGuard");
        ui.add_space(4.0);
        key_value_row(ui, "Tunnel", "BoringTun + Wintun");

        ui.add_space(16.0);

        ui.vertical_centered(|ui| {
            ui.label(egui::RichText::new("© 2024-2026 SwiftTunnel")
                .size(10.0)
                .color(TEXT_DIMMED));

            ui.add_space(8.0);

            ui.horizontal(|ui| {
                ui.spacing_mut().item_spacing.x = 16.0;

                if ui.add(egui::Hyperlink::from_label_and_url(
                    egui::RichText::new("Website").size(11.0).color(ACCENT_PRIMARY),
                    "https://swifttunnel.net"
                )).clicked() {
                    // Link handled by egui
                }

                if ui.add(egui::Hyperlink::from_label_and_url(
                    egui::RichText::new("Discord").size(11.0).color(ACCENT_PRIMARY),
                    "https://discord.gg/swifttunnel"
                )).clicked() {
                    // Link handled by egui
                }

                if ui.add(egui::Hyperlink::from_label_and_url(
                    egui::RichText::new("Support").size(11.0).color(ACCENT_PRIMARY),
                    "mailto:support@swifttunnel.net"
                )).clicked() {
                    // Link handled by egui
                }
            });
        });
    });
}
