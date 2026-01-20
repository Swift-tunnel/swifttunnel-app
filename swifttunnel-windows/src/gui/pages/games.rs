//! Games page - Game selection and connection stats
//!
//! ExitLag-style game cards with split tunnel toggles.

use eframe::egui::{self, Color32, Ui, Vec2};
use std::collections::HashSet;
use crate::gui::theme::*;
use crate::gui::animations::AnimationManager;
use crate::gui::components::{section_card, game_card, ConnectionStatRow, connection_stats_table, tunneled_processes_list};
use crate::vpn::{GamePreset, ConnectionState};

/// Games page state needed from main app
pub struct GamesPageState<'a> {
    pub vpn_state: &'a ConnectionState,
    pub selected_presets: &'a HashSet<GamePreset>,
    pub tunneled_processes: &'a [String],
}

/// Actions from games page
pub enum GamesPageAction {
    None,
    TogglePreset(GamePreset),
}

/// Render the games page
pub fn render_games_page(
    ui: &mut Ui,
    state: &GamesPageState,
    animations: &mut AnimationManager,
) -> GamesPageAction {
    let mut action = GamesPageAction::None;

    // Game selection section
    action = render_game_selection(ui, state, animations);

    ui.add_space(16.0);

    // Connection stats (when connected)
    if state.vpn_state.is_connected() {
        render_connection_stats(ui, state);
    }

    action
}

/// Render game selection cards
fn render_game_selection(
    ui: &mut Ui,
    state: &GamesPageState,
    animations: &mut AnimationManager,
) -> GamesPageAction {
    let mut action = GamesPageAction::None;

    let enabled_count = state.selected_presets.len();
    let badge = if enabled_count > 0 {
        format!("{} enabled", enabled_count)
    } else {
        "None enabled".to_string()
    };

    section_card(ui, "GAME SELECTION", Some("🎮"), Some(&badge), |ui| {
        ui.label(egui::RichText::new("Select games to route through the VPN tunnel")
            .size(11.0)
            .color(TEXT_MUTED));

        ui.add_space(12.0);

        // Game preset cards in a row
        let is_connected = state.vpn_state.is_connected();
        let presets = [
            (GamePreset::Roblox, "🎮", "Roblox"),
            (GamePreset::Valorant, "🎯", "Valorant"),
            (GamePreset::Fortnite, "🏝", "Fortnite"),
        ];

        ui.horizontal(|ui| {
            ui.spacing_mut().item_spacing.x = 10.0;
            let card_width = (ui.available_width() - 20.0) / 3.0;

            for (preset, icon, name) in presets {
                ui.allocate_ui(Vec2::new(card_width, 100.0), |ui| {
                    let is_selected = state.selected_presets.contains(&preset);

                    if game_card(
                        ui,
                        &format!("{:?}", preset),
                        icon,
                        name,
                        is_selected,
                        false, // Not disabled
                        animations,
                    ) {
                        action = GamesPageAction::TogglePreset(preset);
                    }
                });
            }
        });

        // Info about split tunneling
        ui.add_space(12.0);

        if is_connected {
            egui::Frame::none()
                .fill(STATUS_CONNECTED.gamma_multiply(0.1))
                .rounding(6.0)
                .inner_margin(egui::Margin::symmetric(12.0, 8.0))
                .show(ui, |ui| {
                    ui.horizontal(|ui| {
                        ui.label(egui::RichText::new("✓").size(12.0).color(STATUS_CONNECTED));
                        ui.add_space(6.0);
                        ui.label(egui::RichText::new("Split tunneling active - selected games are routed through VPN")
                            .size(11.0)
                            .color(STATUS_CONNECTED));
                    });
                });
        } else {
            egui::Frame::none()
                .fill(BG_ELEVATED)
                .rounding(6.0)
                .inner_margin(egui::Margin::symmetric(12.0, 8.0))
                .show(ui, |ui| {
                    ui.horizontal(|ui| {
                        ui.label(egui::RichText::new("ℹ").size(12.0).color(TEXT_MUTED));
                        ui.add_space(6.0);
                        ui.label(egui::RichText::new("Connect to VPN to enable split tunneling for selected games")
                            .size(11.0)
                            .color(TEXT_MUTED));
                    });
                });
        }
    });

    action
}

/// Render connection stats table
fn render_connection_stats(ui: &mut Ui, state: &GamesPageState) {
    section_card(ui, "CONNECTION STATS", Some("📊"), None, |ui| {
        if let ConnectionState::Connected { tunneled_processes, server_region, .. } = state.vpn_state {
            if tunneled_processes.is_empty() {
                // Empty state
                ui.vertical_centered(|ui| {
                    ui.add_space(8.0);
                    ui.label(egui::RichText::new("🔍").size(24.0).color(TEXT_DIMMED));
                    ui.add_space(8.0);
                    ui.label(egui::RichText::new("No game processes detected")
                        .size(13.0)
                        .color(TEXT_MUTED));
                    ui.label(egui::RichText::new("Start a selected game to see connection stats")
                        .size(11.0)
                        .color(TEXT_DIMMED));
                    ui.add_space(8.0);
                });
            } else {
                // Show process list (simpler than full bandwidth stats for now)
                // Real-time bandwidth tracking would require driver integration

                ui.label(egui::RichText::new("Tunneled Processes")
                    .size(12.0)
                    .color(TEXT_SECONDARY));

                ui.add_space(8.0);

                for process in tunneled_processes {
                    egui::Frame::none()
                        .fill(BG_ELEVATED)
                        .rounding(6.0)
                        .inner_margin(egui::Margin::symmetric(12.0, 8.0))
                        .show(ui, |ui| {
                            ui.horizontal(|ui| {
                                // Status indicator
                                let (rect, _) = ui.allocate_exact_size(Vec2::new(8.0, 8.0), egui::Sense::hover());
                                ui.painter().circle_filled(rect.center(), 4.0, STATUS_CONNECTED);

                                ui.add_space(8.0);

                                // Process name
                                ui.label(egui::RichText::new(process)
                                    .size(12.0)
                                    .color(TEXT_PRIMARY));

                                ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                                    // Server
                                    let flag = get_region_flag(server_region);
                                    ui.label(egui::RichText::new(format!("{} {}", flag, get_region_name(server_region)))
                                        .size(11.0)
                                        .color(TEXT_SECONDARY));

                                    ui.add_space(8.0);

                                    // Protocol badge
                                    egui::Frame::none()
                                        .fill(ACCENT_CYAN.gamma_multiply(0.15))
                                        .rounding(4.0)
                                        .inner_margin(egui::Margin::symmetric(6.0, 2.0))
                                        .show(ui, |ui| {
                                            ui.label(egui::RichText::new("UDP")
                                                .size(10.0)
                                                .color(ACCENT_CYAN)
                                                .strong());
                                        });
                                });
                            });
                        });

                    ui.add_space(4.0);
                }

                // Note about bandwidth stats
                ui.add_space(8.0);
                ui.label(egui::RichText::new("• Real-time bandwidth stats coming in a future update")
                    .size(10.0)
                    .color(TEXT_DIMMED));
            }
        }
    });
}

/// Get game icon for preset
pub fn get_game_icon(preset: &GamePreset) -> &'static str {
    match preset {
        GamePreset::Roblox => "🎮",
        GamePreset::Valorant => "🎯",
        GamePreset::Fortnite => "🏝",
    }
}

/// Get game name for preset
pub fn get_game_name(preset: &GamePreset) -> &'static str {
    match preset {
        GamePreset::Roblox => "Roblox",
        GamePreset::Valorant => "Valorant",
        GamePreset::Fortnite => "Fortnite",
    }
}
