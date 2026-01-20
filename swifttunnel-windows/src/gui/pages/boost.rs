//! Boost page - FPS optimizations and game settings
//!
//! 3-column card layout for boost toggles.

use eframe::egui::{self, Ui, Vec2};
use std::collections::HashSet;
use crate::gui::theme::*;
use crate::gui::animations::AnimationManager;
use crate::gui::components::{section_card, preset_card, boost_toggle, tier_badge, toggle_switch, ToggleStyle};
use crate::structs::{Config, OptimizationProfile, GraphicsQuality};

/// Boost page state needed from main app
pub struct BoostPageState<'a> {
    pub config: &'a Config,
    pub selected_profile: OptimizationProfile,
    pub optimizations_active: bool,
    pub expanded_info: &'a HashSet<String>,
}

/// Actions from boost page
pub enum BoostPageAction {
    None,
    ToggleOptimizations,
    SelectProfile(OptimizationProfile),
    ToggleSetting(BoostSetting),
    ToggleExpand(String),
    SetTargetFps(u32),
    SetGraphicsQuality(GraphicsQuality),
}

/// Individual boost settings
#[derive(Clone, Copy, Debug)]
pub enum BoostSetting {
    HighPriority,
    TimerResolution,
    MMCSS,
    GameMode,
    DisableNagle,
    DisableThrottling,
    OptimizeMTU,
}

/// Render the boost page
pub fn render_boost_page(
    ui: &mut Ui,
    state: &BoostPageState,
    animations: &mut AnimationManager,
) -> BoostPageAction {
    // Master toggle
    let mut action = render_master_toggle(ui, state, animations);

    ui.add_space(16.0);

    // Profile presets
    if let BoostPageAction::SelectProfile(profile) = render_profile_presets(ui, state, animations) {
        action = BoostPageAction::SelectProfile(profile);
    }

    ui.add_space(16.0);

    // System optimizations (3-column grid)
    if let result @ BoostPageAction::ToggleSetting(_) | result @ BoostPageAction::ToggleExpand(_) = render_system_optimizations(ui, state, animations) {
        action = result;
    }

    ui.add_space(16.0);

    // Roblox-specific settings
    if let result @ BoostPageAction::SetTargetFps(_) | result @ BoostPageAction::SetGraphicsQuality(_) = render_roblox_settings(ui, state, animations) {
        action = result;
    }

    action
}

/// Render master optimizations toggle
fn render_master_toggle(
    ui: &mut Ui,
    state: &BoostPageState,
    animations: &mut AnimationManager,
) -> BoostPageAction {
    let mut action = BoostPageAction::None;

    egui::Frame::none()
        .fill(if state.optimizations_active { ACCENT_PRIMARY.gamma_multiply(0.1) } else { BG_CARD })
        .stroke(egui::Stroke::new(1.0, if state.optimizations_active { ACCENT_PRIMARY.gamma_multiply(0.3) } else { BG_ELEVATED }))
        .rounding(CARD_ROUNDING)
        .inner_margin(CONTENT_PADDING_SM)
        .show(ui, |ui| {
            ui.horizontal(|ui| {
                ui.vertical(|ui| {
                    ui.label(egui::RichText::new("FPS BOOST")
                        .size(14.0)
                        .color(TEXT_PRIMARY)
                        .strong());
                    ui.label(egui::RichText::new("Enable system optimizations for better gaming performance")
                        .size(11.0)
                        .color(TEXT_MUTED));
                });

                ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                    if toggle_switch(ui, "master_boost", state.optimizations_active, animations, ToggleStyle::Standard) {
                        action = BoostPageAction::ToggleOptimizations;
                    }
                });
            });
        });

    action
}

/// Render profile preset cards
fn render_profile_presets(
    ui: &mut Ui,
    state: &BoostPageState,
    animations: &mut AnimationManager,
) -> BoostPageAction {
    let mut action = BoostPageAction::None;

    ui.horizontal(|ui| {
        ui.spacing_mut().item_spacing.x = 10.0;
        let card_width = (ui.available_width() - 20.0) / 3.0;

        let presets = [
            (OptimizationProfile::LowEnd, "🚀", "Performance", "Max FPS"),
            (OptimizationProfile::Balanced, "⚖", "Balanced", "Recommended"),
            (OptimizationProfile::HighEnd, "✨", "Quality", "Stability"),
        ];

        for (profile, icon, name, desc) in presets {
            ui.allocate_ui(Vec2::new(card_width, 80.0), |ui| {
                let is_selected = state.selected_profile == profile;

                if preset_card(ui, &format!("{:?}", profile), icon, name, desc, is_selected, animations) {
                    action = BoostPageAction::SelectProfile(profile);
                }
            });
        }
    });

    action
}

/// Render system optimization toggles in 3-column grid
fn render_system_optimizations(
    ui: &mut Ui,
    state: &BoostPageState,
    animations: &mut AnimationManager,
) -> BoostPageAction {
    let mut action = BoostPageAction::None;

    section_card(ui, "SYSTEM OPTIMIZATIONS", Some("⚙"), None, |ui| {
        // Tier badge
        ui.horizontal(|ui| {
            tier_badge(ui, 1, "SAFE");
            ui.add_space(8.0);
            ui.label(egui::RichText::new("These optimizations are safe and reversible")
                .size(10.0)
                .color(TEXT_MUTED));
        });

        ui.add_space(12.0);

        // System optimizations in grid
        let sys = &state.config.system_optimization;
        let net = &state.config.network_settings;

        let settings = [
            ("high_priority", "📊", "High Priority", "Boost game process priority", sys.set_high_priority, BoostSetting::HighPriority),
            ("timer_resolution", "⏱", "1ms Timer", "Smoother frame pacing", sys.timer_resolution_1ms, BoostSetting::TimerResolution),
            ("mmcss", "🎮", "MMCSS Gaming", "Thread scheduling for games", sys.mmcss_gaming_profile, BoostSetting::MMCSS),
            ("game_mode", "🎯", "Game Mode", "Windows Game Mode", sys.game_mode_enabled, BoostSetting::GameMode),
            ("nagle", "📡", "Disable Nagle", "Lower network latency", net.disable_nagle, BoostSetting::DisableNagle),
            ("throttling", "⚡", "No Throttling", "Disable network throttling", net.disable_network_throttling, BoostSetting::DisableThrottling),
        ];

        // 2-column layout
        let columns = 2;
        for chunk in settings.chunks(columns) {
            ui.horizontal(|ui| {
                ui.spacing_mut().item_spacing.x = 10.0;
                let item_width = (ui.available_width() - 10.0) / columns as f32;

                for (id, icon, title, desc, enabled, setting) in chunk {
                    ui.allocate_ui(Vec2::new(item_width, 0.0), |ui| {
                        let is_expanded = state.expanded_info.contains(*id);

                        let (clicked, expand_clicked) = boost_toggle(
                            ui,
                            id,
                            icon,
                            title,
                            desc,
                            *enabled && state.optimizations_active,
                            animations,
                            is_expanded,
                        );

                        if clicked {
                            action = BoostPageAction::ToggleSetting(*setting);
                        }
                        if expand_clicked {
                            action = BoostPageAction::ToggleExpand(id.to_string());
                        }
                    });
                }

                // Pad incomplete row
                for _ in chunk.len()..columns {
                    ui.allocate_space(Vec2::new((ui.available_width() - 10.0) / columns as f32, 0.0));
                }
            });
            ui.add_space(8.0);
        }
    });

    action
}

/// Render Roblox-specific settings
fn render_roblox_settings(
    ui: &mut Ui,
    state: &BoostPageState,
    _animations: &mut AnimationManager,
) -> BoostPageAction {
    let mut action = BoostPageAction::None;

    section_card(ui, "ROBLOX SETTINGS", Some("🎮"), None, |ui| {
        // Target FPS slider
        ui.label(egui::RichText::new("Target FPS")
            .size(12.0)
            .color(TEXT_PRIMARY));

        ui.add_space(4.0);

        ui.horizontal(|ui| {
            // Quick presets
            let presets = [60, 120, 144, 240];
            let current_fps = state.config.roblox_settings.target_fps;

            for fps in presets {
                let is_selected = current_fps == fps;
                let button = egui::Button::new(
                    egui::RichText::new(fps.to_string())
                        .size(11.0)
                        .color(if is_selected { TEXT_PRIMARY } else { TEXT_SECONDARY })
                )
                .fill(if is_selected { ACCENT_PRIMARY } else { BG_ELEVATED })
                .rounding(6.0)
                .min_size(Vec2::new(48.0, 28.0));

                if ui.add(button).clicked() {
                    action = BoostPageAction::SetTargetFps(fps);
                }
            }

            // Max button
            let is_max = current_fps >= 9999;
            let button = egui::Button::new(
                egui::RichText::new("Max")
                    .size(11.0)
                    .color(if is_max { TEXT_PRIMARY } else { TEXT_SECONDARY })
            )
            .fill(if is_max { ACCENT_CYAN } else { BG_ELEVATED })
            .rounding(6.0)
            .min_size(Vec2::new(48.0, 28.0));

            if ui.add(button).clicked() {
                action = BoostPageAction::SetTargetFps(9999);
            }
        });

        ui.add_space(8.0);

        // FPS slider
        let mut fps = state.config.roblox_settings.target_fps as f32;
        let slider = egui::Slider::new(&mut fps, 30.0..=240.0)
            .show_value(true)
            .text("FPS");

        if ui.add(slider).changed() {
            action = BoostPageAction::SetTargetFps(fps as u32);
        }

        ui.add_space(16.0);

        // Graphics quality slider
        ui.label(egui::RichText::new("Graphics Quality")
            .size(12.0)
            .color(TEXT_PRIMARY));

        ui.add_space(4.0);

        ui.horizontal(|ui| {
            let presets = [1, 3, 5, 7, 10];
            let current_quality = state.config.roblox_settings.graphics_quality.to_level();

            for quality in presets {
                let is_selected = current_quality == quality;
                let button = egui::Button::new(
                    egui::RichText::new(quality.to_string())
                        .size(11.0)
                        .color(if is_selected { TEXT_PRIMARY } else { TEXT_SECONDARY })
                )
                .fill(if is_selected { ACCENT_PRIMARY } else { BG_ELEVATED })
                .rounding(6.0)
                .min_size(Vec2::new(36.0, 28.0));

                if ui.add(button).clicked() {
                    action = BoostPageAction::SetGraphicsQuality(GraphicsQuality::from_level(quality));
                }
            }
        });

        ui.add_space(8.0);

        // Quality slider
        let mut quality = state.config.roblox_settings.graphics_quality.to_level() as f32;
        let slider = egui::Slider::new(&mut quality, 1.0..=10.0)
            .show_value(true)
            .text("Level");

        if ui.add(slider).changed() {
            action = BoostPageAction::SetGraphicsQuality(GraphicsQuality::from_level(quality as i32));
        }

        ui.add_space(8.0);

        // Info
        ui.label(egui::RichText::new("• Settings are applied automatically when Roblox starts")
            .size(10.0)
            .color(TEXT_DIMMED));
    });

    action
}
