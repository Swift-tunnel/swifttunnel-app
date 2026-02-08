//! Boost tab rendering - PC optimizations, FPS settings, system boosts
//! ExitLag-inspired design with clean boost cards and preset selector

use super::*;
use super::theme::*;
use super::animations::*;
use crate::structs::{OptimizationProfile, GraphicsQuality, DynamicRenderMode};
use crate::system_optimizer::SystemOptimizer;

/// Boost categories for organizing the UI
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum BoostCategory {
    System,
    Network,
    Roblox,
}

impl BoostCategory {
    pub fn icon(&self) -> &'static str {
        match self {
            BoostCategory::System => "SYS",
            BoostCategory::Network => "NET",
            BoostCategory::Roblox => "GFX",
        }
    }

    pub fn title(&self) -> &'static str {
        match self {
            BoostCategory::System => "System Performance",
            BoostCategory::Network => "Network Optimization",
            BoostCategory::Roblox => "Roblox Settings",
        }
    }

    pub fn description(&self) -> &'static str {
        match self {
            BoostCategory::System => "Optimize CPU and memory for gaming",
            BoostCategory::Network => "Reduce latency and improve connection",
            BoostCategory::Roblox => "FPS and graphics configuration",
        }
    }
}

/// Individual boost info
pub struct BoostConfig {
    pub id: &'static str,
    pub name: &'static str,
    pub description: &'static str,
    pub icon: &'static str,
    pub impact: &'static str,
    pub category: BoostCategory,
}

// Boost definitions
const BOOST_HIGH_PRIORITY: BoostConfig = BoostConfig {
    id: "high_priority",
    name: "High Priority",
    description: "Sets game to high CPU priority",
    icon: "CPU",
    impact: "+5-15% FPS",
    category: BoostCategory::System,
};

const BOOST_TIMER_RESOLUTION: BoostConfig = BoostConfig {
    id: "timer_resolution",
    name: "0.5ms Timer",
    description: "Max precision frame pacing",
    icon: "TMR",
    impact: "Lower input lag",
    category: BoostCategory::System,
};

const BOOST_MMCSS: BoostConfig = BoostConfig {
    id: "mmcss",
    name: "MMCSS Profile",
    description: "Gaming thread priority",
    icon: "THD",
    impact: "Better scheduling",
    category: BoostCategory::System,
};

const BOOST_GAME_MODE: BoostConfig = BoostConfig {
    id: "game_mode",
    name: "Game Mode",
    description: "Windows gaming optimizations",
    icon: "WIN",
    impact: "Fewer interrupts",
    category: BoostCategory::System,
};

const BOOST_DISABLE_NAGLE: BoostConfig = BoostConfig {
    id: "disable_nagle",
    name: "Disable Nagle",
    description: "Send packets immediately",
    icon: "PKT",
    impact: "-5-20ms latency",
    category: BoostCategory::Network,
};

const BOOST_NETWORK_THROTTLING: BoostConfig = BoostConfig {
    id: "network_throttling",
    name: "No Throttling",
    description: "Remove network limits",
    icon: "BW",
    impact: "Consistent speed",
    category: BoostCategory::Network,
};

const BOOST_OPTIMIZE_MTU: BoostConfig = BoostConfig {
    id: "optimize_mtu",
    name: "Optimize MTU",
    description: "Reduce packet fragmentation",
    icon: "MTU",
    impact: "Fewer retries",
    category: BoostCategory::Network,
};

impl BoosterApp {
    pub(crate) fn render_boost_tab(&mut self, ui: &mut egui::Ui) {
        // Clear old restore point status
        if let Some((_, _, time)) = &self.restore_point_status {
            if time.elapsed() > std::time::Duration::from_secs(5) {
                self.restore_point_status = None;
            }
        }

        // Master toggle and status
        self.render_boost_master_toggle(ui);
        ui.add_space(SPACING_MD);

        // Preset selector
        self.render_preset_selector(ui);
        ui.add_space(SPACING_MD);

        // Roblox FPS Settings (collapsible card)
        self.render_roblox_fps_card(ui);
        ui.add_space(SPACING_MD);

        // System Boosts Grid
        self.render_boost_category_grid(ui, BoostCategory::System, &[
            &BOOST_HIGH_PRIORITY,
            &BOOST_TIMER_RESOLUTION,
            &BOOST_MMCSS,
            &BOOST_GAME_MODE,
        ]);
        ui.add_space(SPACING_MD);

        // Network Boosts Grid
        self.render_boost_category_grid(ui, BoostCategory::Network, &[
            &BOOST_DISABLE_NAGLE,
            &BOOST_NETWORK_THROTTLING,
            &BOOST_OPTIMIZE_MTU,
        ]);
        ui.add_space(SPACING_MD);

        // System Protection
        self.render_system_protection_card(ui);
    }

    /// Render master boost toggle with status
    fn render_boost_master_toggle(&mut self, ui: &mut egui::Ui) {
        let is_active = self.state.optimizations_active;
        let active_count = self.count_active_boosts();

        let (status_color, status_text) = if is_active {
            (STATUS_CONNECTED, "Active")
        } else {
            (STATUS_INACTIVE, "Inactive")
        };

        let mut toggle_requested = false;

        card_frame()
            .show(ui, |ui| {
                ui.horizontal(|ui| {
                    // Status indicator with pulse when active
                    let indicator_size = 40.0;
                    let (indicator_rect, _) = ui.allocate_exact_size(
                        egui::vec2(indicator_size, indicator_size),
                        egui::Sense::hover()
                    );
                    let center = indicator_rect.center();

                    if is_active {
                        // Animated glow
                        let elapsed = self.app_start_time.elapsed().as_secs_f32();
                        let pulse = ((elapsed * std::f32::consts::PI / PULSE_ANIMATION_DURATION).sin() + 1.0) / 2.0;
                        ui.painter().circle_filled(center, 16.0 + pulse * 3.0, status_color.gamma_multiply(0.2));
                        ui.painter().circle_filled(center, 14.0, status_color);
                    } else {
                        ui.painter().circle_filled(center, 14.0, BG_ELEVATED);
                        ui.painter().circle_stroke(center, 14.0, egui::Stroke::new(1.5, status_color));
                    }

                    ui.add_space(SPACING_SM);

                    ui.vertical(|ui| {
                        ui.horizontal(|ui| {
                            ui.label(egui::RichText::new("PC Boosts")
                                .size(18.0)
                                .color(TEXT_PRIMARY)
                                .strong());
                            ui.add_space(SPACING_SM);

                            // Status badge
                            egui::Frame::NONE
                                .fill(status_color.gamma_multiply(0.12))
                                .rounding(10.0)
                                .inner_margin(egui::Margin::symmetric(8, 3))
                                .show(ui, |ui| {
                                    ui.label(egui::RichText::new(status_text)
                                        .size(10.0)
                                        .color(status_color)
                                        .strong());
                                });
                        });

                        ui.add_space(2.0);

                        let profile_name = format!("{:?}", self.selected_profile);
                        let desc = if is_active {
                            format!("{} boosts enabled - {} profile", active_count, profile_name)
                        } else {
                            "Enable boosts to optimize your PC".to_string()
                        };
                        ui.label(egui::RichText::new(desc)
                            .size(12.0)
                            .color(TEXT_SECONDARY));
                    });

                    ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                        // Large toggle button
                        let btn_size = egui::vec2(100.0, 40.0);
                        let (btn_rect, btn_response) = ui.allocate_exact_size(btn_size, egui::Sense::click());

                        let is_hovered = btn_response.hovered();
                        let btn_color = if is_active { STATUS_ERROR } else { ACCENT_PRIMARY };
                        let btn_bg = if is_hovered { lighten(btn_color, 0.1) } else { btn_color };

                        ui.painter().rect_filled(btn_rect, 10.0, btn_bg);

                        let btn_text = if is_active { "Disable" } else { "Enable" };
                        ui.painter().text(
                            btn_rect.center(),
                            egui::Align2::CENTER_CENTER,
                            btn_text,
                            egui::FontId::proportional(14.0),
                            TEXT_PRIMARY
                        );

                        if btn_response.clicked() {
                            toggle_requested = true;
                        }
                    });
                });
            });

        if toggle_requested {
            self.toggle_optimizations();
        }
    }

    /// Render preset selector (Performance / Balanced / Quality)
    fn render_preset_selector(&mut self, ui: &mut egui::Ui) {
        ui.horizontal(|ui| {
            ui.label(egui::RichText::new("PRESET").size(11.0).color(TEXT_MUTED).strong());
        });
        ui.add_space(SPACING_SM);

        let mut new_profile = None;
        let available_width = self.content_area_width.min(ui.available_width());
        let btn_width = ((available_width - CARD_GAP * 2.0) / 3.0).max(80.0);

        ui.horizontal(|ui| {
            ui.spacing_mut().item_spacing.x = CARD_GAP;

            for (profile, label, desc) in [
                (OptimizationProfile::LowEnd, "Performance", "Max FPS"),
                (OptimizationProfile::Balanced, "Balanced", "FPS + Quality"),
                (OptimizationProfile::HighEnd, "Quality", "Best Visuals"),
            ] {
                let is_selected = self.selected_profile == profile;
                let card_id = format!("preset_{:?}", profile);
                let hover_val = self.animations.get_hover_value(&card_id);

                let bg = if is_selected {
                    ACCENT_PRIMARY
                } else {
                    lerp_color(BG_CARD, BG_HOVER, hover_val)
                };

                let border = if is_selected {
                    ACCENT_PRIMARY
                } else {
                    lerp_color(BORDER_SUBTLE, BORDER_HOVER, hover_val)
                };

                let response = egui::Frame::NONE
                    .fill(bg)
                    .stroke(egui::Stroke::new(if is_selected { 0.0 } else { 1.0 }, border))
                    .rounding(10.0)
                    .inner_margin(egui::Margin::symmetric(8, 12))
                    .show(ui, |ui| {
                        ui.set_min_width(btn_width - 16.0);
                        ui.set_max_width(btn_width - 16.0);

                        ui.vertical_centered(|ui| {
                            let text_color = if is_selected { TEXT_PRIMARY } else { TEXT_SECONDARY };
                            ui.label(egui::RichText::new(label).size(13.0).color(text_color).strong());
                            ui.add_space(2.0);

                            let desc_color = if is_selected { TEXT_PRIMARY.gamma_multiply(0.8) } else { TEXT_MUTED };
                            ui.label(egui::RichText::new(desc).size(10.0).color(desc_color));
                        });
                    });

                let is_hovered = response.response.hovered();
                self.animations.animate_hover(&card_id, is_hovered, hover_val);

                if response.response.interact(egui::Sense::click()).clicked() {
                    new_profile = Some(profile);
                }
            }
        });

        if let Some(profile) = new_profile {
            self.selected_profile = profile;
            self.apply_profile_preset();
            self.mark_dirty();
        }
    }

    /// Render Roblox FPS settings card
    fn render_roblox_fps_card(&mut self, ui: &mut egui::Ui) {
        let current_fps = self.state.config.roblox_settings.target_fps;
        let is_uncapped = current_fps >= 9999;
        let fps_display = if is_uncapped { "Uncapped".to_string() } else { format!("{}", current_fps) };

        card_frame()
            .show(ui, |ui| {
                // Header
                ui.horizontal(|ui| {
                    ui.label(egui::RichText::new("Roblox Settings").size(14.0).color(TEXT_PRIMARY).strong());

                    ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                        // Protected badge
                        egui::Frame::NONE
                            .fill(STATUS_CONNECTED.gamma_multiply(0.1))
                            .rounding(8.0)
                            .inner_margin(egui::Margin::symmetric(8, 3))
                            .show(ui, |ui| {
                                ui.label(egui::RichText::new("Protected")
                                    .size(10.0)
                                    .color(STATUS_CONNECTED));
                            });
                    });
                });

                ui.add_space(SPACING_MD);

                // FPS Section
                ui.horizontal(|ui| {
                    ui.vertical(|ui| {
                        ui.label(egui::RichText::new("Target FPS").size(12.0).color(TEXT_SECONDARY));
                        ui.label(egui::RichText::new(&fps_display).size(24.0).color(ACCENT_PRIMARY).strong());
                    });

                    ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                        // Uncapped toggle
                        let mut uncapped = is_uncapped;
                        if ui.add(
                            egui::Button::new(egui::RichText::new(if uncapped { "Uncapped" } else { "Uncapped" }).size(11.0).color(if uncapped { TEXT_PRIMARY } else { TEXT_SECONDARY }))
                                .fill(if uncapped { ACCENT_PRIMARY } else { BG_ELEVATED })
                                .rounding(6.0)
                                .min_size(egui::vec2(80.0, 28.0))
                        ).clicked() {
                            uncapped = !uncapped;
                            if uncapped {
                                self.state.config.roblox_settings.target_fps = 9999;
                            } else {
                                self.state.config.roblox_settings.target_fps = 144; // Default to 144 when uncapping
                            }
                            self.mark_dirty();
                        }

                        // Number input (only if not uncapped)
                        if !uncapped {
                            ui.add_space(8.0);
                            let mut fps_value = self.state.config.roblox_settings.target_fps as i32;
                            let response = ui.add(
                                egui::DragValue::new(&mut fps_value)
                                    .range(1..=9998)
                                    .speed(1.0)
                                    .suffix(" FPS")
                            );
                            if response.changed() {
                                self.state.config.roblox_settings.target_fps = fps_value.clamp(1, 9998) as u32;
                                self.mark_dirty();
                            }
                        }
                    });
                });

                // FPS Slider (only if not uncapped - re-read config to handle same-frame toggle)
                let show_slider = self.state.config.roblox_settings.target_fps < 9999;
                if show_slider {
                    ui.add_space(SPACING_SM);
                    let mut slider_fps = self.state.config.roblox_settings.target_fps.min(500) as i32;
                    if ui.add(egui::Slider::new(&mut slider_fps, 30..=500).show_value(false)).changed() {
                        self.state.config.roblox_settings.target_fps = slider_fps as u32;
                        self.mark_dirty();
                    }
                }

                ui.add_space(SPACING_MD);

                // Graphics Quality Section
                let current_quality = self.state.config.roblox_settings.graphics_quality.to_level();

                ui.horizontal(|ui| {
                    ui.vertical(|ui| {
                        ui.label(egui::RichText::new("Graphics Quality").size(12.0).color(TEXT_SECONDARY));
                        let quality_text = if current_quality == 0 { "Auto".to_string() } else { format!("Level {}", current_quality) };
                        ui.label(egui::RichText::new(quality_text).size(18.0).color(ACCENT_CYAN).strong());
                    });

                    ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                        // Quick quality buttons
                        for level in [1, 5, 10] {
                            let is_sel = current_quality == level;
                            let bg = if is_sel { ACCENT_CYAN } else { BG_ELEVATED };
                            let text = if is_sel { egui::Color32::from_rgb(23, 23, 23) } else { TEXT_SECONDARY };

                            if ui.add(
                                egui::Button::new(egui::RichText::new(format!("{}", level)).size(11.0).color(text))
                                    .fill(bg)
                                    .rounding(6.0)
                                    .min_size(egui::vec2(36.0, 28.0))
                            ).clicked() {
                                self.state.config.roblox_settings.graphics_quality = GraphicsQuality::from_level(level);
                                if self.selected_profile != OptimizationProfile::Custom {
                                    self.selected_profile = OptimizationProfile::Custom;
                                }
                                self.mark_dirty();
                            }
                        }
                    });
                });

                // Quality Slider
                ui.add_space(SPACING_SM);
                let mut quality_level = current_quality.max(1) as i32;
                if ui.add(egui::Slider::new(&mut quality_level, 1..=10).show_value(false)).changed() {
                    self.state.config.roblox_settings.graphics_quality = GraphicsQuality::from_level(quality_level);
                    if self.selected_profile != OptimizationProfile::Custom {
                        self.selected_profile = OptimizationProfile::Custom;
                    }
                    self.mark_dirty();
                }

                ui.add_space(SPACING_MD);

                // Dynamic Render Section - Enhanced UI
                let current_mode = self.state.config.roblox_settings.dynamic_render_optimization;

                // Header with description
                ui.horizontal(|ui| {
                    ui.label(egui::RichText::new("Dynamic Render").size(12.0).color(TEXT_SECONDARY));
                    ui.add_space(8.0);
                    egui::Frame::NONE
                        .fill(ACCENT_LIME.gamma_multiply(0.15))
                        .rounding(4.0)
                        .inner_margin(egui::Margin::symmetric(6, 2))
                        .show(ui, |ui| {
                            ui.label(egui::RichText::new("Recommended")
                                .size(9.0)
                                .color(ACCENT_LIME));
                        });
                });

                ui.add_space(4.0);
                ui.label(egui::RichText::new("Lowers internal render resolution for massive FPS gains. Most players can't notice the difference.")
                    .size(10.0)
                    .color(TEXT_MUTED));

                ui.add_space(SPACING_SM);

                // Buttons with impact labels
                ui.horizontal(|ui| {
                    for (label, mode, impact) in [
                        ("Off", DynamicRenderMode::Off, ""),
                        ("Low", DynamicRenderMode::Low, "+5%"),
                        ("Med", DynamicRenderMode::Medium, "+15%"),
                        ("High", DynamicRenderMode::High, "+30%"),
                    ] {
                        let is_sel = current_mode == mode;
                        let bg = if is_sel { ACCENT_LIME } else { BG_ELEVATED };
                        let text_color = if is_sel { egui::Color32::from_rgb(23, 23, 23) } else { TEXT_SECONDARY };

                        ui.vertical(|ui| {
                            // Button
                            if ui.add(
                                egui::Button::new(egui::RichText::new(label).size(11.0).color(text_color))
                                    .fill(bg)
                                    .rounding(6.0)
                                    .min_size(egui::vec2(52.0, 28.0))
                            ).clicked() {
                                self.state.config.roblox_settings.dynamic_render_optimization = mode;
                                if self.selected_profile != OptimizationProfile::Custom {
                                    self.selected_profile = OptimizationProfile::Custom;
                                }
                                self.mark_dirty();
                            }
                            // Impact label below button
                            if !impact.is_empty() {
                                ui.add_space(2.0);
                                ui.label(egui::RichText::new(impact)
                                    .size(9.0)
                                    .color(if is_sel { ACCENT_LIME } else { TEXT_MUTED }));
                            } else {
                                ui.add_space(2.0);
                                ui.label(egui::RichText::new("--").size(9.0).color(TEXT_MUTED));
                            }
                        });
                        ui.add_space(4.0);
                    }
                });
            });
    }

    /// Render a category of boosts in a grid
    fn render_boost_category_grid(&mut self, ui: &mut egui::Ui, category: BoostCategory, boosts: &[&BoostConfig]) {
        // Section header
        ui.horizontal(|ui| {
            // Category label badge instead of ASCII icon
            egui::Frame::NONE
                .fill(ACCENT_PRIMARY.gamma_multiply(0.12))
                .rounding(4.0)
                .inner_margin(egui::Margin::symmetric(6, 2))
                .show(ui, |ui| {
                    ui.label(egui::RichText::new(category.icon())
                        .size(9.0).color(ACCENT_PRIMARY).strong());
                });
            ui.add_space(4.0);
            ui.label(egui::RichText::new(category.title()).size(12.0).color(TEXT_PRIMARY).strong());

            ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                // Safe badge
                egui::Frame::NONE
                    .fill(STATUS_CONNECTED.gamma_multiply(0.1))
                    .rounding(8.0)
                    .inner_margin(egui::Margin::symmetric(8, 2))
                    .show(ui, |ui| {
                        ui.label(egui::RichText::new("SAFE").size(9.0).color(STATUS_CONNECTED));
                    });
            });
        });
        ui.add_space(SPACING_SM);

        // Calculate card width (full width, single column layout)
        let available_width = self.content_area_width.min(ui.available_width());
        let card_width = available_width;

        // Render boosts in single column (vertical stack)
        for boost in boosts {
            self.render_boost_card(ui, boost, card_width);
            ui.add_space(SPACING_SM);
        }
    }

    /// Render a single boost card with toggle
    fn render_boost_card(&mut self, ui: &mut egui::Ui, boost: &BoostConfig, width: f32) {
        let is_enabled = self.get_boost_value(boost.id);
        let card_id = format!("boost_{}", boost.id);
        let hover_val = self.animations.get_hover_value(&card_id);

        let bg = lerp_color(BG_CARD, BG_HOVER, hover_val * 0.3);
        let border = if is_enabled {
            ACCENT_PRIMARY.gamma_multiply(0.5)
        } else {
            lerp_color(BORDER_SUBTLE, BORDER_HOVER, hover_val)
        };

        let response = egui::Frame::NONE
            .fill(bg)
            .stroke(egui::Stroke::new(1.0, border))
            .rounding(10.0)
            .inner_margin(egui::Margin::same(12))
            .show(ui, |ui| {
                // Use full available width for single column layout

                ui.horizontal(|ui| {
                    // Short text label instead of ASCII icon
                    let icon_bg = if is_enabled { ACCENT_PRIMARY.gamma_multiply(0.15) } else { BG_ELEVATED };
                    let icon_color = if is_enabled { ACCENT_PRIMARY } else { TEXT_MUTED };

                    egui::Frame::NONE
                        .fill(icon_bg)
                        .rounding(6.0)
                        .inner_margin(egui::Margin::symmetric(8, 8))
                        .show(ui, |ui| {
                            ui.label(egui::RichText::new(boost.icon).size(10.0).color(icon_color).strong());
                        });

                    ui.add_space(SPACING_SM);

                    // Text content
                    ui.vertical(|ui| {
                        ui.label(egui::RichText::new(boost.name).size(12.0).color(TEXT_PRIMARY).strong());
                        ui.label(egui::RichText::new(boost.description).size(10.0).color(TEXT_MUTED));
                    });

                    ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                        // Toggle switch
                        let toggle_id = format!("toggle_{}", boost.id);
                        let anim_val = self.animations.get_toggle_value(&toggle_id, is_enabled);
                        self.animations.animate_toggle(&toggle_id, is_enabled, anim_val);
                        let current_anim = self.animations.get_toggle_value(&toggle_id, is_enabled);

                        let toggle_width = TOGGLE_WIDTH;
                        let toggle_height = TOGGLE_HEIGHT;
                        let (toggle_rect, toggle_response) = ui.allocate_exact_size(
                            egui::vec2(toggle_width, toggle_height),
                            egui::Sense::click()
                        );

                        // Track color - blue accent when enabled
                        let track_color = lerp_color(BG_ELEVATED, ACCENT_PRIMARY, current_anim);
                        ui.painter().rect_filled(toggle_rect, toggle_height / 2.0, track_color);

                        // Knob
                        let knob_radius = (toggle_height - 6.0) / 2.0;
                        let knob_x = toggle_rect.left() + toggle_height / 2.0 + current_anim * (toggle_width - toggle_height);
                        let knob_center = egui::pos2(knob_x, toggle_rect.center().y);
                        ui.painter().circle_filled(knob_center, knob_radius, TEXT_PRIMARY);

                        if toggle_response.clicked() {
                            self.set_boost_value(boost.id, !is_enabled);
                            self.mark_dirty();
                        }
                    });
                });

                // Impact badge
                ui.add_space(6.0);
                ui.horizontal(|ui| {
                    let impact_color = if is_enabled { ACCENT_PRIMARY } else { TEXT_DIMMED };
                    egui::Frame::NONE
                        .fill(impact_color.gamma_multiply(0.08))
                        .rounding(4.0)
                        .inner_margin(egui::Margin::symmetric(6, 2))
                        .show(ui, |ui| {
                            ui.label(egui::RichText::new(boost.impact).size(9.0).color(impact_color));
                        });
                });
            });

        let is_hovered = response.response.hovered();
        self.animations.animate_hover(&card_id, is_hovered, hover_val);
    }

    /// Get boost value by ID
    fn get_boost_value(&self, id: &str) -> bool {
        match id {
            "high_priority" => self.state.config.system_optimization.set_high_priority,
            "timer_resolution" => self.state.config.system_optimization.timer_resolution_1ms,
            "mmcss" => self.state.config.system_optimization.mmcss_gaming_profile,
            "game_mode" => self.state.config.system_optimization.game_mode_enabled,
            "disable_nagle" => self.state.config.network_settings.disable_nagle,
            "network_throttling" => self.state.config.network_settings.disable_network_throttling,
            "optimize_mtu" => self.state.config.network_settings.optimize_mtu,
            "gaming_qos" => self.state.config.network_settings.gaming_qos,
            _ => false,
        }
    }

    /// Set boost value by ID and apply immediately if main toggle is active
    fn set_boost_value(&mut self, id: &str, value: bool) {
        // Update the config value
        match id {
            "high_priority" => self.state.config.system_optimization.set_high_priority = value,
            "timer_resolution" => self.state.config.system_optimization.timer_resolution_1ms = value,
            "mmcss" => self.state.config.system_optimization.mmcss_gaming_profile = value,
            "game_mode" => self.state.config.system_optimization.game_mode_enabled = value,
            "disable_nagle" => self.state.config.network_settings.disable_nagle = value,
            "network_throttling" => self.state.config.network_settings.disable_network_throttling = value,
            "optimize_mtu" => self.state.config.network_settings.optimize_mtu = value,
            "gaming_qos" => self.state.config.network_settings.gaming_qos = value,
            _ => {}
        }

        // Apply immediately if main optimizations toggle is active
        self.apply_single_boost(id, value);
    }

    /// Render system protection card
    fn render_system_protection_card(&mut self, ui: &mut egui::Ui) {
        let mut create_restore_point = false;
        let mut open_restore = false;

        card_frame()
            .show(ui, |ui| {
                ui.horizontal(|ui| {
                    ui.label(egui::RichText::new("System Protection").size(13.0).color(TEXT_PRIMARY).strong());
                });
                ui.add_space(4.0);
                ui.label(egui::RichText::new("Create restore points before making changes").size(11.0).color(TEXT_MUTED));

                ui.add_space(SPACING_MD);

                ui.horizontal(|ui| {
                    if ui.add(
                        egui::Button::new(egui::RichText::new("Create Restore Point").size(12.0).color(TEXT_PRIMARY))
                            .fill(ACCENT_PRIMARY)
                            .rounding(8.0)
                            .min_size(egui::vec2(160.0, 36.0))
                    ).clicked() {
                        create_restore_point = true;
                    }

                    ui.add_space(SPACING_SM);

                    if ui.add(
                        egui::Button::new(egui::RichText::new("Open System Restore").size(12.0).color(TEXT_SECONDARY))
                            .fill(BG_ELEVATED)
                            .rounding(8.0)
                            .min_size(egui::vec2(150.0, 36.0))
                    ).clicked() {
                        open_restore = true;
                    }
                });

                if let Some((msg, color, _)) = &self.restore_point_status {
                    ui.add_space(SPACING_SM);
                    ui.label(egui::RichText::new(msg).size(11.0).color(*color));
                }
            });

        if create_restore_point {
            match SystemOptimizer::create_restore_point("SwiftTunnel - Before PC Boosts") {
                Ok(desc) => {
                    self.restore_point_status = Some((
                        format!("Restore point created: {}", desc),
                        STATUS_CONNECTED,
                        std::time::Instant::now()
                    ));
                }
                Err(e) => {
                    self.restore_point_status = Some((
                        format!("Failed: {}", e),
                        STATUS_ERROR,
                        std::time::Instant::now()
                    ));
                }
            }
        }

        if open_restore {
            if let Err(e) = SystemOptimizer::open_system_restore() {
                self.restore_point_status = Some((
                    format!("Failed to open: {}", e),
                    STATUS_ERROR,
                    std::time::Instant::now()
                ));
            }
        }
    }

    /// Legacy helper methods for backwards compatibility
    pub(crate) fn render_toggle_row(&mut self, ui: &mut egui::Ui, label: &str, description: &str, value: bool, on_toggle: fn(&mut Self)) {
        self.render_animated_toggle_row(ui, label, description, value, on_toggle);
    }

    pub(crate) fn render_animated_toggle_row(
        &mut self,
        ui: &mut egui::Ui,
        label: &str,
        description: &str,
        value: bool,
        on_toggle: fn(&mut Self),
    ) {
        let toggle_id = format!("toggle_{}", label);
        let anim_val = self.animations.get_toggle_value(&toggle_id, value);
        self.animations.animate_toggle(&toggle_id, value, anim_val);
        let current_anim = self.animations.get_toggle_value(&toggle_id, value);

        let response = ui.horizontal(|ui| {
            ui.vertical(|ui| {
                ui.label(egui::RichText::new(label).size(13.0).color(TEXT_PRIMARY));
                ui.label(egui::RichText::new(description).size(11.0).color(TEXT_MUTED));
            });

            ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                let toggle_width = TOGGLE_WIDTH;
                let toggle_height = TOGGLE_HEIGHT;
                let (toggle_rect, toggle_response) = ui.allocate_exact_size(
                    egui::vec2(toggle_width, toggle_height),
                    egui::Sense::click()
                );

                let bg_color = lerp_color(BG_ELEVATED, ACCENT_PRIMARY, current_anim);
                ui.painter().rect_filled(toggle_rect, toggle_height / 2.0, bg_color);

                let knob_radius = (toggle_height - 6.0) / 2.0;
                let knob_x = toggle_rect.left() + toggle_height / 2.0 + current_anim * (toggle_width - toggle_height);
                let knob_center = egui::pos2(knob_x, toggle_rect.center().y);
                ui.painter().circle_filled(knob_center, knob_radius, TEXT_PRIMARY);

                toggle_response.clicked()
            }).inner
        });

        if response.inner {
            on_toggle(self);
            self.mark_dirty();
        }
    }
}
