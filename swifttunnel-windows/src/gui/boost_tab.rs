//! Boost tab rendering - PC optimizations, FPS settings, system boosts

use super::*;
use super::theme::*;
use super::animations::*;
use crate::structs::{OptimizationProfile, GraphicsQuality, DynamicRenderMode};
use crate::system_optimizer::SystemOptimizer;

/// Profile preset info for tooltips
mod profile_info {
    pub struct ProfileInfo {
        pub name: &'static str,
        pub description: &'static str,
        pub settings_summary: &'static str,
        pub fps_target: &'static str,
        pub best_for: &'static str,
    }

    pub const PERFORMANCE: ProfileInfo = ProfileInfo {
        name: "Performance Mode",
        description: "Maximum FPS with minimal visual quality. Aggressive optimizations for competitive play.",
        settings_summary: "FPS: Uncapped | Quality: 1 | Dynamic Render: High | All boosts ON",
        fps_target: "Target: 240+ FPS",
        best_for: "Competitive/PvP",
    };

    pub const BALANCED: ProfileInfo = ProfileInfo {
        name: "Balanced Mode",
        description: "Good balance between performance and visuals. Suitable for most players.",
        settings_summary: "FPS: 144 | Quality: 5 | Dynamic Render: Medium | Core boosts ON",
        fps_target: "Target: 100-144 FPS",
        best_for: "Casual gameplay",
    };

    pub const QUALITY: ProfileInfo = ProfileInfo {
        name: "Quality Mode",
        description: "Best visual experience with moderate performance. For high-end systems.",
        settings_summary: "FPS: 60 | Quality: 10 | Dynamic Render: Off | Minimal boosts",
        fps_target: "Target: 60 FPS",
        best_for: "Exploration/Screenshots",
    };
}

/// Tier info for boost categories
mod tier_info {
    pub const TIER_1_TITLE: &str = "Tier 1 - Safe Optimizations";
    pub const TIER_1_DESC: &str = "These settings are safe to enable with no risk of system instability. They can be reverted at any time and don't modify critical system files.";
}

/// Boost info for individual toggles
mod boost_info {
    pub struct BoostInfo {
        pub name: &'static str,
        pub description: &'static str,
        pub technical: &'static str,
        pub impact: &'static str,
    }

    pub const HIGH_PRIORITY: BoostInfo = BoostInfo {
        name: "High Priority",
        description: "Sets Roblox process to high priority for better CPU scheduling",
        technical: "SetPriorityClass(HIGH_PRIORITY_CLASS)",
        impact: "+5-15% FPS in CPU-bound scenarios",
    };

    pub const TIMER_RESOLUTION: BoostInfo = BoostInfo {
        name: "1ms Timer Resolution",
        description: "Reduces system timer interval for smoother frame pacing",
        technical: "NtSetTimerResolution(1ms)",
        impact: "Smoother frametimes, reduced input lag",
    };

    pub const MMCSS: BoostInfo = BoostInfo {
        name: "MMCSS Gaming Profile",
        description: "Applies Windows multimedia scheduling for games",
        technical: "AvSetMmThreadCharacteristics(\"Games\")",
        impact: "Prioritizes game threads over background tasks",
    };

    pub const GAME_MODE: BoostInfo = BoostInfo {
        name: "Windows Game Mode",
        description: "Enables Windows Game Mode for reduced background activity",
        technical: "Registry: GameDVR_FSEBehaviorMode",
        impact: "Fewer interruptions during gameplay",
    };

    pub const DISABLE_NAGLE: BoostInfo = BoostInfo {
        name: "Disable Nagle's Algorithm",
        description: "Sends packets immediately without buffering",
        technical: "TCP_NODELAY socket option",
        impact: "-5-20ms network latency",
    };

    pub const NETWORK_THROTTLING: BoostInfo = BoostInfo {
        name: "Disable Network Throttling",
        description: "Removes Windows network throttling for games",
        technical: "Registry: NetworkThrottlingIndex",
        impact: "More consistent packet delivery",
    };

    pub const OPTIMIZE_MTU: BoostInfo = BoostInfo {
        name: "Optimize MTU",
        description: "Sets optimal MTU size to reduce packet fragmentation",
        technical: "netsh interface ipv4 set subinterface mtu=1500",
        impact: "Fewer retransmissions, lower latency",
    };
}

impl BoosterApp {
    pub(crate) fn render_boost_tab(&mut self, ui: &mut egui::Ui) {
        // Clear old restore point status
        if let Some((_, _, time)) = &self.restore_point_status {
            if time.elapsed() > std::time::Duration::from_secs(5) {
                self.restore_point_status = None;
            }
        }

        // STATUS HEADER WITH ENABLE/DISABLE
        let (status_text, status_color) = if self.state.optimizations_active {
            ("Optimizations Active", STATUS_CONNECTED)
        } else {
            ("Optimizations Inactive", STATUS_INACTIVE)
        };

        let profile_str = format!("{:?}", self.selected_profile);
        let opt_active = self.state.optimizations_active;
        let mut toggle_opt = false;

        egui::Frame::NONE
            .fill(BG_CARD).stroke(egui::Stroke::new(1.0, BG_ELEVATED))
            .rounding(12.0).inner_margin(20)
            .show(ui, |ui| {
                ui.set_min_width(ui.available_width());

                ui.horizontal(|ui| {
                    let (rect, _) = ui.allocate_exact_size(egui::vec2(12.0, 12.0), egui::Sense::hover());
                    ui.painter().circle_filled(rect.center(), 6.0, status_color);
                    ui.add_space(8.0);

                    ui.vertical(|ui| {
                        ui.label(egui::RichText::new(status_text).size(16.0).color(status_color).strong());
                        ui.label(egui::RichText::new(format!("Profile: {}", profile_str)).size(12.0).color(TEXT_SECONDARY));
                    });

                    ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                        let (btn_text, btn_color) = if opt_active { ("Disable", STATUS_ERROR) } else { ("Enable", ACCENT_PRIMARY) };
                        if ui.add(
                            egui::Button::new(egui::RichText::new(btn_text).size(14.0).color(TEXT_PRIMARY))
                                .fill(btn_color).rounding(8.0).min_size(egui::vec2(100.0, 40.0))
                        ).clicked() {
                            toggle_opt = true;
                        }
                    });
                });
            });

        if toggle_opt {
            self.toggle_optimizations();
        }

        // PROFILE SELECTION
        ui.add_space(16.0);
        ui.label(egui::RichText::new("QUICK PRESET").size(12.0).color(TEXT_MUTED).strong());
        ui.add_space(12.0);

        let mut new_profile = None;
        let available_width = ui.available_width();
        let gap = 12.0;
        let card_width = ((available_width - gap * 2.0) / 3.0).max(100.0);

        ui.horizontal(|ui| {
            ui.spacing_mut().item_spacing.x = gap;

            for (title, desc, icon, profile, profile_info) in [
                ("Performance", "Maximum FPS", ">", OptimizationProfile::LowEnd, &profile_info::PERFORMANCE),
                ("Balanced", "FPS + Quality", "=", OptimizationProfile::Balanced, &profile_info::BALANCED),
                ("Quality", "Best Visuals", "*", OptimizationProfile::HighEnd, &profile_info::QUALITY),
            ] {
                let is_selected = self.selected_profile == profile;
                let card_id = format!("profile_{}", title);

                // Get hover animation value
                let hover_val = self.animations.get_hover_value(&card_id);

                // Calculate colors with hover effect
                let (bg, border, text_color) = if is_selected {
                    (ACCENT_PRIMARY.gamma_multiply(0.15), ACCENT_PRIMARY, ACCENT_PRIMARY)
                } else {
                    // Blend towards hover state
                    let hover_brightness = 1.0 + hover_val * 0.15;
                    let bg = egui::Color32::from_rgb(
                        (BG_CARD.r() as f32 * hover_brightness).min(255.0) as u8,
                        (BG_CARD.g() as f32 * hover_brightness).min(255.0) as u8,
                        (BG_CARD.b() as f32 * hover_brightness).min(255.0) as u8,
                    );
                    (bg, BG_ELEVATED, TEXT_PRIMARY)
                };

                let response = egui::Frame::NONE
                    .fill(bg)
                    .stroke(egui::Stroke::new(if is_selected { 2.0 } else { 1.0 }, border))
                    .rounding(12.0)
                    .inner_margin(egui::Margin::symmetric(12, 16))
                    .show(ui, |ui| {
                        ui.set_width(card_width - 24.0);
                        ui.vertical_centered(|ui| {
                            ui.label(egui::RichText::new(icon).size(24.0).color(if is_selected { ACCENT_PRIMARY } else { TEXT_MUTED }));
                            ui.add_space(8.0);
                            ui.label(egui::RichText::new(title).size(14.0).color(text_color).strong());
                            ui.add_space(4.0);
                            ui.label(egui::RichText::new(desc).size(11.0).color(TEXT_SECONDARY));
                        });
                    });

                // Handle hover for animation
                let is_hovered = response.response.hovered();
                self.animations.animate_hover(&card_id, is_hovered, hover_val);

                // Show tooltip on hover
                if is_hovered {
                    let tooltip_id = ui.id().with(&card_id);
                    egui::show_tooltip_at_pointer(ui.ctx(), egui::LayerId::new(egui::Order::Tooltip, tooltip_id), tooltip_id, |ui| {
                        ui.set_max_width(250.0);
                        ui.label(egui::RichText::new(profile_info.name).size(13.0).color(TEXT_PRIMARY).strong());
                        ui.add_space(4.0);
                        ui.label(egui::RichText::new(profile_info.description).size(11.0).color(TEXT_SECONDARY));
                        ui.add_space(8.0);
                        ui.label(egui::RichText::new(profile_info.settings_summary).size(10.0).color(TEXT_MUTED));
                        ui.add_space(6.0);
                        ui.horizontal(|ui| {
                            egui::Frame::NONE
                                .fill(ACCENT_PRIMARY.gamma_multiply(0.15))
                                .rounding(4.0)
                                .inner_margin(egui::Margin::symmetric(6, 2))
                                .show(ui, |ui| {
                                    ui.label(egui::RichText::new(profile_info.fps_target).size(10.0).color(ACCENT_PRIMARY));
                                });
                            ui.add_space(4.0);
                            ui.label(egui::RichText::new(format!("Best for: {}", profile_info.best_for)).size(10.0).color(TEXT_MUTED));
                        });
                    });
                }

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

        // ROBLOX FPS SETTINGS
        ui.add_space(16.0);

        let current_fps = self.state.config.roblox_settings.target_fps;
        let is_uncapped = current_fps >= 9999;
        let fps_display = if is_uncapped { "Uncapped".to_string() } else { format!("{}", current_fps) };

        egui::Frame::NONE
            .fill(BG_CARD).stroke(egui::Stroke::new(1.0, BG_ELEVATED))
            .rounding(12.0).inner_margin(20)
            .show(ui, |ui| {
                ui.set_min_width(ui.available_width());
                ui.label(egui::RichText::new("Roblox FPS Settings").size(14.0).color(TEXT_PRIMARY).strong());
                ui.add_space(12.0);

                ui.horizontal(|ui| {
                    ui.label(egui::RichText::new("Target FPS").size(13.0).color(TEXT_SECONDARY));
                    ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                        ui.label(egui::RichText::new(&fps_display).size(14.0).color(ACCENT_PRIMARY).strong());
                    });
                });

                ui.add_space(8.0);
                if !is_uncapped {
                    if ui.add(egui::Slider::new(&mut self.state.config.roblox_settings.target_fps, 30..=360).show_value(false)).changed() {
                        self.mark_dirty();
                    }
                } else {
                    ui.add_enabled(false, egui::Slider::new(&mut 360u32.clone(), 30..=360).show_value(false));
                }

                ui.add_space(12.0);
                ui.horizontal(|ui| {
                    for fps in [60, 120, 144, 240] {
                        let is_sel = current_fps == fps;
                        let (bg, text) = if is_sel { (ACCENT_PRIMARY, TEXT_PRIMARY) } else { (BG_ELEVATED, TEXT_SECONDARY) };
                        if ui.add(
                            egui::Button::new(egui::RichText::new(format!("{}", fps)).size(11.0).color(text))
                                .fill(bg).rounding(4.0).min_size(egui::vec2(44.0, 28.0))
                        ).clicked() {
                            self.state.config.roblox_settings.target_fps = fps;
                            self.mark_dirty();
                        }
                    }
                    let (bg, text) = if is_uncapped { (ACCENT_PRIMARY, TEXT_PRIMARY) } else { (BG_ELEVATED, TEXT_SECONDARY) };
                    if ui.add(
                        egui::Button::new(egui::RichText::new("Max").size(11.0).color(text))
                            .fill(bg).rounding(4.0).min_size(egui::vec2(44.0, 28.0))
                    ).clicked() {
                        self.state.config.roblox_settings.target_fps = 9999;
                        self.mark_dirty();
                    }
                });

                ui.add_space(8.0);
                ui.label(egui::RichText::new("FPS settings are protected from Roblox overwriting them").size(10.0).color(STATUS_CONNECTED));

                // GRAPHICS QUALITY SLIDER
                ui.add_space(16.0);
                ui.separator();
                ui.add_space(12.0);

                let current_quality = self.state.config.roblox_settings.graphics_quality.to_level();
                let quality_display = if current_quality == 0 { "Auto".to_string() } else { format!("Level {}", current_quality) };

                ui.horizontal(|ui| {
                    ui.label(egui::RichText::new("Graphics Quality").size(13.0).color(TEXT_SECONDARY));
                    ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                        ui.label(egui::RichText::new(&quality_display).size(14.0).color(ACCENT_CYAN).strong());
                    });
                });

                ui.add_space(8.0);

                // Slider for graphics quality (1-10)
                let mut quality_level = current_quality.max(1) as i32; // Ensure min of 1 for slider
                if ui.add(egui::Slider::new(&mut quality_level, 1..=10).show_value(false)).changed() {
                    self.state.config.roblox_settings.graphics_quality = GraphicsQuality::from_level(quality_level);
                    // Switch to Custom profile when manually changing graphics
                    if self.selected_profile != OptimizationProfile::Custom {
                        self.selected_profile = OptimizationProfile::Custom;
                    }
                    self.mark_dirty();
                }

                ui.add_space(12.0);

                // Quick preset buttons for common quality levels
                ui.horizontal(|ui| {
                    for (label, level) in [("1", 1), ("3", 3), ("5", 5), ("7", 7), ("10", 10)] {
                        let is_sel = current_quality == level;
                        let (bg, text) = if is_sel { (ACCENT_CYAN, TEXT_PRIMARY) } else { (BG_ELEVATED, TEXT_SECONDARY) };
                        if ui.add(
                            egui::Button::new(egui::RichText::new(label).size(11.0).color(text))
                                .fill(bg).rounding(4.0).min_size(egui::vec2(36.0, 28.0))
                        ).clicked() {
                            self.state.config.roblox_settings.graphics_quality = GraphicsQuality::from_level(level);
                            if self.selected_profile != OptimizationProfile::Custom {
                                self.selected_profile = OptimizationProfile::Custom;
                            }
                            self.mark_dirty();
                        }
                    }
                });

                ui.add_space(8.0);
                ui.horizontal(|ui| {
                    ui.label(egui::RichText::new("-").size(10.0));
                    ui.label(egui::RichText::new("Lower = better FPS, Higher = better visuals").size(10.0).color(TEXT_MUTED));
                });

                // DYNAMIC RENDER OPTIMIZATION
                ui.add_space(16.0);
                ui.separator();
                ui.add_space(12.0);

                let current_mode = self.state.config.roblox_settings.dynamic_render_optimization;
                let mode_display = match current_mode {
                    DynamicRenderMode::Off => "Off",
                    DynamicRenderMode::Low => "Low",
                    DynamicRenderMode::Medium => "Medium",
                    DynamicRenderMode::High => "High",
                };

                ui.horizontal(|ui| {
                    ui.label(egui::RichText::new("Dynamic Render").size(13.0).color(TEXT_SECONDARY));
                    ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                        let color = if current_mode == DynamicRenderMode::Off { TEXT_MUTED } else { ACCENT_LIME };
                        ui.label(egui::RichText::new(mode_display).size(14.0).color(color).strong());
                    });
                });

                ui.add_space(12.0);

                ui.horizontal(|ui| {
                    for (label, mode) in [
                        ("Off", DynamicRenderMode::Off),
                        ("Low", DynamicRenderMode::Low),
                        ("Med", DynamicRenderMode::Medium),
                        ("High", DynamicRenderMode::High),
                    ] {
                        let is_sel = current_mode == mode;
                        let (bg, text) = if is_sel { (ACCENT_LIME, egui::Color32::from_rgb(23, 23, 23)) } else { (BG_ELEVATED, TEXT_SECONDARY) };
                        if ui.add(
                            egui::Button::new(egui::RichText::new(label).size(11.0).color(text))
                                .fill(bg).rounding(4.0).min_size(egui::vec2(44.0, 28.0))
                        ).clicked() {
                            self.state.config.roblox_settings.dynamic_render_optimization = mode;
                            if self.selected_profile != OptimizationProfile::Custom {
                                self.selected_profile = OptimizationProfile::Custom;
                            }
                            self.mark_dirty();
                        }
                    }
                });

                ui.add_space(8.0);
                ui.horizontal(|ui| {
                    ui.label(egui::RichText::new("\u{26A1}").size(10.0).color(ACCENT_LIME));
                    ui.label(egui::RichText::new("Adaptive resolution for +5-30% FPS boost").size(10.0).color(TEXT_MUTED));
                });
            });

        // SYSTEM BOOSTS (Tier 1)
        ui.add_space(16.0);

        egui::Frame::NONE
            .fill(BG_CARD).stroke(egui::Stroke::new(1.0, BG_ELEVATED))
            .rounding(12.0).inner_margin(20)
            .show(ui, |ui| {
                ui.set_min_width(ui.available_width());
                ui.horizontal(|ui| {
                    ui.label(egui::RichText::new("System Boosts").size(14.0).color(TEXT_PRIMARY).strong());
                    ui.add_space(8.0);

                    // Tier 1 badge with tooltip
                    let tier_badge = egui::Frame::NONE
                        .fill(STATUS_CONNECTED.gamma_multiply(0.15))
                        .rounding(4.0)
                        .inner_margin(egui::Margin::symmetric(6, 2))
                        .show(ui, |ui| {
                            ui.label(egui::RichText::new("TIER 1 - SAFE").size(10.0).color(STATUS_CONNECTED));
                        });
                    if tier_badge.response.hovered() {
                        let tooltip_id = ui.id().with("tier1_tip");
                        egui::show_tooltip_at_pointer(ui.ctx(), egui::LayerId::new(egui::Order::Tooltip, tooltip_id), tooltip_id, |ui| {
                            ui.set_max_width(280.0);
                            ui.label(egui::RichText::new(tier_info::TIER_1_TITLE).size(12.0).color(TEXT_PRIMARY).strong());
                            ui.add_space(4.0);
                            ui.label(egui::RichText::new(tier_info::TIER_1_DESC).size(11.0).color(TEXT_SECONDARY));
                        });
                    }
                });
                ui.add_space(4.0);
                ui.label(egui::RichText::new("Safe optimizations with no side effects").size(11.0).color(TEXT_MUTED));
                ui.add_space(12.0);

                self.render_toggle_row_with_info(ui, &boost_info::HIGH_PRIORITY,
                    self.state.config.system_optimization.set_high_priority, |app| {
                    app.state.config.system_optimization.set_high_priority = !app.state.config.system_optimization.set_high_priority;
                });
                ui.add_space(10.0);

                self.render_toggle_row_with_info(ui, &boost_info::TIMER_RESOLUTION,
                    self.state.config.system_optimization.timer_resolution_1ms, |app| {
                    app.state.config.system_optimization.timer_resolution_1ms = !app.state.config.system_optimization.timer_resolution_1ms;
                });
                ui.add_space(10.0);

                self.render_toggle_row_with_info(ui, &boost_info::MMCSS,
                    self.state.config.system_optimization.mmcss_gaming_profile, |app| {
                    app.state.config.system_optimization.mmcss_gaming_profile = !app.state.config.system_optimization.mmcss_gaming_profile;
                });
                ui.add_space(10.0);

                self.render_toggle_row_with_info(ui, &boost_info::GAME_MODE,
                    self.state.config.system_optimization.game_mode_enabled, |app| {
                    app.state.config.system_optimization.game_mode_enabled = !app.state.config.system_optimization.game_mode_enabled;
                });
            });

        // NETWORK BOOSTS (Tier 1)
        ui.add_space(16.0);

        egui::Frame::NONE
            .fill(BG_CARD).stroke(egui::Stroke::new(1.0, BG_ELEVATED))
            .rounding(12.0).inner_margin(20)
            .show(ui, |ui| {
                ui.set_min_width(ui.available_width());
                ui.horizontal(|ui| {
                    ui.label(egui::RichText::new("Network Boosts").size(14.0).color(TEXT_PRIMARY).strong());
                    ui.add_space(8.0);

                    // Tier 1 badge with tooltip
                    let tier_badge = egui::Frame::NONE
                        .fill(STATUS_CONNECTED.gamma_multiply(0.15))
                        .rounding(4.0)
                        .inner_margin(egui::Margin::symmetric(6, 2))
                        .show(ui, |ui| {
                            ui.label(egui::RichText::new("TIER 1 - SAFE").size(10.0).color(STATUS_CONNECTED));
                        });
                    if tier_badge.response.hovered() {
                        let tooltip_id = ui.id().with("tier1_net_tip");
                        egui::show_tooltip_at_pointer(ui.ctx(), egui::LayerId::new(egui::Order::Tooltip, tooltip_id), tooltip_id, |ui| {
                            ui.set_max_width(280.0);
                            ui.label(egui::RichText::new(tier_info::TIER_1_TITLE).size(12.0).color(TEXT_PRIMARY).strong());
                            ui.add_space(4.0);
                            ui.label(egui::RichText::new(tier_info::TIER_1_DESC).size(11.0).color(TEXT_SECONDARY));
                        });
                    }
                });
                ui.add_space(4.0);
                ui.label(egui::RichText::new("Lower latency for online games").size(11.0).color(TEXT_MUTED));
                ui.add_space(12.0);

                self.render_toggle_row_with_info(ui, &boost_info::DISABLE_NAGLE,
                    self.state.config.network_settings.disable_nagle, |app| {
                    app.state.config.network_settings.disable_nagle = !app.state.config.network_settings.disable_nagle;
                });
                ui.add_space(10.0);

                self.render_toggle_row_with_info(ui, &boost_info::NETWORK_THROTTLING,
                    self.state.config.network_settings.disable_network_throttling, |app| {
                    app.state.config.network_settings.disable_network_throttling = !app.state.config.network_settings.disable_network_throttling;
                });
                ui.add_space(10.0);

                self.render_toggle_row_with_info(ui, &boost_info::OPTIMIZE_MTU,
                    self.state.config.network_settings.optimize_mtu, |app| {
                    app.state.config.network_settings.optimize_mtu = !app.state.config.network_settings.optimize_mtu;
                });
            });

        // SYSTEM PROTECTION
        ui.add_space(16.0);

        let mut create_restore_point = false;
        let mut open_restore = false;

        egui::Frame::NONE
            .fill(BG_CARD).stroke(egui::Stroke::new(1.0, BG_ELEVATED))
            .rounding(12.0).inner_margin(20)
            .show(ui, |ui| {
                ui.set_min_width(ui.available_width());
                ui.label(egui::RichText::new("System Protection").size(14.0).color(TEXT_PRIMARY).strong());
                ui.add_space(4.0);
                ui.label(egui::RichText::new("Create restore points before making changes").size(11.0).color(TEXT_MUTED));
                ui.add_space(16.0);

                ui.horizontal(|ui| {
                    if ui.add(
                        egui::Button::new(egui::RichText::new("+ Create Restore Point").size(13.0).color(TEXT_PRIMARY))
                            .fill(ACCENT_PRIMARY).rounding(8.0).min_size(egui::vec2(180.0, 38.0))
                    ).clicked() {
                        create_restore_point = true;
                    }

                    ui.add_space(12.0);

                    if ui.add(
                        egui::Button::new(egui::RichText::new("~ Open System Restore").size(13.0).color(TEXT_PRIMARY))
                            .fill(BG_ELEVATED).rounding(8.0).min_size(egui::vec2(180.0, 38.0))
                    ).clicked() {
                        open_restore = true;
                    }
                });

                if let Some((msg, color, _)) = &self.restore_point_status {
                    ui.add_space(12.0);
                    ui.label(egui::RichText::new(msg).size(12.0).color(*color));
                }
            });

        if create_restore_point {
            match SystemOptimizer::create_restore_point("SwiftTunnel - Before PC Boosts") {
                Ok(desc) => {
                    self.restore_point_status = Some((
                        format!("+ Restore point created: {}", desc),
                        STATUS_CONNECTED,
                        std::time::Instant::now()
                    ));
                }
                Err(e) => {
                    self.restore_point_status = Some((
                        format!("x Failed: {}", e),
                        STATUS_ERROR,
                        std::time::Instant::now()
                    ));
                }
            }
        }

        if open_restore {
            if let Err(e) = SystemOptimizer::open_system_restore() {
                self.restore_point_status = Some((
                    format!("x Failed to open: {}", e),
                    STATUS_ERROR,
                    std::time::Instant::now()
                ));
            }
        }

        // Show status message if any
        if let Some((msg, color, _)) = &self.status_message {
            ui.add_space(16.0);
            ui.label(egui::RichText::new(msg).size(13.0).color(*color));
        }
    }

    pub(crate) fn render_toggle_row(&mut self, ui: &mut egui::Ui, label: &str, description: &str, value: bool, on_toggle: fn(&mut Self)) {
        self.render_animated_toggle_row(ui, label, description, None, value, on_toggle);
    }

    pub(crate) fn render_toggle_row_with_info(&mut self, ui: &mut egui::Ui, info: &boost_info::BoostInfo, value: bool, on_toggle: fn(&mut Self)) {
        self.render_animated_toggle_row(ui, info.name, info.description, Some(info), value, on_toggle);
    }

    pub(crate) fn render_animated_toggle_row(
        &mut self,
        ui: &mut egui::Ui,
        label: &str,
        description: &str,
        info: Option<&boost_info::BoostInfo>,
        value: bool,
        on_toggle: fn(&mut Self),
    ) {
        let toggle_id = format!("toggle_{}", label);

        // Get current animation value and trigger animation if needed
        let current_anim_val = self.animations.get_toggle_value(&toggle_id, value);
        self.animations.animate_toggle(&toggle_id, value, current_anim_val);
        let anim_val = self.animations.get_toggle_value(&toggle_id, value);

        // Check if this toggle's info panel is expanded
        let is_expanded = self.expanded_boost_info.contains(&toggle_id);

        let response = ui.horizontal(|ui| {
            ui.vertical(|ui| {
                // Name + description row
                ui.horizontal(|ui| {
                    ui.label(egui::RichText::new(label).size(13.0).color(TEXT_PRIMARY));

                    // Info expand button (if we have detailed info)
                    if info.is_some() {
                        let expand_char = if is_expanded { "-" } else { "?" };
                        if ui.add(
                            egui::Button::new(egui::RichText::new(expand_char).size(10.0).color(TEXT_MUTED))
                                .fill(egui::Color32::TRANSPARENT)
                                .frame(false)
                        ).clicked() {
                            if is_expanded {
                                self.expanded_boost_info.remove(&toggle_id);
                            } else {
                                self.expanded_boost_info.insert(toggle_id.clone());
                            }
                            self.mark_dirty();
                        }
                    }
                });

                ui.label(egui::RichText::new(description).size(11.0).color(TEXT_MUTED));

                // Expanded info panel (technical details + impact)
                if is_expanded {
                    if let Some(boost_info) = info {
                        ui.add_space(6.0);
                        egui::Frame::NONE
                            .fill(BG_ELEVATED.gamma_multiply(0.5))
                            .rounding(6.0)
                            .inner_margin(egui::Margin::symmetric(10, 8))
                            .show(ui, |ui| {
                                ui.set_max_width(ui.available_width() - 60.0); // Leave room for toggle

                                ui.horizontal(|ui| {
                                    ui.label(egui::RichText::new(">").size(10.0).color(ACCENT_PRIMARY));
                                    ui.add_space(4.0);
                                    ui.label(egui::RichText::new("Technical:").size(10.0).color(TEXT_SECONDARY));
                                    ui.label(egui::RichText::new(boost_info.technical).size(10.0).color(TEXT_MUTED));
                                });
                                ui.add_space(4.0);
                                ui.horizontal(|ui| {
                                    ui.label(egui::RichText::new("+").size(10.0).color(STATUS_CONNECTED));
                                    ui.add_space(4.0);
                                    ui.label(egui::RichText::new("Impact:").size(10.0).color(TEXT_SECONDARY));
                                    ui.label(egui::RichText::new(boost_info.impact).size(10.0).color(STATUS_CONNECTED));
                                });
                            });
                    }
                }
            });

            ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                // Custom toggle switch with animation
                let toggle_width = 44.0;
                let toggle_height = 24.0;
                let (toggle_rect, toggle_response) = ui.allocate_exact_size(
                    egui::vec2(toggle_width, toggle_height),
                    egui::Sense::click()
                );

                // Background track - animate color
                let bg_color = lerp_color(BG_ELEVATED, STATUS_CONNECTED, anim_val);
                ui.painter().rect_filled(toggle_rect, toggle_height / 2.0, bg_color);

                // Knob - animate position
                let knob_radius = (toggle_height - 6.0) / 2.0;
                let knob_x_off = anim_val * (toggle_width - toggle_height);
                let knob_center = egui::pos2(
                    toggle_rect.left() + toggle_height / 2.0 + knob_x_off,
                    toggle_rect.center().y
                );
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
