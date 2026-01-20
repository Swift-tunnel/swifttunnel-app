//! Card components
//!
//! Various card styles for game selection, regions, and info panels.

use eframe::egui::{self, Ui, Sense, Vec2};
use crate::gui::theme::*;
use crate::gui::animations::AnimationManager;

/// Game card for split tunnel selection
/// Returns true if clicked
pub fn game_card(
    ui: &mut Ui,
    id: &str,
    icon: &str,
    name: &str,
    is_selected: bool,
    is_disabled: bool,
    animations: &mut AnimationManager,
) -> bool {
    let mut clicked = false;
    let card_id = format!("game_card_{}", id);

    let card_bg = if is_selected {
        ACCENT_PRIMARY.gamma_multiply(0.15)
    } else {
        BG_ELEVATED
    };

    let card_border = if is_selected {
        ACCENT_PRIMARY.gamma_multiply(0.5)
    } else {
        BG_HOVER
    };

    let hover_val = animations.get_hover_value(&card_id);

    egui::Frame::none()
        .fill(lerp_color(card_bg, BG_HOVER, if is_disabled { 0.0 } else { hover_val * 0.3 }))
        .stroke(egui::Stroke::new(1.5, card_border))
        .rounding(CARD_ROUNDING)
        .inner_margin(egui::Margin::symmetric(12.0, 14.0))
        .show(ui, |ui| {
            let response = ui.interact(
                ui.min_rect(),
                egui::Id::new(&card_id),
                if is_disabled { Sense::hover() } else { Sense::click() },
            );

            if response.clicked() && !is_disabled {
                clicked = true;
            }

            animations.animate_hover(&card_id, response.hovered(), hover_val);

            ui.vertical_centered(|ui| {
                // Icon
                ui.label(egui::RichText::new(icon)
                    .size(32.0)
                    .color(if is_disabled { TEXT_DIMMED } else { TEXT_PRIMARY }));

                ui.add_space(6.0);

                // Name
                ui.label(egui::RichText::new(name)
                    .size(13.0)
                    .color(if is_disabled { TEXT_MUTED } else { TEXT_PRIMARY })
                    .strong());

                ui.add_space(4.0);

                // Status text
                let status = if is_disabled {
                    "VPN Required"
                } else if is_selected {
                    "Split Tunnel ✓"
                } else {
                    "Split Tunnel"
                };
                ui.label(egui::RichText::new(status)
                    .size(10.0)
                    .color(if is_selected { ACCENT_PRIMARY } else { TEXT_MUTED }));
            });
        });

    clicked
}

/// Render a styled country code badge (replaces emoji flags which don't render on Windows)
fn render_country_badge(ui: &mut Ui, region_id: &str) {
    use crate::gui::theme::{get_region_code, get_region_flag_color};

    let code = get_region_code(region_id);
    let (primary, _secondary) = get_region_flag_color(region_id);

    let badge_size = Vec2::new(40.0, 28.0);
    let (rect, _) = ui.allocate_exact_size(badge_size, Sense::hover());

    // Draw badge background with subtle gradient
    ui.painter().rect_filled(rect, 6.0, primary.gamma_multiply(0.85));

    // Draw country code text
    let font = egui::FontId::new(14.0, egui::FontFamily::Monospace);
    let galley = ui.painter().layout_no_wrap(code.to_string(), font, TEXT_PRIMARY);
    let text_pos = egui::Pos2::new(
        rect.center().x - galley.size().x / 2.0,
        rect.center().y - galley.size().y / 2.0,
    );
    ui.painter().galley(text_pos, galley, TEXT_PRIMARY);
}

/// Region card for server selection
/// Returns true if clicked
pub fn region_card(
    ui: &mut Ui,
    id: &str,
    _flag: &str, // Deprecated - flags don't render on Windows
    name: &str,
    latency: Option<u32>,
    is_selected: bool,
    is_last_used: bool,
    is_loading: bool,
    animations: &mut AnimationManager,
) -> bool {
    let card_id = format!("region_card_{}", id);
    let hover_val = animations.get_hover_value(&card_id);

    // Colors based on selection and hover
    let (bg_color, border_color, border_width) = if is_selected {
        (
            lerp_color(ACCENT_PRIMARY.gamma_multiply(0.15), ACCENT_PRIMARY.gamma_multiply(0.22), hover_val),
            ACCENT_PRIMARY,
            2.0
        )
    } else {
        (
            lerp_color(BG_ELEVATED, BG_HOVER, hover_val * 0.5),
            lerp_color(BG_HOVER, ACCENT_PRIMARY.gamma_multiply(0.5), hover_val),
            1.0
        )
    };

    let mut clicked = false;

    egui::Frame::none()
        .fill(bg_color)
        .stroke(egui::Stroke::new(border_width, border_color))
        .rounding(10.0)
        .inner_margin(egui::Margin::symmetric(12.0, 10.0))
        .show(ui, |ui| {
            let response = ui.interact(
                ui.max_rect(),
                egui::Id::new(&card_id),
                Sense::click(),
            );

            if response.clicked() {
                clicked = true;
            }

            animations.animate_hover(&card_id, response.hovered(), hover_val);

            ui.horizontal(|ui| {
                // Country code badge
                render_country_badge(ui, id);

                ui.add_space(10.0);

                // Name and latency
                ui.vertical(|ui| {
                    // Region name with badges
                    ui.horizontal(|ui| {
                        ui.label(egui::RichText::new(name)
                            .size(13.0)
                            .color(TEXT_PRIMARY)
                            .strong());

                        if is_selected {
                            ui.add_space(4.0);
                            ui.label(egui::RichText::new("✓")
                                .size(11.0)
                                .color(ACCENT_PRIMARY));
                        } else if is_last_used {
                            ui.add_space(4.0);
                            ui.label(egui::RichText::new("LAST")
                                .size(9.0)
                                .color(ACCENT_SECONDARY));
                        }
                    });

                    ui.add_space(4.0);

                    // Latency
                    if is_loading && latency.is_none() {
                        let dots = match ((ui.ctx().input(|i| i.time) * 2.0) as i32 % 4) {
                            0 => ".",
                            1 => "..",
                            2 => "...",
                            _ => "....",
                        };
                        ui.label(egui::RichText::new(format!("Measuring{}", dots))
                            .size(11.0)
                            .color(TEXT_MUTED));
                    } else if let Some(ms) = latency {
                        let color = latency_color(ms);
                        ui.horizontal(|ui| {
                            // Small latency bar
                            let bar_width = 50.0;
                            let bar_height = 4.0;
                            let fill = latency_fill_percent(ms);
                            let (rect, _) = ui.allocate_exact_size(Vec2::new(bar_width, bar_height), Sense::hover());
                            ui.painter().rect_filled(rect, 2.0, BG_CARD);
                            let fill_rect = egui::Rect::from_min_size(rect.min, Vec2::new(bar_width * fill, bar_height));
                            ui.painter().rect_filled(fill_rect, 2.0, color);

                            ui.add_space(8.0);
                            ui.label(egui::RichText::new(format!("{}ms", ms))
                                .size(11.0)
                                .color(color));
                        });
                    } else {
                        ui.label(egui::RichText::new("—")
                            .size(11.0)
                            .color(TEXT_DIMMED));
                    }
                });
            });
        });

    clicked
}

/// Boost preset card (Performance, Balanced, Quality)
/// Returns true if clicked
pub fn preset_card(
    ui: &mut Ui,
    id: &str,
    icon: &str,
    name: &str,
    description: &str,
    is_selected: bool,
    animations: &mut AnimationManager,
) -> bool {
    let mut clicked = false;
    let card_id = format!("preset_card_{}", id);

    let card_bg = if is_selected {
        ACCENT_PRIMARY.gamma_multiply(0.2)
    } else {
        BG_ELEVATED
    };

    let card_border = if is_selected {
        ACCENT_PRIMARY
    } else {
        BG_HOVER
    };

    let hover_val = animations.get_hover_value(&card_id);

    let response = egui::Frame::none()
        .fill(lerp_color(card_bg, BG_HOVER, hover_val * 0.3))
        .stroke(egui::Stroke::new(if is_selected { 2.0 } else { 1.0 }, card_border))
        .rounding(CARD_ROUNDING)
        .inner_margin(CONTENT_PADDING_SM)
        .show(ui, |ui| {
            ui.vertical_centered(|ui| {
                ui.label(egui::RichText::new(icon).size(24.0));
                ui.add_space(4.0);
                ui.label(egui::RichText::new(name)
                    .size(13.0)
                    .color(if is_selected { ACCENT_PRIMARY } else { TEXT_PRIMARY })
                    .strong());
                ui.label(egui::RichText::new(description)
                    .size(10.0)
                    .color(TEXT_MUTED));
            });
        })
        .response;

    let sense_response = ui.interact(response.rect, egui::Id::new(&card_id), Sense::click());
    if sense_response.clicked() {
        clicked = true;
    }

    animations.animate_hover(&card_id, sense_response.hovered(), hover_val);

    clicked
}

/// Section card wrapper with clear visual hierarchy
pub fn section_card<R>(
    ui: &mut Ui,
    title: &str,
    icon: Option<&str>,
    badge: Option<&str>,
    add_contents: impl FnOnce(&mut Ui) -> R,
) -> R {
    egui::Frame::none()
        .fill(BG_CARD)
        .stroke(egui::Stroke::new(1.0, BG_ELEVATED))
        .rounding(CARD_ROUNDING)
        .inner_margin(egui::Margin::symmetric(20.0, 16.0))
        .show(ui, |ui| {
            // Section header
            ui.horizontal(|ui| {
                // Icon badge
                if let Some(icon) = icon {
                    egui::Frame::none()
                        .fill(ACCENT_PRIMARY.gamma_multiply(0.1))
                        .rounding(6.0)
                        .inner_margin(egui::Margin::symmetric(6.0, 4.0))
                        .show(ui, |ui| {
                            ui.label(egui::RichText::new(icon).size(14.0));
                        });
                    ui.add_space(8.0);
                }

                // Title
                ui.label(egui::RichText::new(title)
                    .size(13.0)
                    .color(TEXT_SECONDARY)
                    .strong());

                // Badge on the right
                if let Some(badge) = badge {
                    ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                        egui::Frame::none()
                            .fill(BG_ELEVATED)
                            .rounding(4.0)
                            .inner_margin(egui::Margin::symmetric(8.0, 3.0))
                            .show(ui, |ui| {
                                ui.label(egui::RichText::new(badge)
                                    .size(10.0)
                                    .color(TEXT_MUTED));
                            });
                    });
                }
            });

            // Separator
            ui.add_space(12.0);
            ui.separator();
            ui.add_space(12.0);

            add_contents(ui)
        })
        .inner
}

/// Render shimmer loading effect
fn render_shimmer(ui: &mut Ui, rect: egui::Rect, _animations: &AnimationManager) {
    // Simple shimmer effect
    let time = ui.ctx().input(|i| i.time);
    let shimmer = ((time * 2.0).sin() as f32 + 1.0) / 2.0;

    let base_color = BG_ELEVATED;
    let shimmer_color = lerp_color(base_color, BG_HOVER, shimmer);

    ui.painter().rect_filled(rect, 2.0, shimmer_color);
}

/// Info stat card (for displaying IP, uptime, etc.)
pub fn stat_card(
    ui: &mut Ui,
    label: &str,
    value: &str,
    icon: Option<&str>,
) {
    let available_width = ui.available_width();
    let available_height = ui.available_height();

    egui::Frame::none()
        .fill(BG_ELEVATED)
        .stroke(egui::Stroke::new(1.0, BG_HOVER))
        .rounding(10.0)
        .inner_margin(egui::Margin::symmetric(14.0, 12.0))
        .show(ui, |ui| {
            ui.set_min_width(available_width - 28.0);
            ui.set_min_height(available_height - 24.0);

            ui.vertical(|ui| {
                // Label row with icon
                ui.horizontal(|ui| {
                    if let Some(icon) = icon {
                        ui.label(egui::RichText::new(icon)
                            .size(10.0)
                            .color(ACCENT_PRIMARY));
                        ui.add_space(4.0);
                    }
                    ui.label(egui::RichText::new(label)
                        .size(10.0)
                        .color(TEXT_MUTED));
                });

                ui.add_space(6.0);

                // Value with monospace font for numbers
                ui.label(egui::RichText::new(value)
                    .size(14.0)
                    .color(TEXT_PRIMARY)
                    .strong());
            });
        });
}
