//! Toggle switch components
//!
//! Animated toggle switches with multiple styles.

use eframe::egui::{self, Color32, Ui, Sense, Vec2, Pos2};
use crate::gui::theme::*;
use crate::gui::animations::AnimationManager;

/// Style variants for toggle switches
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum ToggleStyle {
    /// Standard toggle (pill shape)
    Standard,
    /// Compact toggle for tight spaces
    Compact,
    /// Card-style toggle (full width)
    Card,
}

/// Render an animated toggle switch
/// Returns true if the toggle was clicked
pub fn toggle_switch(
    ui: &mut Ui,
    id: &str,
    enabled: bool,
    animations: &mut AnimationManager,
    style: ToggleStyle,
) -> bool {
    let (size, knob_size, padding) = match style {
        ToggleStyle::Standard => (Vec2::new(52.0, 28.0), 20.0, 4.0),
        ToggleStyle::Compact => (Vec2::new(40.0, 22.0), 16.0, 3.0),
        ToggleStyle::Card => (Vec2::new(48.0, 26.0), 18.0, 4.0),
    };

    let (rect, response) = ui.allocate_exact_size(size, Sense::click());

    if response.clicked() {
        // Start animation
        let current = animations.get_toggle_value(id, enabled);
        animations.animate_toggle(id, !enabled, current);
        return true;
    }

    if ui.is_rect_visible(rect) {
        let anim_value = animations.get_toggle_value(id, enabled);

        // Background colors
        let bg_off = BG_ELEVATED;
        let bg_on = ACCENT_PRIMARY;
        let bg_color = lerp_color(bg_off, bg_on, anim_value);

        // Border
        let border_off = BG_HOVER;
        let border_on = ACCENT_PRIMARY.gamma_multiply(0.8);
        let border_color = lerp_color(border_off, border_on, anim_value);

        // Draw track
        let rounding = size.y / 2.0;
        ui.painter().rect_filled(rect, rounding, bg_color);
        ui.painter().rect_stroke(rect, rounding, egui::Stroke::new(1.0, border_color));

        // Draw knob
        let knob_travel = size.x - knob_size - padding * 2.0;
        let knob_x = rect.min.x + padding + knob_travel * anim_value + knob_size / 2.0;
        let knob_center = Pos2::new(knob_x, rect.center().y);

        // Knob glow when on
        if anim_value > 0.5 {
            let glow_alpha = (anim_value - 0.5) * 2.0 * 0.3;
            ui.painter().circle_filled(
                knob_center,
                knob_size / 2.0 + 2.0,
                ACCENT_CYAN.gamma_multiply(glow_alpha),
            );
        }

        // Knob
        ui.painter().circle_filled(knob_center, knob_size / 2.0, TEXT_PRIMARY);
    }

    false
}

/// Render a labeled toggle switch (label on left, toggle on right)
/// Returns true if the toggle was clicked
pub fn labeled_toggle(
    ui: &mut Ui,
    id: &str,
    label: &str,
    enabled: bool,
    animations: &mut AnimationManager,
) -> bool {
    let mut clicked = false;

    ui.horizontal(|ui| {
        ui.label(egui::RichText::new(label).size(13.0).color(TEXT_PRIMARY));
        ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
            clicked = toggle_switch(ui, id, enabled, animations, ToggleStyle::Standard);
        });
    });

    clicked
}

/// Render a toggle with icon and description (for boost settings)
/// Returns true if clicked
pub fn boost_toggle(
    ui: &mut Ui,
    id: &str,
    icon: &str,
    title: &str,
    description: &str,
    enabled: bool,
    animations: &mut AnimationManager,
    is_expanded: bool,
) -> (bool, bool) {
    // Returns (clicked, expand_clicked)
    let mut clicked = false;
    let mut expand_clicked = false;

    egui::Frame::none()
        .fill(if enabled { ACCENT_PRIMARY.gamma_multiply(0.08) } else { BG_ELEVATED })
        .stroke(egui::Stroke::new(
            1.0,
            if enabled { ACCENT_PRIMARY.gamma_multiply(0.3) } else { BG_HOVER }
        ))
        .rounding(10.0)
        .inner_margin(egui::Margin::symmetric(14.0, 12.0))
        .show(ui, |ui| {
            ui.set_min_width(ui.available_width());

            ui.horizontal(|ui| {
                // Icon
                ui.label(egui::RichText::new(icon).size(18.0));

                ui.add_space(8.0);

                // Title and toggle
                ui.vertical(|ui| {
                    ui.horizontal(|ui| {
                        ui.label(egui::RichText::new(title)
                            .size(13.0)
                            .color(TEXT_PRIMARY)
                            .strong());

                        // Info button
                        let info_response = ui.add(
                            egui::Button::new(
                                egui::RichText::new(if is_expanded { "−" } else { "?" })
                                    .size(11.0)
                                    .color(TEXT_MUTED)
                            )
                            .fill(Color32::TRANSPARENT)
                            .frame(false)
                            .min_size(Vec2::new(20.0, 20.0))
                        );
                        if info_response.clicked() {
                            expand_clicked = true;
                        }

                        ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                            clicked = toggle_switch(ui, id, enabled, animations, ToggleStyle::Compact);
                        });
                    });

                    // Brief description
                    ui.label(egui::RichText::new(description)
                        .size(11.0)
                        .color(TEXT_MUTED));
                });
            });

            // Expanded info panel
            if is_expanded {
                ui.add_space(8.0);
                egui::Frame::none()
                    .fill(BG_CARD)
                    .rounding(6.0)
                    .inner_margin(10.0)
                    .show(ui, |ui| {
                        ui.label(egui::RichText::new(get_boost_details(id))
                            .size(11.0)
                            .color(TEXT_SECONDARY));
                    });
            }
        });

    (clicked, expand_clicked)
}

/// Get detailed description for a boost setting
fn get_boost_details(id: &str) -> &'static str {
    match id {
        "high_priority" => "Sets the game process to High priority, giving it more CPU time. This can improve frame times and reduce micro-stutters. Risk: Low - may cause other apps to feel sluggish.",
        "timer_resolution" => "Reduces Windows timer resolution to 1ms for smoother frame pacing. Improves consistency of frame delivery. Risk: None - automatically resets when disabled.",
        "mmcss" => "Enables Multimedia Class Scheduler Service optimizations for gaming threads. Windows reserves CPU time for game audio and input processing. Risk: Low.",
        "game_mode" => "Enables Windows Game Mode which prioritizes game performance and reduces background interruptions. Risk: None.",
        "nagle" => "Disables Nagle's algorithm which batches small packets. Reduces network latency at the cost of slightly more bandwidth. Risk: Very low.",
        "throttling" => "Disables Windows network throttling for multimedia applications. Allows higher throughput for game traffic. Risk: None.",
        "mtu" => "Optimizes Maximum Transmission Unit size for gaming. Can reduce packet fragmentation and improve latency. Risk: Low - reverts on disable.",
        _ => "No additional details available.",
    }
}

/// Master VPN toggle pill (for header)
pub fn master_toggle_pill(
    ui: &mut Ui,
    is_connected: bool,
    is_connecting: bool,
    animations: &mut AnimationManager,
) -> bool {
    let mut clicked = false;
    let id = "master_toggle";

    // Determine state
    let (label, bg_color, text_color) = if is_connecting {
        ("Connecting...", STATUS_WARNING, Color32::BLACK)
    } else if is_connected {
        ("SwiftTunnel ON", STATUS_CONNECTED, Color32::BLACK)
    } else {
        ("SwiftTunnel OFF", BG_ELEVATED, TEXT_PRIMARY)
    };

    let size = Vec2::new(160.0, 36.0);
    let (rect, response) = ui.allocate_exact_size(size, Sense::click());

    if response.clicked() && !is_connecting {
        clicked = true;
    }

    if ui.is_rect_visible(rect) {
        // Draw pill background
        let rounding = size.y / 2.0;

        // Hover effect
        let hover_val = animations.get_hover_value(id);
        let final_bg = if response.hovered() && !is_connecting {
            lerp_color(bg_color, bg_color.gamma_multiply(1.2), hover_val)
        } else {
            bg_color
        };

        ui.painter().rect_filled(rect, rounding, final_bg);

        // Border
        let border_color = if is_connected {
            STATUS_CONNECTED.gamma_multiply(0.5)
        } else if is_connecting {
            STATUS_WARNING.gamma_multiply(0.5)
        } else {
            BG_HOVER
        };
        ui.painter().rect_stroke(rect, rounding, egui::Stroke::new(1.0, border_color));

        // Label
        let font = egui::FontId::proportional(13.0);
        let galley = ui.painter().layout_no_wrap(label.to_string(), font, text_color);
        let text_pos = rect.center() - galley.size() / 2.0;
        ui.painter().galley(text_pos, galley, text_color);
    }

    // Update hover animation
    animations.animate_hover(id, response.hovered(), animations.get_hover_value(id));

    clicked
}
