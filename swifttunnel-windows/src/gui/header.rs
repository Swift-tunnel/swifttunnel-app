//! Header bar component
//!
//! Top header with master VPN toggle and status

use eframe::egui::{self, Color32, Ui, Sense, Vec2, Pos2, Rect};
use crate::gui::theme::*;
use crate::gui::animations::AnimationManager;
use crate::gui::components::toggle::master_toggle_pill;

/// Header action returned from render
pub enum HeaderAction {
    None,
    ToggleVpn,
    Minimize,
    Close,
}

/// Render the header bar
pub fn render_header(
    ui: &mut Ui,
    is_connected: bool,
    is_connecting: bool,
    connected_region: Option<&str>,
    connected_latency: Option<u32>,
    animations: &mut AnimationManager,
    app_start_time: std::time::Instant,
) -> HeaderAction {
    let mut action = HeaderAction::None;

    let header_rect = ui.available_rect_before_wrap();
    let header_rect = Rect::from_min_size(
        header_rect.min,
        Vec2::new(header_rect.width(), HEADER_HEIGHT),
    );

    // Draw header background
    ui.painter().rect_filled(header_rect, 0.0, BG_MAIN);

    // Draw bottom border
    let border_rect = Rect::from_min_size(
        Pos2::new(header_rect.min.x, header_rect.max.y - 1.0),
        Vec2::new(header_rect.width(), 1.0),
    );
    ui.painter().rect_filled(border_rect, 0.0, BG_ELEVATED);

    ui.allocate_ui_at_rect(header_rect, |ui| {
        ui.horizontal(|ui| {
            ui.set_min_height(HEADER_HEIGHT);

            ui.add_space(16.0);

            // Left: Title
            ui.vertical(|ui| {
                ui.add_space(12.0);
                ui.label(egui::RichText::new("SwiftTunnel")
                    .size(18.0)
                    .color(TEXT_PRIMARY)
                    .strong());
                ui.label(egui::RichText::new("Game Booster")
                    .size(10.0)
                    .color(TEXT_DIMMED));
            });

            ui.add_space(24.0);

            // Center: Master toggle
            ui.vertical(|ui| {
                ui.add_space(12.0);
                if master_toggle_pill(ui, is_connected, is_connecting, animations) {
                    action = HeaderAction::ToggleVpn;
                }
            });

            ui.add_space(16.0);

            // Center-right: Status text
            ui.vertical(|ui| {
                ui.add_space(14.0);
                let status_text = if is_connected {
                    if let Some(region) = connected_region {
                        let flag = get_region_flag(region);
                        let name = get_region_name(region);
                        if let Some(ms) = connected_latency {
                            format!("Protected • {} {} • {}ms", flag, name, ms)
                        } else {
                            format!("Protected • {} {}", flag, name)
                        }
                    } else {
                        "Protected".to_string()
                    }
                } else if is_connecting {
                    "Establishing connection...".to_string()
                } else {
                    "Disconnected".to_string()
                };

                let status_color = if is_connected {
                    STATUS_CONNECTED
                } else if is_connecting {
                    STATUS_WARNING
                } else {
                    TEXT_MUTED
                };

                ui.label(egui::RichText::new(status_text)
                    .size(11.0)
                    .color(status_color));
            });

            // Right: Window controls
            ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                ui.add_space(8.0);

                // Close button
                if render_window_button(ui, "×", STATUS_ERROR, "close") {
                    action = HeaderAction::Close;
                }

                ui.add_space(4.0);

                // Minimize button
                if render_window_button(ui, "−", TEXT_MUTED, "minimize") {
                    action = HeaderAction::Minimize;
                }
            });
        });
    });

    action
}

/// Render a window control button
fn render_window_button(ui: &mut Ui, icon: &str, hover_color: Color32, id: &str) -> bool {
    let size = Vec2::new(32.0, 28.0);
    let (rect, response) = ui.allocate_exact_size(size, Sense::click());

    if ui.is_rect_visible(rect) {
        // Background on hover
        if response.hovered() {
            ui.painter().rect_filled(rect, 4.0, hover_color.gamma_multiply(0.2));
        }

        // Icon
        let icon_color = if response.hovered() { hover_color } else { TEXT_SECONDARY };
        let font = egui::FontId::proportional(16.0);
        let galley = ui.painter().layout_no_wrap(icon.to_string(), font, icon_color);
        let icon_pos = Pos2::new(
            rect.center().x - galley.size().x / 2.0,
            rect.center().y - galley.size().y / 2.0,
        );
        ui.painter().galley(icon_pos, galley, icon_color);
    }

    response.clicked()
}

/// Render compact header for logged-out state
pub fn render_auth_header(ui: &mut Ui, app_start_time: std::time::Instant) {
    let header_height = 80.0;

    egui::Frame::none()
        .fill(BG_CARD)
        .rounding(egui::Rounding {
            nw: CARD_ROUNDING,
            ne: CARD_ROUNDING,
            sw: 0.0,
            se: 0.0,
        })
        .inner_margin(CONTENT_PADDING)
        .show(ui, |ui| {
            ui.set_min_width(ui.available_width());

            ui.horizontal(|ui| {
                // Animated logo
                let logo_size = 48.0;
                let (rect, _) = ui.allocate_exact_size(Vec2::new(logo_size, logo_size), Sense::hover());
                let center = rect.center();

                let elapsed = app_start_time.elapsed().as_secs_f32();
                let rotation = elapsed * 0.5;

                let ring_color_1 = lerp_color(ACCENT_PRIMARY, ACCENT_CYAN, ((rotation).sin() + 1.0) / 2.0);
                let ring_color_2 = lerp_color(ACCENT_CYAN, ACCENT_SECONDARY, ((rotation + 1.0).sin() + 1.0) / 2.0);

                ui.painter().circle_filled(center, logo_size * 0.42, BG_ELEVATED);

                for i in 0..8 {
                    let angle_start = (i as f32 / 8.0) * std::f32::consts::TAU + rotation;
                    let color = lerp_color(ring_color_1, ring_color_2, i as f32 / 8.0);
                    let alpha = 0.6 + (((angle_start * 2.0).sin() + 1.0) / 2.0) * 0.4;

                    for j in 0..3 {
                        let angle = angle_start + j as f32 * 0.05;
                        let x = center.x + angle.cos() * (logo_size * 0.38);
                        let y = center.y + angle.sin() * (logo_size * 0.38);
                        ui.painter().circle_filled(Pos2::new(x, y), 2.5, color.gamma_multiply(alpha));
                    }
                }

                // Inner wave
                let wave_color = ACCENT_CYAN;
                for i in 0..3 {
                    let offset = (i as f32 - 1.0) * 5.0;
                    let start = Pos2::new(center.x - 10.0, center.y + offset);
                    let end = Pos2::new(center.x + 10.0, center.y + offset);
                    let control1 = Pos2::new(center.x - 4.0, center.y + offset - 5.0);
                    let control2 = Pos2::new(center.x + 4.0, center.y + offset + 5.0);

                    let points = [start, control1, control2, end];
                    let alpha = 0.6 + (i as f32 * 0.2);
                    let stroke = egui::Stroke::new(2.5, wave_color.gamma_multiply(alpha));
                    ui.painter().add(egui::Shape::CubicBezier(egui::epaint::CubicBezierShape::from_points_stroke(
                        points,
                        false,
                        Color32::TRANSPARENT,
                        stroke,
                    )));
                }

                ui.add_space(16.0);

                // Title
                ui.vertical(|ui| {
                    ui.label(egui::RichText::new("SwiftTunnel")
                        .size(24.0)
                        .color(TEXT_PRIMARY)
                        .strong());
                    ui.label(egui::RichText::new("Game Booster for Competitive Gaming")
                        .size(12.0)
                        .color(TEXT_SECONDARY));
                });
            });
        });
}
