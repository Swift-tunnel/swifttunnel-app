//! Home page - Connection status and region selection
//!
//! Main dashboard showing VPN status and server selection.

use eframe::egui::{self, Color32, Ui, Sense, Vec2, Pos2};
use std::collections::HashMap;
use crate::gui::theme::*;
use crate::gui::animations::{AnimationManager, ConnectionStep};
use crate::gui::components::{section_card, region_card, stat_card};
use crate::vpn::{ConnectionState, DynamicGamingRegion};

/// Home page state needed from main app
pub struct HomePageState<'a> {
    pub vpn_state: &'a ConnectionState,
    pub regions: &'a [DynamicGamingRegion],
    pub latencies: &'a HashMap<String, Option<u32>>,
    pub selected_region: &'a str,
    pub last_connected_region: Option<&'a str>,
    pub is_loading: bool,
    pub finding_best: bool,
    pub tunneled_processes: &'a [String],
    pub app_start_time: std::time::Instant,
}

/// Actions from home page
pub enum HomePageAction {
    None,
    Connect,
    Disconnect,
    SelectRegion(String),
}

/// Render the home page
pub fn render_home_page(
    ui: &mut Ui,
    state: &HomePageState,
    animations: &mut AnimationManager,
) -> HomePageAction {
    // Connection status section
    let mut action = render_connection_status(ui, state, animations);

    ui.add_space(16.0);

    // Region selector
    if let HomePageAction::SelectRegion(region) = render_region_selector(ui, state, animations) {
        action = HomePageAction::SelectRegion(region);
    }

    ui.add_space(16.0);

    // Quick info (when connected)
    if state.vpn_state.is_connected() {
        render_quick_info(ui, state);
    }

    action
}

/// Render connection status card
fn render_connection_status(
    ui: &mut Ui,
    state: &HomePageState,
    animations: &mut AnimationManager,
) -> HomePageAction {
    let mut action = HomePageAction::None;

    let is_connected = state.vpn_state.is_connected();
    let is_connecting = state.vpn_state.is_connecting();

    section_card(ui, "CONNECTION STATUS", Some("🔗"), None, |ui| {
        ui.horizontal(|ui| {
            // Large status indicator with animation
            let indicator_size = 64.0;
            let (rect, _) = ui.allocate_exact_size(Vec2::new(indicator_size, indicator_size), Sense::hover());
            let center = rect.center();

            if is_connected {
                // Breathing glow animation
                let elapsed = state.app_start_time.elapsed().as_secs_f32();
                let pulse = ((elapsed * std::f32::consts::PI / PULSE_ANIMATION_DURATION).sin() + 1.0) / 2.0;

                // Outer glow
                let glow_radius = indicator_size / 2.0 + pulse * 4.0;
                ui.painter().circle_filled(center, glow_radius, STATUS_CONNECTED.gamma_multiply(0.2 + pulse * 0.1));

                // Inner circle
                ui.painter().circle_filled(center, indicator_size / 2.0 - 4.0, STATUS_CONNECTED.gamma_multiply(0.3));
                ui.painter().circle_stroke(center, indicator_size / 2.0 - 4.0, egui::Stroke::new(3.0, STATUS_CONNECTED));

                // Checkmark
                let font = egui::FontId::proportional(28.0);
                let galley = ui.painter().layout_no_wrap("✓".to_string(), font, STATUS_CONNECTED);
                let icon_pos = Pos2::new(center.x - galley.size().x / 2.0, center.y - galley.size().y / 2.0);
                ui.painter().galley(icon_pos, galley, STATUS_CONNECTED);

            } else if is_connecting {
                // Spinning animation
                let elapsed = state.app_start_time.elapsed().as_secs_f32();
                let rotation = elapsed * 3.0;

                ui.painter().circle_stroke(center, indicator_size / 2.0 - 4.0, egui::Stroke::new(2.0, BG_HOVER));

                // Spinning arc
                for i in 0..3 {
                    let angle = rotation + i as f32 * std::f32::consts::TAU / 3.0;
                    let arc_start = center + Vec2::new(angle.cos(), angle.sin()) * (indicator_size / 2.0 - 4.0);
                    let alpha = 1.0 - (i as f32 / 3.0);
                    ui.painter().circle_filled(arc_start, 4.0, STATUS_WARNING.gamma_multiply(alpha));
                }

            } else {
                // Disconnected state
                ui.painter().circle_filled(center, indicator_size / 2.0 - 4.0, BG_ELEVATED);
                ui.painter().circle_stroke(center, indicator_size / 2.0 - 4.0, egui::Stroke::new(2.0, BG_HOVER));

                let font = egui::FontId::proportional(24.0);
                let galley = ui.painter().layout_no_wrap("○".to_string(), font, TEXT_MUTED);
                let icon_pos = Pos2::new(center.x - galley.size().x / 2.0, center.y - galley.size().y / 2.0);
                ui.painter().galley(icon_pos, galley, TEXT_MUTED);
            }

            ui.add_space(20.0);

            // Status text and button
            ui.vertical(|ui| {
                let (status_text, status_detail) = if is_connected {
                    if let ConnectionState::Connected { server_region, .. } = state.vpn_state {
                        let flag = get_region_flag(server_region);
                        let name = get_region_name(server_region);
                        ("Protected", format!("{} {}", flag, name))
                    } else {
                        ("Protected", "Connected".to_string())
                    }
                } else if is_connecting {
                    ("Connecting", "Please wait...".to_string())
                } else {
                    ("Disconnected", "Not protected".to_string())
                };

                let status_color = if is_connected { STATUS_CONNECTED }
                    else if is_connecting { STATUS_WARNING }
                    else { TEXT_MUTED };

                ui.label(egui::RichText::new(status_text)
                    .size(20.0)
                    .color(status_color)
                    .strong());

                ui.label(egui::RichText::new(status_detail)
                    .size(12.0)
                    .color(TEXT_SECONDARY));

                ui.add_space(12.0);

                // Connect/Disconnect button
                let button_text = if is_connected { "Disconnect" }
                    else if is_connecting { "Connecting..." }
                    else { "Connect" };

                let button_color = if is_connected { STATUS_ERROR }
                    else if is_connecting { STATUS_WARNING }
                    else { ACCENT_PRIMARY };

                let button = egui::Button::new(
                    egui::RichText::new(button_text)
                        .size(14.0)
                        .color(if is_connecting { Color32::BLACK } else { TEXT_PRIMARY })
                )
                .fill(if is_connecting { button_color.gamma_multiply(0.5) } else { button_color })
                .rounding(8.0)
                .min_size(Vec2::new(140.0, 40.0));

                if ui.add_enabled(!is_connecting, button).clicked() {
                    if is_connected {
                        action = HomePageAction::Disconnect;
                    } else {
                        action = HomePageAction::Connect;
                    }
                }
            });
        });

        // Connection progress steps (when connecting)
        if is_connecting {
            ui.add_space(16.0);
            render_connection_progress(ui, state, animations);
        }
    });

    action
}

/// Render connection progress steps
fn render_connection_progress(ui: &mut Ui, state: &HomePageState, _animations: &AnimationManager) {
    let current_step = connection_step_from_state(state.vpn_state);
    let current_idx = current_step.step_index();

    let steps = [
        (1, "Config"),
        (2, "Adapter"),
        (3, "Tunnel"),
        (4, "Route"),
    ];

    ui.horizontal(|ui| {
        ui.spacing_mut().item_spacing.x = 0.0;
        let step_width = ui.available_width() / steps.len() as f32;

        for (idx, label) in steps {
            let is_complete = current_idx > idx;
            let is_current = current_idx == idx;

            ui.allocate_ui(Vec2::new(step_width, 32.0), |ui| {
                ui.vertical_centered(|ui| {
                    let dot_size = 10.0;
                    let (rect, _) = ui.allocate_exact_size(Vec2::new(dot_size, dot_size), Sense::hover());

                    let dot_color = if is_complete { STATUS_CONNECTED }
                        else if is_current { STATUS_WARNING }
                        else { BG_ELEVATED };

                    if is_current {
                        let elapsed = state.app_start_time.elapsed().as_secs_f32();
                        let pulse = ((elapsed * std::f32::consts::PI * 2.0).sin() + 1.0) / 2.0;
                        ui.painter().circle_filled(rect.center(), 5.0 + pulse * 2.0, dot_color.gamma_multiply(0.3));
                    }
                    ui.painter().circle_filled(rect.center(), 4.0, dot_color);

                    let label_color = if is_complete || is_current { TEXT_PRIMARY } else { TEXT_MUTED };
                    ui.label(egui::RichText::new(label).size(10.0).color(label_color));
                });
            });
        }
    });
}

/// Convert ConnectionState to ConnectionStep
fn connection_step_from_state(state: &ConnectionState) -> ConnectionStep {
    match state {
        ConnectionState::Disconnected => ConnectionStep::Idle,
        ConnectionState::FetchingConfig => ConnectionStep::Fetching,
        ConnectionState::CreatingAdapter => ConnectionStep::Adapter,
        ConnectionState::Connecting => ConnectionStep::Tunnel,
        ConnectionState::ConfiguringSplitTunnel => ConnectionStep::Routing,
        ConnectionState::Connected { .. } => ConnectionStep::Connected,
        ConnectionState::Disconnecting => ConnectionStep::Idle,
        ConnectionState::Error(_) => ConnectionStep::Idle,
    }
}

/// Render region selector grid
fn render_region_selector(
    ui: &mut Ui,
    state: &HomePageState,
    animations: &mut AnimationManager,
) -> HomePageAction {
    let mut action = HomePageAction::None;

    let region_count = state.regions.len();
    let badge_text = if state.finding_best {
        "Measuring latency...".to_string()
    } else {
        format!("{} regions", region_count)
    };

    section_card(ui, "SELECT REGION", Some("🌍"), Some(&badge_text), |ui| {
        if state.regions.is_empty() {
            if state.is_loading {
                // Show loading skeleton
                ui.horizontal(|ui| {
                    ui.spinner();
                    ui.label(egui::RichText::new("Loading servers...")
                        .color(TEXT_MUTED));
                });
            } else {
                ui.label(egui::RichText::new("No servers available")
                    .color(TEXT_MUTED));
            }
            return;
        }

        // 2-column grid
        let columns = 2;
        let spacing = 10.0;
        let available = ui.available_width();
        let card_width = (available - spacing) / columns as f32;

        let regions: Vec<_> = state.regions.iter().collect();
        for chunk in regions.chunks(columns) {
            ui.horizontal(|ui| {
                ui.spacing_mut().item_spacing.x = spacing;

                for region in chunk {
                    let latency = state.latencies.get(&region.id).and_then(|l| *l);
                    let is_selected = state.selected_region == region.id;
                    let is_last = state.last_connected_region == Some(region.id.as_str());

                    ui.allocate_ui(Vec2::new(card_width, 70.0), |ui| {
                        if region_card(
                            ui,
                            &region.id,
                            get_region_flag(&region.id),
                            get_region_name(&region.id),
                            latency,
                            is_selected,
                            is_last,
                            state.is_loading,
                            animations,
                        ) {
                            action = HomePageAction::SelectRegion(region.id.clone());
                        }
                    });
                }

                // Pad incomplete row
                for _ in chunk.len()..columns {
                    ui.allocate_space(Vec2::new(card_width, 70.0));
                }
            });
            ui.add_space(spacing);
        }
    });

    action
}

/// Render quick info stats when connected
fn render_quick_info(ui: &mut Ui, state: &HomePageState) {
    if let ConnectionState::Connected { ref assigned_ip, since, ref tunneled_processes, .. } = state.vpn_state {
        ui.horizontal(|ui| {
            let card_width = (ui.available_width() - 20.0) / 3.0;

            ui.allocate_ui(Vec2::new(card_width, 60.0), |ui| {
                stat_card(ui, "IP Address", assigned_ip, Some("🌐"));
            });

            ui.add_space(10.0);

            ui.allocate_ui(Vec2::new(card_width, 60.0), |ui| {
                let uptime = since.elapsed();
                let hours = uptime.as_secs() / 3600;
                let minutes = (uptime.as_secs() % 3600) / 60;
                let seconds = uptime.as_secs() % 60;
                let uptime_str = format!("{:02}:{:02}:{:02}", hours, minutes, seconds);
                stat_card(ui, "Uptime", &uptime_str, Some("⏱"));
            });

            ui.add_space(10.0);

            ui.allocate_ui(Vec2::new(card_width, 60.0), |ui| {
                let process_count = tunneled_processes.len();
                let status = if process_count > 0 {
                    format!("{} app{}", process_count, if process_count == 1 { "" } else { "s" })
                } else {
                    "None detected".to_string()
                };
                stat_card(ui, "Split Tunnel", &status, Some("📂"));
            });
        });
    }
}
