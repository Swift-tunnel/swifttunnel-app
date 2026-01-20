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

    // Determine status badge text
    let status_badge = if is_connected {
        Some("PROTECTED")
    } else if is_connecting {
        Some("CONNECTING")
    } else {
        None
    };

    section_card(ui, "CONNECTION STATUS", Some("⚡"), status_badge, |ui| {
        ui.horizontal(|ui| {
            // Large status indicator with animation
            let indicator_size = 72.0;
            let (rect, _) = ui.allocate_exact_size(Vec2::new(indicator_size, indicator_size), Sense::hover());
            let center = rect.center();

            if is_connected {
                // Breathing glow animation
                let elapsed = state.app_start_time.elapsed().as_secs_f32();
                let pulse = ((elapsed * std::f32::consts::PI / PULSE_ANIMATION_DURATION).sin() + 1.0) / 2.0;

                // Outer glow rings
                let glow_radius = indicator_size / 2.0 + pulse * 6.0;
                ui.painter().circle_filled(center, glow_radius, STATUS_CONNECTED.gamma_multiply(0.08 + pulse * 0.04));
                ui.painter().circle_filled(center, glow_radius - 4.0, STATUS_CONNECTED.gamma_multiply(0.12 + pulse * 0.06));

                // Inner circle with gradient-like effect
                ui.painter().circle_filled(center, indicator_size / 2.0 - 6.0, STATUS_CONNECTED.gamma_multiply(0.25));
                ui.painter().circle_stroke(center, indicator_size / 2.0 - 6.0, egui::Stroke::new(3.0, STATUS_CONNECTED));

                // Checkmark icon
                let font = egui::FontId::proportional(32.0);
                let galley = ui.painter().layout_no_wrap("✓".to_string(), font, STATUS_CONNECTED);
                let icon_pos = Pos2::new(center.x - galley.size().x / 2.0, center.y - galley.size().y / 2.0);
                ui.painter().galley(icon_pos, galley, STATUS_CONNECTED);

            } else if is_connecting {
                // Spinning animation with multiple rings
                let elapsed = state.app_start_time.elapsed().as_secs_f32();
                let rotation = elapsed * 3.0;

                // Outer track
                ui.painter().circle_stroke(center, indicator_size / 2.0 - 6.0, egui::Stroke::new(3.0, BG_ELEVATED));

                // Spinning dots with trail effect
                for i in 0..4 {
                    let angle = rotation + i as f32 * std::f32::consts::TAU / 4.0;
                    let arc_pos = center + Vec2::new(angle.cos(), angle.sin()) * (indicator_size / 2.0 - 6.0);
                    let alpha = 1.0 - (i as f32 / 4.0) * 0.7;
                    let dot_size = 5.0 - (i as f32 * 0.8);
                    ui.painter().circle_filled(arc_pos, dot_size, STATUS_WARNING.gamma_multiply(alpha));
                }

                // Center pulse
                let pulse = ((elapsed * 4.0).sin() + 1.0) / 2.0;
                ui.painter().circle_filled(center, 8.0 + pulse * 3.0, STATUS_WARNING.gamma_multiply(0.3));

            } else {
                // Disconnected state - subtle and muted
                ui.painter().circle_filled(center, indicator_size / 2.0 - 6.0, BG_ELEVATED);
                ui.painter().circle_stroke(center, indicator_size / 2.0 - 6.0, egui::Stroke::new(2.0, BG_HOVER));

                // Shield icon (Unicode)
                let font = egui::FontId::proportional(28.0);
                let galley = ui.painter().layout_no_wrap("○".to_string(), font, TEXT_DIMMED);
                let icon_pos = Pos2::new(center.x - galley.size().x / 2.0, center.y - galley.size().y / 2.0);
                ui.painter().galley(icon_pos, galley, TEXT_DIMMED);
            }

            ui.add_space(24.0);

            // Status text and button column
            ui.vertical(|ui| {
                // Main status text
                let (status_text, status_detail) = if is_connected {
                    if let ConnectionState::Connected { server_region, .. } = state.vpn_state {
                        use crate::gui::theme::get_region_code;
                        let code = get_region_code(server_region);
                        let name = get_region_name(server_region);
                        ("Protected", format!("[{}] {}", code, name))
                    } else {
                        ("Protected", "Connected to VPN".to_string())
                    }
                } else if is_connecting {
                    ("Connecting", "Establishing secure tunnel...".to_string())
                } else {
                    ("Disconnected", "Your connection is not protected".to_string())
                };

                let status_color = if is_connected { STATUS_CONNECTED }
                    else if is_connecting { STATUS_WARNING }
                    else { TEXT_MUTED };

                ui.label(egui::RichText::new(status_text)
                    .size(22.0)
                    .color(status_color)
                    .strong());

                ui.add_space(4.0);

                ui.label(egui::RichText::new(status_detail)
                    .size(12.0)
                    .color(TEXT_SECONDARY));

                ui.add_space(16.0);

                // Connect/Disconnect button with proper styling
                let button_text = if is_connected { "Disconnect" }
                    else if is_connecting { "Connecting..." }
                    else { "Connect" };

                let button_color = if is_connected { STATUS_ERROR }
                    else if is_connecting { STATUS_WARNING }
                    else { ACCENT_PRIMARY };

                let text_color = if is_connecting {
                    Color32::from_rgb(40, 40, 40)
                } else {
                    TEXT_PRIMARY
                };

                let button = egui::Button::new(
                    egui::RichText::new(button_text)
                        .size(14.0)
                        .color(text_color)
                        .strong()
                )
                .fill(if is_connecting { button_color.gamma_multiply(0.6) } else { button_color })
                .stroke(egui::Stroke::new(1.0, button_color.gamma_multiply(0.8)))
                .rounding(10.0)
                .min_size(Vec2::new(160.0, 44.0));

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
            ui.add_space(20.0);
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
        (1, "Config", "Fetching server configuration"),
        (2, "Adapter", "Creating network adapter"),
        (3, "Tunnel", "Establishing tunnel"),
        (4, "Route", "Configuring routes"),
    ];

    // Progress bar background
    egui::Frame::none()
        .fill(BG_ELEVATED)
        .rounding(8.0)
        .inner_margin(egui::Margin::symmetric(16.0, 12.0))
        .show(ui, |ui| {
            ui.set_min_width(ui.available_width());

            // Calculate progress percentage
            let progress = (current_idx as f32 - 1.0) / (steps.len() as f32);

            // Progress bar track
            let bar_height = 4.0;
            let bar_width = ui.available_width();
            let (bar_rect, _) = ui.allocate_exact_size(Vec2::new(bar_width, bar_height), Sense::hover());

            // Track
            ui.painter().rect_filled(bar_rect, 2.0, BG_CARD);

            // Filled portion
            let elapsed = state.app_start_time.elapsed().as_secs_f32();
            let pulse = ((elapsed * 2.0).sin() + 1.0) / 2.0 * 0.1;
            let fill_width = bar_width * (progress + pulse).min(1.0);
            let fill_rect = egui::Rect::from_min_size(bar_rect.min, Vec2::new(fill_width, bar_height));
            ui.painter().rect_filled(fill_rect, 2.0, STATUS_WARNING);

            ui.add_space(12.0);

            // Steps indicators
            ui.horizontal(|ui| {
                let step_width = ui.available_width() / steps.len() as f32;

                for (idx, label, _desc) in steps {
                    let is_complete = current_idx > idx;
                    let is_current = current_idx == idx;

                    ui.allocate_ui(Vec2::new(step_width, 24.0), |ui| {
                        ui.vertical_centered(|ui| {
                            // Step indicator
                            let indicator_size = 18.0;
                            let (rect, _) = ui.allocate_exact_size(Vec2::new(indicator_size, indicator_size), Sense::hover());

                            let (bg_color, fg_color) = if is_complete {
                                (STATUS_CONNECTED, TEXT_PRIMARY)
                            } else if is_current {
                                let pulse = ((state.app_start_time.elapsed().as_secs_f32() * 3.0).sin() + 1.0) / 2.0;
                                ui.painter().circle_filled(rect.center(), indicator_size / 2.0 + 2.0, STATUS_WARNING.gamma_multiply(0.3 * pulse));
                                (STATUS_WARNING, TEXT_PRIMARY)
                            } else {
                                (BG_CARD, TEXT_DIMMED)
                            };

                            ui.painter().circle_filled(rect.center(), indicator_size / 2.0, bg_color);

                            // Step number or checkmark
                            let text = if is_complete { "✓" } else { &idx.to_string() };
                            let font = egui::FontId::proportional(if is_complete { 11.0 } else { 10.0 });
                            let galley = ui.painter().layout_no_wrap(text.to_string(), font, fg_color);
                            let text_pos = egui::Pos2::new(
                                rect.center().x - galley.size().x / 2.0,
                                rect.center().y - galley.size().y / 2.0,
                            );
                            ui.painter().galley(text_pos, galley, fg_color);

                            // Label
                            let label_color = if is_complete || is_current { TEXT_PRIMARY } else { TEXT_MUTED };
                            ui.label(egui::RichText::new(label).size(10.0).color(label_color));
                        });
                    });
                }
            });
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

    section_card(ui, "SELECT REGION", Some("🌐"), Some(&badge_text), |ui| {
        if state.regions.is_empty() {
            if state.is_loading {
                // Show loading state with skeleton cards
                ui.vertical_centered(|ui| {
                    ui.add_space(20.0);
                    ui.spinner();
                    ui.add_space(12.0);
                    ui.label(egui::RichText::new("Loading servers...")
                        .size(12.0)
                        .color(TEXT_MUTED));
                    ui.add_space(20.0);
                });
            } else {
                ui.vertical_centered(|ui| {
                    ui.add_space(20.0);
                    ui.label(egui::RichText::new("No servers available")
                        .size(12.0)
                        .color(TEXT_MUTED));
                    ui.add_space(20.0);
                });
            }
            return;
        }

        // Calculate grid dimensions - 2 columns with proper spacing
        let total_width = ui.available_width();
        let gap = 12.0;
        let card_width = (total_width - gap) / 2.0;
        let card_height = 76.0; // Fixed height for all cards

        // Collect regions into pairs for 2-column layout
        let regions: Vec<_> = state.regions.iter().collect();
        let mut i = 0;

        while i < regions.len() {
            ui.horizontal(|ui| {
                // First column
                if i < regions.len() {
                    let region = &regions[i];
                    let latency = state.latencies.get(&region.id).and_then(|l| *l);
                    let is_selected = state.selected_region == region.id;
                    let is_last = state.last_connected_region == Some(region.id.as_str());

                    ui.allocate_ui(Vec2::new(card_width, card_height), |ui| {
                        if region_card(
                            ui,
                            &region.id,
                            get_region_flag(&region.id),
                            get_region_name(&region.id),
                            latency,
                            is_selected,
                            is_last,
                            state.finding_best,
                            animations,
                        ) {
                            action = HomePageAction::SelectRegion(region.id.clone());
                        }
                    });
                }

                ui.add_space(gap);

                // Second column
                if i + 1 < regions.len() {
                    let region = &regions[i + 1];
                    let latency = state.latencies.get(&region.id).and_then(|l| *l);
                    let is_selected = state.selected_region == region.id;
                    let is_last = state.last_connected_region == Some(region.id.as_str());

                    ui.allocate_ui(Vec2::new(card_width, card_height), |ui| {
                        if region_card(
                            ui,
                            &region.id,
                            get_region_flag(&region.id),
                            get_region_name(&region.id),
                            latency,
                            is_selected,
                            is_last,
                            state.finding_best,
                            animations,
                        ) {
                            action = HomePageAction::SelectRegion(region.id.clone());
                        }
                    });
                }
            });

            // Row spacing
            ui.add_space(gap);
            i += 2;
        }
    });

    action
}

/// Render quick info stats when connected
fn render_quick_info(ui: &mut Ui, state: &HomePageState) {
    if let ConnectionState::Connected { ref assigned_ip, since, ref tunneled_processes, .. } = state.vpn_state {
        // Stats row with proper spacing
        let gap = 12.0;
        let card_width = (ui.available_width() - gap * 2.0) / 3.0;
        let card_height = 70.0;

        ui.horizontal(|ui| {
            ui.allocate_ui(Vec2::new(card_width, card_height), |ui| {
                stat_card(ui, "VPN IP Address", assigned_ip, Some("●"));
            });

            ui.add_space(gap);

            ui.allocate_ui(Vec2::new(card_width, card_height), |ui| {
                let uptime = since.elapsed();
                let hours = uptime.as_secs() / 3600;
                let minutes = (uptime.as_secs() % 3600) / 60;
                let seconds = uptime.as_secs() % 60;
                let uptime_str = format!("{:02}:{:02}:{:02}", hours, minutes, seconds);
                stat_card(ui, "Session Duration", &uptime_str, Some("◷"));
            });

            ui.add_space(gap);

            ui.allocate_ui(Vec2::new(card_width, card_height), |ui| {
                let process_count = tunneled_processes.len();
                let status = if process_count > 0 {
                    format!("{} app{}", process_count, if process_count == 1 { "" } else { "s" })
                } else {
                    "Waiting...".to_string()
                };
                stat_card(ui, "Split Tunnel", &status, Some("◈"));
            });
        });
    }
}
