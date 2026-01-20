//! Network page - Network analyzer with stability and speed tests
//!
//! Real-time network diagnostics.

use eframe::egui::{self, Color32, Ui, Sense, Vec2, Pos2, Rect};
use crate::gui::theme::*;
use crate::gui::animations::{AnimationManager, Animation};
use crate::gui::components::section_card;
use crate::network_analyzer::{
    NetworkAnalyzerState, StabilityTestResults, SpeedTestResults,
    ConnectionQuality, SpeedTestPhase,
};

/// Network page state needed from main app
pub struct NetworkPageState<'a> {
    pub analyzer_state: &'a NetworkAnalyzerState,
    pub download_gauge_anim: Option<&'a Animation>,
    pub upload_gauge_anim: Option<&'a Animation>,
    pub app_start_time: std::time::Instant,
}

/// Actions from network page
pub enum NetworkPageAction {
    None,
    StartStabilityTest,
    StartSpeedTest,
}

/// Render the network page
pub fn render_network_page(
    ui: &mut Ui,
    state: &NetworkPageState,
    _animations: &mut AnimationManager,
) -> NetworkPageAction {
    let mut action = NetworkPageAction::None;

    // Connection stability test
    if let NetworkPageAction::StartStabilityTest = render_stability_test(ui, state) {
        action = NetworkPageAction::StartStabilityTest;
    }

    ui.add_space(16.0);

    // Speed test
    if let NetworkPageAction::StartSpeedTest = render_speed_test(ui, state) {
        action = NetworkPageAction::StartSpeedTest;
    }

    action
}

/// Render stability test section
fn render_stability_test(ui: &mut Ui, state: &NetworkPageState) -> NetworkPageAction {
    let mut action = NetworkPageAction::None;
    let stability = &state.analyzer_state.stability;

    section_card(ui, "CONNECTION STABILITY", Some("📶"), None, |ui| {
        ui.label(egui::RichText::new("Test ping stability, jitter, and packet loss")
            .size(11.0)
            .color(TEXT_MUTED));

        ui.add_space(12.0);

        if stability.running {
            // Running test UI
            render_running_stability_test(ui, state);
        } else if let Some(results) = &stability.results {
            // Show results
            render_stability_results(ui, results);

            ui.add_space(16.0);

            // Re-run button
            if ui.add(
                egui::Button::new(egui::RichText::new("Run Again").size(13.0).color(TEXT_PRIMARY))
                    .fill(BG_ELEVATED)
                    .rounding(8.0)
                    .min_size(Vec2::new(120.0, 36.0))
            ).clicked() {
                action = NetworkPageAction::StartStabilityTest;
            }
        } else {
            // Initial state - start button
            ui.vertical_centered(|ui| {
                ui.add_space(16.0);
                ui.label(egui::RichText::new("📊").size(32.0).color(TEXT_MUTED));
                ui.add_space(8.0);
                ui.label(egui::RichText::new("Test your connection stability")
                    .size(13.0)
                    .color(TEXT_SECONDARY));
                ui.label(egui::RichText::new("Measures ping, jitter, and packet loss over 30 seconds")
                    .size(11.0)
                    .color(TEXT_MUTED));
                ui.add_space(16.0);

                if ui.add(
                    egui::Button::new(egui::RichText::new("Start Test").size(14.0).color(TEXT_PRIMARY))
                        .fill(ACCENT_PRIMARY)
                        .rounding(8.0)
                        .min_size(Vec2::new(140.0, 40.0))
                ).clicked() {
                    action = NetworkPageAction::StartStabilityTest;
                }
            });
        }
    });

    action
}

/// Render running stability test
fn render_running_stability_test(ui: &mut Ui, state: &NetworkPageState) {
    let stability = &state.analyzer_state.stability;

    // Progress bar
    let progress = stability.progress;
    ui.horizontal(|ui| {
        ui.label(egui::RichText::new("Testing...")
            .size(12.0)
            .color(TEXT_SECONDARY));
        ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
            ui.label(egui::RichText::new(format!("{:.0}%", progress * 100.0))
                .size(12.0)
                .color(ACCENT_PRIMARY));
        });
    });

    ui.add_space(4.0);

    let (rect, _) = ui.allocate_exact_size(Vec2::new(ui.available_width(), 8.0), Sense::hover());
    ui.painter().rect_filled(rect, 4.0, BG_ELEVATED);
    let fill_rect = Rect::from_min_size(rect.min, Vec2::new(rect.width() * progress, rect.height()));
    ui.painter().rect_filled(fill_rect, 4.0, ACCENT_PRIMARY);

    ui.add_space(16.0);

    // Real-time ping chart
    render_ping_chart(ui, &stability.ping_samples, state.app_start_time);
}

/// Render real-time ping chart
fn render_ping_chart(ui: &mut Ui, samples: &[Option<u32>], _app_start_time: std::time::Instant) {
    let chart_height = 120.0;
    let (rect, _) = ui.allocate_exact_size(Vec2::new(ui.available_width(), chart_height), Sense::hover());

    // Background
    ui.painter().rect_filled(rect, 6.0, BG_ELEVATED);

    if samples.is_empty() {
        return;
    }

    // Determine scale - show last 60 samples
    let visible_samples: Vec<_> = samples.iter().rev().take(60).rev().collect();
    let max_ping = visible_samples.iter()
        .filter_map(|s| **s)
        .max()
        .unwrap_or(100)
        .max(100);

    let padding = 8.0;
    let chart_rect = rect.shrink(padding);
    let point_spacing = chart_rect.width() / 60.0;

    // Grid lines
    for i in 0..=4 {
        let y = chart_rect.min.y + (chart_rect.height() * i as f32 / 4.0);
        ui.painter().line_segment(
            [Pos2::new(chart_rect.min.x, y), Pos2::new(chart_rect.max.x, y)],
            egui::Stroke::new(1.0, BG_HOVER.gamma_multiply(0.5)),
        );

        // Label
        let ms = max_ping - (max_ping * i / 4);
        ui.painter().text(
            Pos2::new(chart_rect.min.x + 2.0, y + 2.0),
            egui::Align2::LEFT_TOP,
            format!("{}ms", ms),
            egui::FontId::proportional(9.0),
            TEXT_DIMMED,
        );
    }

    // Plot points and lines
    let mut last_point: Option<Pos2> = None;

    for (i, sample) in visible_samples.iter().enumerate() {
        let x = chart_rect.min.x + (i as f32 * point_spacing);

        if let Some(ms) = sample {
            let normalized = 1.0 - (*ms as f32 / max_ping as f32).min(1.0);
            let y = chart_rect.min.y + (chart_rect.height() * (1.0 - normalized));
            let point = Pos2::new(x, y);

            // Line to previous point
            if let Some(prev) = last_point {
                ui.painter().line_segment(
                    [prev, point],
                    egui::Stroke::new(2.0, latency_color(*ms)),
                );
            }

            // Point
            let color = latency_color(*ms);
            ui.painter().circle_filled(point, 3.0, color);

            last_point = Some(point);
        } else {
            // Packet loss - draw X marker
            let y = chart_rect.max.y - 10.0;
            ui.painter().text(
                Pos2::new(x, y),
                egui::Align2::CENTER_CENTER,
                "×",
                egui::FontId::proportional(12.0),
                STATUS_ERROR,
            );
            last_point = None;
        }
    }
}

/// Render stability test results
fn render_stability_results(ui: &mut Ui, results: &StabilityTestResults) {
    // Quality badge
    ui.horizontal(|ui| {
        let quality_color = match results.quality {
            ConnectionQuality::Excellent | ConnectionQuality::Good => STATUS_CONNECTED,
            ConnectionQuality::Fair => STATUS_WARNING,
            ConnectionQuality::Poor | ConnectionQuality::Bad => STATUS_ERROR,
        };

        egui::Frame::none()
            .fill(quality_color.gamma_multiply(0.15))
            .stroke(egui::Stroke::new(1.0, quality_color.gamma_multiply(0.3)))
            .rounding(8.0)
            .inner_margin(egui::Margin::symmetric(12.0, 6.0))
            .show(ui, |ui| {
                ui.horizontal(|ui| {
                    ui.label(egui::RichText::new(results.quality.emoji()).size(16.0));
                    ui.add_space(4.0);
                    ui.label(egui::RichText::new(results.quality.label())
                        .size(14.0)
                        .color(quality_color)
                        .strong());
                });
            });

        ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
            let time_ago = chrono::Utc::now() - results.timestamp;
            let minutes = time_ago.num_minutes();
            let time_str = if minutes < 1 {
                "Just now".to_string()
            } else if minutes < 60 {
                format!("{}m ago", minutes)
            } else {
                format!("{}h ago", time_ago.num_hours())
            };
            ui.label(egui::RichText::new(time_str)
                .size(10.0)
                .color(TEXT_DIMMED));
        });
    });

    ui.add_space(16.0);

    // Stats grid
    ui.horizontal(|ui| {
        ui.spacing_mut().item_spacing.x = 10.0;
        let stat_width = (ui.available_width() - 30.0) / 4.0;

        // Average ping
        render_stat_box(ui, stat_width, "Avg Ping", &format!("{:.0}ms", results.avg_ping), latency_color(results.avg_ping as u32));

        // Min/Max
        render_stat_box(ui, stat_width, "Min / Max", &format!("{}ms / {}ms", results.min_ping, results.max_ping), TEXT_PRIMARY);

        // Jitter
        let jitter_color = if results.jitter < 5.0 { LATENCY_EXCELLENT }
            else if results.jitter < 10.0 { LATENCY_GOOD }
            else if results.jitter < 20.0 { LATENCY_FAIR }
            else { LATENCY_POOR };
        render_stat_box(ui, stat_width, "Jitter", &format!("{:.1}ms", results.jitter), jitter_color);

        // Packet loss
        let loss_color = if results.packet_loss < 1.0 { LATENCY_EXCELLENT }
            else if results.packet_loss < 2.0 { LATENCY_GOOD }
            else if results.packet_loss < 5.0 { LATENCY_FAIR }
            else { STATUS_ERROR };
        render_stat_box(ui, stat_width, "Packet Loss", &format!("{:.1}%", results.packet_loss), loss_color);
    });
}

/// Render a stat box
fn render_stat_box(ui: &mut Ui, width: f32, label: &str, value: &str, value_color: Color32) {
    ui.allocate_ui(Vec2::new(width, 60.0), |ui| {
        egui::Frame::none()
            .fill(BG_ELEVATED)
            .rounding(8.0)
            .inner_margin(10.0)
            .show(ui, |ui| {
                ui.vertical(|ui| {
                    ui.label(egui::RichText::new(label)
                        .size(10.0)
                        .color(TEXT_MUTED));
                    ui.label(egui::RichText::new(value)
                        .size(14.0)
                        .color(value_color)
                        .strong());
                });
            });
    });
}

/// Render speed test section
fn render_speed_test(ui: &mut Ui, state: &NetworkPageState) -> NetworkPageAction {
    let mut action = NetworkPageAction::None;
    let speed = &state.analyzer_state.speed;

    section_card(ui, "SPEED TEST", Some("⚡"), None, |ui| {
        ui.label(egui::RichText::new("Test download and upload speeds using Cloudflare")
            .size(11.0)
            .color(TEXT_MUTED));

        ui.add_space(12.0);

        if speed.running {
            // Running test UI
            render_running_speed_test(ui, state);
        } else if let Some(results) = &speed.results {
            // Show results
            render_speed_results(ui, results, state);

            ui.add_space(16.0);

            // Re-run button
            if ui.add(
                egui::Button::new(egui::RichText::new("Run Again").size(13.0).color(TEXT_PRIMARY))
                    .fill(BG_ELEVATED)
                    .rounding(8.0)
                    .min_size(Vec2::new(120.0, 36.0))
            ).clicked() {
                action = NetworkPageAction::StartSpeedTest;
            }
        } else {
            // Initial state
            ui.vertical_centered(|ui| {
                ui.add_space(16.0);
                ui.label(egui::RichText::new("⚡").size(32.0).color(TEXT_MUTED));
                ui.add_space(8.0);
                ui.label(egui::RichText::new("Test your internet speed")
                    .size(13.0)
                    .color(TEXT_SECONDARY));
                ui.label(egui::RichText::new("Measures download and upload using Cloudflare servers")
                    .size(11.0)
                    .color(TEXT_MUTED));
                ui.add_space(16.0);

                if ui.add(
                    egui::Button::new(egui::RichText::new("Start Test").size(14.0).color(TEXT_PRIMARY))
                        .fill(ACCENT_PRIMARY)
                        .rounding(8.0)
                        .min_size(Vec2::new(140.0, 40.0))
                ).clicked() {
                    action = NetworkPageAction::StartSpeedTest;
                }
            });
        }
    });

    action
}

/// Render running speed test
fn render_running_speed_test(ui: &mut Ui, state: &NetworkPageState) {
    let speed = &state.analyzer_state.speed;

    ui.horizontal(|ui| {
        ui.label(egui::RichText::new(speed.phase.label())
            .size(12.0)
            .color(TEXT_SECONDARY));
        ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
            ui.label(egui::RichText::new(format!("{:.0}%", speed.phase_progress * 100.0))
                .size(12.0)
                .color(ACCENT_PRIMARY));
        });
    });

    ui.add_space(4.0);

    // Progress bar
    let (rect, _) = ui.allocate_exact_size(Vec2::new(ui.available_width(), 8.0), Sense::hover());
    ui.painter().rect_filled(rect, 4.0, BG_ELEVATED);
    let fill_rect = Rect::from_min_size(rect.min, Vec2::new(rect.width() * speed.phase_progress, rect.height()));
    let color = match speed.phase {
        SpeedTestPhase::Download => ACCENT_CYAN,
        SpeedTestPhase::Upload => STATUS_CONNECTED,
        _ => ACCENT_PRIMARY,
    };
    ui.painter().rect_filled(fill_rect, 4.0, color);

    ui.add_space(16.0);

    // Speed gauges
    ui.horizontal(|ui| {
        let gauge_width = (ui.available_width() - 20.0) / 2.0;

        // Download gauge
        ui.allocate_ui(Vec2::new(gauge_width, 100.0), |ui| {
            render_speed_gauge(ui, "Download", speed.download_speed, ACCENT_CYAN, speed.phase == SpeedTestPhase::Download);
        });

        ui.add_space(20.0);

        // Upload gauge
        ui.allocate_ui(Vec2::new(gauge_width, 100.0), |ui| {
            render_speed_gauge(ui, "Upload", speed.upload_speed, STATUS_CONNECTED, speed.phase == SpeedTestPhase::Upload);
        });
    });
}

/// Render speed test results
fn render_speed_results(ui: &mut Ui, results: &SpeedTestResults, state: &NetworkPageState) {
    // Timestamp
    ui.horizontal(|ui| {
        ui.label(egui::RichText::new("Last test")
            .size(10.0)
            .color(TEXT_MUTED));

        let time_ago = chrono::Utc::now() - results.timestamp;
        let minutes = time_ago.num_minutes();
        let time_str = if minutes < 1 {
            "Just now".to_string()
        } else if minutes < 60 {
            format!("{}m ago", minutes)
        } else {
            format!("{}h ago", time_ago.num_hours())
        };

        ui.label(egui::RichText::new(time_str)
            .size(10.0)
            .color(TEXT_DIMMED));
    });

    ui.add_space(12.0);

    // Speed gauges with results
    ui.horizontal(|ui| {
        let gauge_width = (ui.available_width() - 20.0) / 2.0;

        // Download gauge
        ui.allocate_ui(Vec2::new(gauge_width, 100.0), |ui| {
            render_speed_gauge(ui, "Download", results.download_mbps, ACCENT_CYAN, false);
        });

        ui.add_space(20.0);

        // Upload gauge
        ui.allocate_ui(Vec2::new(gauge_width, 100.0), |ui| {
            render_speed_gauge(ui, "Upload", results.upload_mbps, STATUS_CONNECTED, false);
        });
    });

    ui.add_space(8.0);

    // Server info
    ui.label(egui::RichText::new(format!("Server: {}", results.server))
        .size(10.0)
        .color(TEXT_DIMMED));
}

/// Render speed gauge (semi-circle arc)
fn render_speed_gauge(ui: &mut Ui, label: &str, speed_mbps: f32, color: Color32, is_active: bool) {
    let size = 80.0;
    let (rect, _) = ui.allocate_exact_size(Vec2::new(ui.available_width(), size), Sense::hover());
    let center = Pos2::new(rect.center().x, rect.max.y - 10.0);
    let radius = (size - 20.0) / 2.0;

    // Background arc
    let arc_stroke = 8.0;
    for i in 0..20 {
        let angle = std::f32::consts::PI + (i as f32 / 20.0) * std::f32::consts::PI;
        let x = center.x + angle.cos() * radius;
        let y = center.y + angle.sin() * radius;
        ui.painter().circle_filled(Pos2::new(x, y), arc_stroke / 2.0, BG_HOVER);
    }

    // Filled arc based on speed (max ~100 Mbps for display)
    let fill_percent = (speed_mbps / 100.0).min(1.0);
    let fill_segments = (fill_percent * 20.0).ceil() as i32;

    for i in 0..fill_segments {
        let angle = std::f32::consts::PI + (i as f32 / 20.0) * std::f32::consts::PI;
        let x = center.x + angle.cos() * radius;
        let y = center.y + angle.sin() * radius;

        let segment_alpha = if is_active && i == fill_segments - 1 {
            // Pulse the last segment when active
            0.7 + 0.3 * ((std::time::Instant::now().elapsed().as_secs_f32() * 4.0).sin())
        } else {
            1.0
        };

        ui.painter().circle_filled(Pos2::new(x, y), arc_stroke / 2.0, color.gamma_multiply(segment_alpha));
    }

    // Speed value
    let speed_text = if speed_mbps < 1.0 && speed_mbps > 0.0 {
        format!("{:.1}", speed_mbps)
    } else {
        format!("{:.0}", speed_mbps)
    };

    ui.painter().text(
        Pos2::new(center.x, center.y - 20.0),
        egui::Align2::CENTER_CENTER,
        speed_text,
        egui::FontId::proportional(24.0),
        TEXT_PRIMARY,
    );

    ui.painter().text(
        Pos2::new(center.x, center.y - 2.0),
        egui::Align2::CENTER_CENTER,
        "Mbps",
        egui::FontId::proportional(10.0),
        TEXT_MUTED,
    );

    // Label
    ui.painter().text(
        Pos2::new(center.x, center.y + 10.0),
        egui::Align2::CENTER_TOP,
        label,
        egui::FontId::proportional(11.0),
        color,
    );
}
