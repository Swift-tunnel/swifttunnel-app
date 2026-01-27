//! Network tab rendering - stability tests, speed tests, network analyzer

use super::*;
use super::theme::*;
use super::animations::lerp_color;
use crate::auth::AuthState;
use crate::network_analyzer::{run_stability_test, run_speed_test, StabilityTestProgress, SpeedTestProgress};
use std::sync::Arc;

/// Format speed as human-readable string (Mbps)
fn format_speed(speed: f32) -> String {
    if speed < 1.0 {
        format!("{:.2} Mbps", speed)
    } else if speed < 10.0 {
        format!("{:.1} Mbps", speed)
    } else {
        format!("{:.0} Mbps", speed)
    }
}

impl BoosterApp {
    /// Render the Network Analyzer tab
    pub(crate) fn render_network_tab(&mut self, ui: &mut egui::Ui) {
        // Show update banner if available
        self.render_update_banner(ui);

        let is_logged_in = matches!(self.auth_state, AuthState::LoggedIn(_));

        if !is_logged_in {
            self.render_login_prompt(ui);
            return;
        }

        // Tab header
        ui.horizontal(|ui| {
            ui.label(egui::RichText::new(":: Network Analyzer")
                .size(20.0)
                .color(TEXT_PRIMARY)
                .strong());
            ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                ui.label(egui::RichText::new("Test your connection")
                    .size(12.0)
                    .color(TEXT_MUTED));
            });
        });
        ui.add_space(16.0);

        // Connection Stability Test section
        self.render_stability_section(ui);
        ui.add_space(20.0);

        // Speed Test section
        self.render_speed_test_section(ui);
    }

    /// Render the Connection Stability Test section
    pub(crate) fn render_stability_section(&mut self, ui: &mut egui::Ui) {
        egui::Frame::NONE
            .fill(BG_CARD)
            .rounding(12.0)
            .inner_margin(egui::Margin::same(16))
            .show(ui, |ui| {
                // Section header
                ui.horizontal(|ui| {
                    ui.label(egui::RichText::new("@ Connection Stability")
                        .size(16.0)
                        .color(TEXT_PRIMARY)
                        .strong());

                    ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                        // Show quality badge if we have results
                        if let Some(ref results) = self.network_analyzer_state.stability.results {
                            let (badge_color, badge_text) = match results.quality {
                                crate::network_analyzer::ConnectionQuality::Excellent => (STATUS_CONNECTED, "Excellent"),
                                crate::network_analyzer::ConnectionQuality::Good => (LATENCY_GOOD, "Good"),
                                crate::network_analyzer::ConnectionQuality::Fair => (STATUS_WARNING, "Fair"),
                                crate::network_analyzer::ConnectionQuality::Poor => (LATENCY_POOR, "Poor"),
                                crate::network_analyzer::ConnectionQuality::Bad => (STATUS_ERROR, "Bad"),
                            };
                            egui::Frame::NONE
                                .fill(badge_color.gamma_multiply(0.2))
                                .rounding(4.0)
                                .inner_margin(egui::Margin::symmetric(8, 4))
                                .show(ui, |ui| {
                                    ui.label(egui::RichText::new(badge_text)
                                        .size(11.0)
                                        .color(badge_color)
                                        .strong());
                                });
                        }
                    });
                });
                ui.add_space(12.0);

                // Ping chart
                self.render_ping_chart(ui);
                ui.add_space(12.0);

                // Stats row
                if let Some(ref results) = self.network_analyzer_state.stability.results {
                    ui.horizontal(|ui| {
                        // Avg Ping
                        self.render_stat_box(ui, "Avg Ping", &format!("{:.0}ms", results.avg_ping), latency_color(results.avg_ping as u32));
                        ui.add_space(8.0);
                        // Jitter
                        self.render_stat_box(ui, "Jitter", &format!("{:.1}ms", results.jitter), TEXT_SECONDARY);
                        ui.add_space(8.0);
                        // Packet Loss
                        let loss_color = if results.packet_loss < 1.0 { STATUS_CONNECTED } else if results.packet_loss < 5.0 { STATUS_WARNING } else { STATUS_ERROR };
                        self.render_stat_box(ui, "Loss", &format!("{:.1}%", results.packet_loss), loss_color);
                        ui.add_space(8.0);
                        // Min/Max
                        self.render_stat_box(ui, "Min/Max", &format!("{}/{}ms", results.min_ping, results.max_ping), TEXT_MUTED);
                    });
                } else if self.network_analyzer_state.stability.running {
                    ui.horizontal(|ui| {
                        ui.spinner();
                        ui.label(egui::RichText::new(format!("Testing... {:.0}%", self.network_analyzer_state.stability.progress * 100.0))
                            .size(13.0)
                            .color(TEXT_SECONDARY));
                    });
                }

                ui.add_space(12.0);

                // Start/Stop button
                let is_running = self.network_analyzer_state.stability.running;
                let button_text = if is_running { "[] Stop Test" } else { "> Start Stability Test" };
                let button_color = if is_running { STATUS_ERROR } else { ACCENT_PRIMARY };

                let button = egui::Button::new(
                    egui::RichText::new(button_text)
                        .size(14.0)
                        .color(TEXT_PRIMARY)
                )
                .fill(button_color)
                .rounding(8.0)
                .min_size(egui::vec2(ui.available_width(), 38.0));

                if ui.add(button).clicked() {
                    if is_running {
                        self.stop_stability_test();
                    } else {
                        self.start_stability_test();
                    }
                }
            });
    }

    /// Render the ping chart showing real-time ping history
    pub(crate) fn render_ping_chart(&self, ui: &mut egui::Ui) {
        let samples = &self.network_analyzer_state.stability.ping_samples;
        let chart_height = 120.0;
        let chart_width = ui.available_width();

        // Chart background
        let (response, painter) = ui.allocate_painter(egui::vec2(chart_width, chart_height), egui::Sense::hover());
        let rect = response.rect;

        // Draw background
        painter.rect_filled(rect, 8.0, BG_ELEVATED);

        // Draw reference lines at 50ms, 100ms, 150ms
        let max_ms = 200.0_f32;
        for ref_ms in [50.0, 100.0, 150.0] {
            let y = rect.max.y - (ref_ms / max_ms) * rect.height();
            painter.line_segment(
                [egui::pos2(rect.min.x + 4.0, y), egui::pos2(rect.max.x - 4.0, y)],
                egui::Stroke::new(1.0, BG_HOVER)
            );
            painter.text(
                egui::pos2(rect.min.x + 6.0, y - 8.0),
                egui::Align2::LEFT_BOTTOM,
                format!("{}ms", ref_ms as u32),
                egui::FontId::proportional(9.0),
                TEXT_DIMMED
            );
        }

        // Draw samples
        if samples.len() >= 2 {
            let max_samples = 60; // Show last 60 samples (30 seconds at 2 pings/sec)
            let start_idx = samples.len().saturating_sub(max_samples);
            let visible_samples = &samples[start_idx..];

            let sample_width = rect.width() / max_samples as f32;

            // Draw line connecting points
            let mut points: Vec<egui::Pos2> = Vec::new();
            for (i, sample) in visible_samples.iter().enumerate() {
                if let Some(ms) = sample {
                    let x = rect.min.x + (i as f32 * sample_width) + sample_width / 2.0;
                    let y = rect.max.y - ((*ms as f32).min(max_ms) / max_ms) * rect.height() * 0.9 - 5.0;
                    points.push(egui::pos2(x, y));
                }
            }

            // Draw line
            if points.len() >= 2 {
                for window in points.windows(2) {
                    painter.line_segment(
                        [window[0], window[1]],
                        egui::Stroke::new(2.0, ACCENT_CYAN.gamma_multiply(0.7))
                    );
                }
            }

            // Draw points
            for (i, sample) in visible_samples.iter().enumerate() {
                let x = rect.min.x + (i as f32 * sample_width) + sample_width / 2.0;

                match sample {
                    Some(ms) => {
                        let y = rect.max.y - ((*ms as f32).min(max_ms) / max_ms) * rect.height() * 0.9 - 5.0;
                        let color = latency_color(*ms);
                        painter.circle_filled(egui::pos2(x, y), 3.0, color);
                    }
                    None => {
                        // Packet loss - draw red X at bottom
                        let y = rect.max.y - 10.0;
                        painter.text(
                            egui::pos2(x, y),
                            egui::Align2::CENTER_CENTER,
                            "x",
                            egui::FontId::proportional(12.0),
                            STATUS_ERROR
                        );
                    }
                }
            }
        } else {
            // No data yet - show placeholder
            painter.text(
                rect.center(),
                egui::Align2::CENTER_CENTER,
                "Start test to see ping history",
                egui::FontId::proportional(12.0),
                TEXT_DIMMED
            );
        }
    }

    /// Render a small stat box
    pub(crate) fn render_stat_box(&self, ui: &mut egui::Ui, label: &str, value: &str, value_color: egui::Color32) {
        egui::Frame::NONE
            .fill(BG_ELEVATED)
            .rounding(6.0)
            .inner_margin(egui::Margin::symmetric(12, 8))
            .show(ui, |ui| {
                ui.vertical(|ui| {
                    ui.label(egui::RichText::new(label).size(10.0).color(TEXT_MUTED));
                    ui.label(egui::RichText::new(value).size(14.0).color(value_color).strong());
                });
            });
    }

    /// Start the stability test
    pub(crate) fn start_stability_test(&mut self) {
        if self.network_analyzer_state.stability.running {
            return;
        }

        // Reset state
        self.network_analyzer_state.stability.running = true;
        self.network_analyzer_state.stability.progress = 0.0;
        self.network_analyzer_state.stability.ping_samples.clear();
        self.network_analyzer_state.stability.results = None;

        // Create new channel for this test
        let (tx, rx) = std::sync::mpsc::channel::<StabilityTestProgress>();
        self.stability_progress_rx = rx;

        // Spawn test in background
        let rt = Arc::clone(&self.runtime);
        std::thread::spawn(move || {
            let _ = rt.block_on(async {
                run_stability_test(30, tx).await
            });
        });
    }

    /// Stop the stability test
    pub(crate) fn stop_stability_test(&mut self) {
        if !self.network_analyzer_state.stability.running {
            return;
        }

        log::info!("Stopping stability test");

        // Mark as stopped
        self.network_analyzer_state.stability.running = false;

        // Create new channel to discard any pending messages from old test
        let (tx, rx) = std::sync::mpsc::channel::<StabilityTestProgress>();
        self.stability_progress_rx = rx;
        // tx is dropped, old background thread will error when sending (harmless)
        drop(tx);
    }

    /// Render the Speed Test section
    pub(crate) fn render_speed_test_section(&mut self, ui: &mut egui::Ui) {
        egui::Frame::NONE
            .fill(BG_CARD)
            .rounding(12.0)
            .inner_margin(egui::Margin::same(16))
            .show(ui, |ui| {
                // Section header
                ui.horizontal(|ui| {
                    ui.label(egui::RichText::new("^ Speed Test")
                        .size(16.0)
                        .color(TEXT_PRIMARY)
                        .strong());

                    ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                        if let Some(ref results) = self.network_analyzer_state.speed.results {
                            ui.label(egui::RichText::new(format!("via {}", results.server))
                                .size(11.0)
                                .color(TEXT_MUTED));
                        }
                    });
                });
                ui.add_space(16.0);

                // Speed gauges
                ui.horizontal(|ui| {
                    let gauge_width = (ui.available_width() - 16.0) / 2.0;

                    // Download gauge
                    ui.vertical(|ui| {
                        ui.set_width(gauge_width);
                        self.render_speed_gauge(ui, "Download", self.network_analyzer_state.speed.download_speed, ACCENT_CYAN, true);
                    });

                    ui.add_space(16.0);

                    // Upload gauge
                    ui.vertical(|ui| {
                        ui.set_width(gauge_width);
                        self.render_speed_gauge(ui, "Upload", self.network_analyzer_state.speed.upload_speed, ACCENT_SECONDARY, false);
                    });
                });

                ui.add_space(16.0);

                // Phase indicator
                if self.network_analyzer_state.speed.running {
                    let phase = &self.network_analyzer_state.speed.phase;
                    let phase_text = match phase {
                        crate::network_analyzer::SpeedTestPhase::Download => "v Testing Download...",
                        crate::network_analyzer::SpeedTestPhase::Upload => "^ Testing Upload...",
                        _ => "Starting...",
                    };

                    ui.horizontal(|ui| {
                        ui.spinner();
                        ui.label(egui::RichText::new(phase_text)
                            .size(13.0)
                            .color(TEXT_SECONDARY));

                        // Progress bar
                        ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                            let progress = self.network_analyzer_state.speed.phase_progress;
                            let progress_rect = ui.allocate_exact_size(egui::vec2(100.0, 4.0), egui::Sense::hover()).0;
                            let painter = ui.painter();
                            painter.rect_filled(progress_rect, 2.0, BG_ELEVATED);
                            let filled_width = progress_rect.width() * progress;
                            painter.rect_filled(
                                egui::Rect::from_min_size(progress_rect.min, egui::vec2(filled_width, 4.0)),
                                2.0,
                                ACCENT_PRIMARY
                            );
                        });
                    });
                    ui.add_space(8.0);
                }

                // Start button
                let is_running = self.network_analyzer_state.speed.running;
                let button_text = if is_running { "[] Stop Test" } else { "> Start Speed Test" };
                let button_color = if is_running { STATUS_ERROR } else { GRADIENT_CYAN_START };

                let button = egui::Button::new(
                    egui::RichText::new(button_text)
                        .size(14.0)
                        .color(TEXT_PRIMARY)
                )
                .fill(button_color)
                .rounding(8.0)
                .min_size(egui::vec2(ui.available_width(), 38.0));

                if ui.add(button).clicked() {
                    if is_running {
                        self.stop_speed_test();
                    } else {
                        self.start_speed_test();
                    }
                }

                // Last test info
                if let Some(ref results) = self.network_analyzer_state.speed.results {
                    ui.add_space(8.0);
                    ui.label(egui::RichText::new(format!(
                        "Last test: {} ({})",
                        results.timestamp.format("%H:%M:%S"),
                        results.server
                    ))
                        .size(10.0)
                        .color(TEXT_DIMMED));
                }
            });
    }

    /// Render a semi-circle speed gauge
    pub(crate) fn render_speed_gauge(&self, ui: &mut egui::Ui, label: &str, speed: f32, color: egui::Color32, _is_download: bool) {
        let gauge_size = 140.0;
        let (response, painter) = ui.allocate_painter(egui::vec2(ui.available_width(), gauge_size), egui::Sense::hover());
        let rect = response.rect;
        let center = egui::pos2(rect.center().x, rect.max.y - 20.0);
        let radius = gauge_size * 0.4;

        // Draw background arc
        let arc_width = 12.0;
        let segments = 60;
        for i in 0..segments {
            let angle1 = std::f32::consts::PI - (i as f32 / segments as f32) * std::f32::consts::PI;
            let angle2 = std::f32::consts::PI - ((i + 1) as f32 / segments as f32) * std::f32::consts::PI;

            let p1 = center + egui::vec2(angle1.cos() * radius, -angle1.sin() * radius);
            let p2 = center + egui::vec2(angle2.cos() * radius, -angle2.sin() * radius);

            painter.line_segment([p1, p2], egui::Stroke::new(arc_width, BG_ELEVATED));
        }

        // Draw filled arc based on speed (max 1000 Mbps scale)
        let max_speed = 1000.0_f32;
        let fill_ratio = (speed / max_speed).min(1.0);
        let fill_segments = (fill_ratio * segments as f32) as usize;

        for i in 0..fill_segments {
            let angle1 = std::f32::consts::PI - (i as f32 / segments as f32) * std::f32::consts::PI;
            let angle2 = std::f32::consts::PI - ((i + 1) as f32 / segments as f32) * std::f32::consts::PI;

            let p1 = center + egui::vec2(angle1.cos() * radius, -angle1.sin() * radius);
            let p2 = center + egui::vec2(angle2.cos() * radius, -angle2.sin() * radius);

            // Gradient effect - more saturated towards the end
            let segment_ratio = i as f32 / fill_segments.max(1) as f32;
            let segment_color = lerp_color(color.gamma_multiply(0.6), color, segment_ratio);

            painter.line_segment([p1, p2], egui::Stroke::new(arc_width, segment_color));
        }

        // Draw speed value in center
        let speed_text = format_speed(speed);
        painter.text(
            center + egui::vec2(0.0, -15.0),
            egui::Align2::CENTER_CENTER,
            &speed_text,
            egui::FontId::proportional(24.0),
            TEXT_PRIMARY
        );

        // Draw label below
        painter.text(
            center + egui::vec2(0.0, 10.0),
            egui::Align2::CENTER_CENTER,
            label,
            egui::FontId::proportional(12.0),
            TEXT_SECONDARY
        );

        // Draw scale markers
        for (ratio, label) in [(0.0, "0"), (0.25, "250"), (0.5, "500"), (0.75, "750"), (1.0, "1000")] {
            let angle = std::f32::consts::PI - ratio * std::f32::consts::PI;
            let marker_pos = center + egui::vec2(angle.cos() * (radius + 20.0), -angle.sin() * (radius + 20.0));
            painter.text(
                marker_pos,
                egui::Align2::CENTER_CENTER,
                label,
                egui::FontId::proportional(8.0),
                TEXT_DIMMED
            );
        }
    }

    /// Start the speed test
    pub(crate) fn start_speed_test(&mut self) {
        if self.network_analyzer_state.speed.running {
            return;
        }

        // Reset state
        self.network_analyzer_state.speed.running = true;
        self.network_analyzer_state.speed.phase = crate::network_analyzer::SpeedTestPhase::Download;
        self.network_analyzer_state.speed.phase_progress = 0.0;
        self.network_analyzer_state.speed.download_speed = 0.0;
        self.network_analyzer_state.speed.upload_speed = 0.0;
        self.network_analyzer_state.speed.results = None;

        // Create new channel for this test
        let (tx, rx) = std::sync::mpsc::channel::<SpeedTestProgress>();
        self.speed_progress_rx = rx;

        // Spawn test in background
        let rt = Arc::clone(&self.runtime);
        std::thread::spawn(move || {
            let _ = rt.block_on(async {
                run_speed_test(tx).await
            });
        });
    }

    /// Stop the speed test
    pub(crate) fn stop_speed_test(&mut self) {
        if !self.network_analyzer_state.speed.running {
            return;
        }

        log::info!("Stopping speed test");

        // Mark as stopped
        self.network_analyzer_state.speed.running = false;
        self.network_analyzer_state.speed.phase = crate::network_analyzer::SpeedTestPhase::Idle;

        // Create new channel to discard any pending messages from old test
        let (tx, rx) = std::sync::mpsc::channel::<SpeedTestProgress>();
        self.speed_progress_rx = rx;
        // tx is dropped, old background thread will error when sending (harmless)
        drop(tx);
    }
}
