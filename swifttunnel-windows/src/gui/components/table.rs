//! Table components
//!
//! Data tables for connection stats, process lists, etc.

use eframe::egui::{self, Ui, Vec2};
use crate::gui::theme::*;
use crate::gui::components::badge::protocol_badge;

/// Row data for connection stats table
pub struct ConnectionStatRow {
    pub app_name: String,
    pub server: String,
    pub server_flag: String,
    pub protocol: String,
    pub bytes_sent: u64,
    pub bytes_recv: u64,
}

/// Render connection stats table
pub fn connection_stats_table(ui: &mut Ui, rows: &[ConnectionStatRow]) {
    if rows.is_empty() {
        // Empty state
        egui::Frame::none()
            .fill(BG_ELEVATED)
            .rounding(8.0)
            .inner_margin(CONTENT_PADDING)
            .show(ui, |ui| {
                ui.vertical_centered(|ui| {
                    ui.label(egui::RichText::new("📊")
                        .size(24.0)
                        .color(TEXT_DIMMED));
                    ui.add_space(8.0);
                    ui.label(egui::RichText::new("No active connections")
                        .size(13.0)
                        .color(TEXT_MUTED));
                    ui.label(egui::RichText::new("Start a game to see connection stats")
                        .size(11.0)
                        .color(TEXT_DIMMED));
                });
            });
        return;
    }

    egui::Frame::none()
        .fill(BG_ELEVATED)
        .rounding(8.0)
        .show(ui, |ui| {
            ui.set_min_width(ui.available_width());

            // Header row
            egui::Frame::none()
                .fill(BG_CARD)
                .rounding(egui::Rounding {
                    nw: 8.0,
                    ne: 8.0,
                    sw: 0.0,
                    se: 0.0,
                })
                .inner_margin(egui::Margin::symmetric(12.0, 8.0))
                .show(ui, |ui| {
                    ui.horizontal(|ui| {
                        // Application column (40%)
                        ui.allocate_ui(Vec2::new(ui.available_width() * 0.35, 20.0), |ui| {
                            ui.label(egui::RichText::new("Application")
                                .size(10.0)
                                .color(TEXT_MUTED)
                                .strong());
                        });

                        // Server column (25%)
                        ui.allocate_ui(Vec2::new(ui.available_width() * 0.25, 20.0), |ui| {
                            ui.label(egui::RichText::new("Server")
                                .size(10.0)
                                .color(TEXT_MUTED)
                                .strong());
                        });

                        // Protocol column (15%)
                        ui.allocate_ui(Vec2::new(ui.available_width() * 0.15, 20.0), |ui| {
                            ui.label(egui::RichText::new("Protocol")
                                .size(10.0)
                                .color(TEXT_MUTED)
                                .strong());
                        });

                        // Sent column (12%)
                        ui.allocate_ui(Vec2::new(ui.available_width() * 0.12, 20.0), |ui| {
                            ui.label(egui::RichText::new("↑ Sent")
                                .size(10.0)
                                .color(TEXT_MUTED)
                                .strong());
                        });

                        // Recv column (12%)
                        ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                            ui.label(egui::RichText::new("↓ Recv")
                                .size(10.0)
                                .color(TEXT_MUTED)
                                .strong());
                        });
                    });
                });

            // Data rows
            for (idx, row) in rows.iter().enumerate() {
                let bg = if idx % 2 == 0 { BG_ELEVATED } else { BG_CARD.gamma_multiply(0.5) };

                egui::Frame::none()
                    .fill(bg)
                    .inner_margin(egui::Margin::symmetric(12.0, 8.0))
                    .show(ui, |ui| {
                        ui.horizontal(|ui| {
                            // Application
                            ui.allocate_ui(Vec2::new(ui.available_width() * 0.35, 20.0), |ui| {
                                ui.label(egui::RichText::new(&row.app_name)
                                    .size(12.0)
                                    .color(TEXT_PRIMARY));
                            });

                            // Server
                            ui.allocate_ui(Vec2::new(ui.available_width() * 0.25, 20.0), |ui| {
                                ui.horizontal(|ui| {
                                    ui.spacing_mut().item_spacing.x = 4.0;
                                    ui.label(egui::RichText::new(&row.server_flag).size(12.0));
                                    ui.label(egui::RichText::new(&row.server)
                                        .size(11.0)
                                        .color(TEXT_SECONDARY));
                                });
                            });

                            // Protocol
                            ui.allocate_ui(Vec2::new(ui.available_width() * 0.15, 20.0), |ui| {
                                protocol_badge(ui, &row.protocol);
                            });

                            // Sent
                            ui.allocate_ui(Vec2::new(ui.available_width() * 0.12, 20.0), |ui| {
                                ui.label(egui::RichText::new(format_bytes_rate(row.bytes_sent))
                                    .size(11.0)
                                    .color(ACCENT_CYAN));
                            });

                            // Recv
                            ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                                ui.label(egui::RichText::new(format_bytes_rate(row.bytes_recv))
                                    .size(11.0)
                                    .color(STATUS_CONNECTED));
                            });
                        });
                    });
            }
        });
}

/// Format bytes as human-readable rate
fn format_bytes_rate(bytes: u64) -> String {
    if bytes >= 1_000_000 {
        format!("{:.1}MB/s", bytes as f64 / 1_000_000.0)
    } else if bytes >= 1_000 {
        format!("{:.0}KB/s", bytes as f64 / 1_000.0)
    } else {
        format!("{}B/s", bytes)
    }
}

/// Tunneled processes list (simpler than full stats table)
pub fn tunneled_processes_list(ui: &mut Ui, processes: &[String]) {
    if processes.is_empty() {
        ui.label(egui::RichText::new("No processes tunneled")
            .size(11.0)
            .color(TEXT_MUTED));
        return;
    }

    for process in processes {
        ui.horizontal(|ui| {
            ui.spacing_mut().item_spacing.x = 8.0;
            ui.label(egui::RichText::new("✓").size(12.0).color(STATUS_CONNECTED));
            ui.label(egui::RichText::new(process)
                .size(12.0)
                .color(TEXT_PRIMARY));
        });
    }
}

/// Simple key-value row for settings/info
pub fn key_value_row(ui: &mut Ui, key: &str, value: &str) {
    ui.horizontal(|ui| {
        ui.label(egui::RichText::new(key)
            .size(12.0)
            .color(TEXT_SECONDARY));
        ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
            ui.label(egui::RichText::new(value)
                .size(12.0)
                .color(TEXT_PRIMARY));
        });
    });
}
