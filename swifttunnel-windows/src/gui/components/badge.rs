//! Badge components
//!
//! Status badges, tier indicators, and info pills.

use eframe::egui::{self, Color32, Ui, Vec2, Sense};
use crate::gui::theme::*;

/// Status badge variant
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum BadgeVariant {
    /// Success/connected - green
    Success,
    /// Warning/connecting - amber
    Warning,
    /// Error/offline - red
    Error,
    /// Info - blue
    Info,
    /// Neutral - gray
    Neutral,
    /// Primary - accent blue
    Primary,
    /// Secondary - violet
    Secondary,
}

impl BadgeVariant {
    fn color(&self) -> Color32 {
        match self {
            BadgeVariant::Success => STATUS_CONNECTED,
            BadgeVariant::Warning => STATUS_WARNING,
            BadgeVariant::Error => STATUS_ERROR,
            BadgeVariant::Info => ACCENT_CYAN,
            BadgeVariant::Neutral => TEXT_MUTED,
            BadgeVariant::Primary => ACCENT_PRIMARY,
            BadgeVariant::Secondary => ACCENT_SECONDARY,
        }
    }
}

/// Simple status badge
pub fn status_badge(ui: &mut Ui, text: &str, variant: BadgeVariant) {
    let color = variant.color();

    egui::Frame::none()
        .fill(color.gamma_multiply(0.15))
        .stroke(egui::Stroke::new(1.0, color.gamma_multiply(0.3)))
        .rounding(10.0)
        .inner_margin(egui::Margin::symmetric(8.0, 3.0))
        .show(ui, |ui| {
            ui.label(egui::RichText::new(text)
                .size(11.0)
                .color(color));
        });
}

/// Badge with indicator dot
pub fn dot_badge(ui: &mut Ui, text: &str, variant: BadgeVariant, show_pulse: bool, app_start_time: std::time::Instant) {
    let color = variant.color();

    egui::Frame::none()
        .fill(color.gamma_multiply(0.12))
        .stroke(egui::Stroke::new(1.0, color.gamma_multiply(0.3)))
        .rounding(14.0)
        .inner_margin(egui::Margin::symmetric(12.0, 6.0))
        .show(ui, |ui| {
            ui.horizontal(|ui| {
                ui.spacing_mut().item_spacing.x = 6.0;

                // Indicator dot
                let dot_size = 8.0;
                let (dot_rect, _) = ui.allocate_exact_size(Vec2::new(dot_size, dot_size), Sense::hover());

                if show_pulse {
                    let elapsed = app_start_time.elapsed().as_secs_f32();
                    let pulse = ((elapsed * std::f32::consts::PI / PULSE_ANIMATION_DURATION).sin() + 1.0) / 2.0;
                    let glow_radius = 3.0 + pulse * 2.0;
                    let glow_alpha = 0.4 + pulse * 0.3;

                    ui.painter().circle_filled(dot_rect.center(), glow_radius, color.gamma_multiply(glow_alpha));
                }
                ui.painter().circle_filled(dot_rect.center(), 3.0, color);

                // Text
                ui.label(egui::RichText::new(text)
                    .size(11.0)
                    .color(color)
                    .strong());
            });
        });
}

/// Tier badge (e.g., "TIER 1 - SAFE")
pub fn tier_badge(ui: &mut Ui, tier: u8, label: &str) {
    let (color, text) = match tier {
        1 => (STATUS_CONNECTED, "TIER 1"),
        2 => (STATUS_WARNING, "TIER 2"),
        3 => (STATUS_ERROR, "TIER 3"),
        _ => (TEXT_MUTED, "TIER ?"),
    };

    egui::Frame::none()
        .fill(color.gamma_multiply(0.1))
        .rounding(4.0)
        .inner_margin(egui::Margin::symmetric(6.0, 2.0))
        .show(ui, |ui| {
            ui.horizontal(|ui| {
                ui.spacing_mut().item_spacing.x = 4.0;
                ui.label(egui::RichText::new(text)
                    .size(9.0)
                    .color(color)
                    .strong());
                ui.label(egui::RichText::new("-")
                    .size(9.0)
                    .color(TEXT_DIMMED));
                ui.label(egui::RichText::new(label)
                    .size(9.0)
                    .color(TEXT_MUTED));
            });
        });
}

/// Count badge (e.g., "3 selected")
pub fn count_badge(ui: &mut Ui, count: usize, label: &str) {
    if count == 0 {
        return;
    }

    egui::Frame::none()
        .fill(ACCENT_PRIMARY.gamma_multiply(0.15))
        .stroke(egui::Stroke::new(1.0, ACCENT_PRIMARY.gamma_multiply(0.3)))
        .rounding(12.0)
        .inner_margin(egui::Margin::symmetric(10.0, 4.0))
        .show(ui, |ui| {
            ui.horizontal(|ui| {
                ui.spacing_mut().item_spacing.x = 4.0;
                ui.label(egui::RichText::new("⚡").size(10.0));
                ui.label(egui::RichText::new(format!("{} {}", count, label))
                    .size(11.0)
                    .color(ACCENT_PRIMARY)
                    .strong());
            });
        });
}

/// Version badge
pub fn version_badge(ui: &mut Ui, version: &str) {
    ui.label(egui::RichText::new(format!("v{}", version))
        .size(10.0)
        .color(TEXT_DIMMED));
}

/// Protocol badge for connection stats
pub fn protocol_badge(ui: &mut Ui, protocol: &str) {
    let color = match protocol.to_uppercase().as_str() {
        "UDP" => ACCENT_CYAN,
        "TCP" => ACCENT_PRIMARY,
        _ => TEXT_MUTED,
    };

    egui::Frame::none()
        .fill(color.gamma_multiply(0.15))
        .rounding(4.0)
        .inner_margin(egui::Margin::symmetric(6.0, 2.0))
        .show(ui, |ui| {
            ui.label(egui::RichText::new(protocol)
                .size(10.0)
                .color(color)
                .strong());
        });
}

/// Region indicator with flag
pub fn region_indicator(ui: &mut Ui, region_id: &str, latency_ms: Option<u32>) {
    let flag = get_region_flag(region_id);
    let name = get_region_name(region_id);

    ui.horizontal(|ui| {
        ui.spacing_mut().item_spacing.x = 4.0;
        ui.label(egui::RichText::new(flag).size(14.0));
        ui.label(egui::RichText::new(name)
            .size(12.0)
            .color(TEXT_PRIMARY));

        if let Some(ms) = latency_ms {
            let color = latency_color(ms);
            ui.label(egui::RichText::new("•").size(10.0).color(TEXT_MUTED));
            ui.label(egui::RichText::new(format!("{}ms", ms))
                .size(11.0)
                .color(color));
        }
    });
}
