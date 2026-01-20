//! SwiftTunnel Design System v6
//! Modern layout with SwiftTunnel's blue/cyan color scheme
//!
//! This module contains all design tokens, colors, spacing, and visual constants.

use eframe::egui::{self, Color32};

// ═══════════════════════════════════════════════════════════════════════════════
//  LAYOUT CONSTANTS
// ═══════════════════════════════════════════════════════════════════════════════

/// Width of the sidebar navigation (icon-only)
pub const SIDEBAR_WIDTH: f32 = 60.0;

/// Height of the header bar
pub const HEADER_HEIGHT: f32 = 60.0;

/// Card corner rounding
pub const CARD_ROUNDING: f32 = 12.0;

/// Standard content padding
pub const CONTENT_PADDING: f32 = 24.0;

/// Small content padding
pub const CONTENT_PADDING_SM: f32 = 16.0;

/// Button/card minimum height
pub const BUTTON_HEIGHT: f32 = 38.0;

/// Icon size for sidebar
pub const SIDEBAR_ICON_SIZE: f32 = 20.0;

/// Nav accent bar width
pub const NAV_ACCENT_WIDTH: f32 = 3.0;

// ═══════════════════════════════════════════════════════════════════════════════
//  BACKGROUND COLORS
//  Deep blue-black palette for modern dark theme
// ═══════════════════════════════════════════════════════════════════════════════

/// Sidebar background - deepest
pub const BG_SIDEBAR: Color32 = Color32::from_rgb(8, 10, 20);

/// Main content area background
pub const BG_MAIN: Color32 = Color32::from_rgb(12, 15, 26);

/// Card/panel background
pub const BG_CARD: Color32 = Color32::from_rgb(18, 22, 36);

/// Elevated surfaces (modals, tooltips)
pub const BG_ELEVATED: Color32 = Color32::from_rgb(26, 32, 48);

/// Hover state background
pub const BG_HOVER: Color32 = Color32::from_rgb(32, 40, 58);

/// Active/pressed state background
pub const BG_ACTIVE: Color32 = Color32::from_rgb(38, 48, 68);

/// Input field background
pub const BG_INPUT: Color32 = Color32::from_rgb(14, 20, 32);

/// Darkest background (for app chrome)
pub const BG_DARKEST: Color32 = Color32::from_rgb(6, 9, 18);

// ═══════════════════════════════════════════════════════════════════════════════
//  ACCENT COLORS
//  SwiftTunnel brand colors (blue/cyan)
// ═══════════════════════════════════════════════════════════════════════════════

/// Primary accent - blue
pub const ACCENT_PRIMARY: Color32 = Color32::from_rgb(59, 130, 246);   // #3b82f6

/// Secondary accent - violet
pub const ACCENT_SECONDARY: Color32 = Color32::from_rgb(139, 92, 246); // #8b5cf6

/// Cyan highlight
pub const ACCENT_CYAN: Color32 = Color32::from_rgb(34, 211, 238);      // #22d3ee

/// Gradient start (blue)
pub const GRADIENT_START: Color32 = Color32::from_rgb(59, 130, 246);

/// Gradient end (violet)
pub const GRADIENT_END: Color32 = Color32::from_rgb(139, 92, 246);

/// Gradient cyan start
pub const GRADIENT_CYAN_START: Color32 = Color32::from_rgb(34, 211, 238);

/// Gradient cyan end (emerald)
pub const GRADIENT_CYAN_END: Color32 = Color32::from_rgb(52, 211, 153);

// ═══════════════════════════════════════════════════════════════════════════════
//  STATUS COLORS
// ═══════════════════════════════════════════════════════════════════════════════

/// Connected/success - emerald
pub const STATUS_CONNECTED: Color32 = Color32::from_rgb(52, 211, 153);  // #34d399

/// Connected glow (brighter)
pub const STATUS_CONNECTED_GLOW: Color32 = Color32::from_rgb(110, 231, 183);

/// Warning/connecting - amber
pub const STATUS_WARNING: Color32 = Color32::from_rgb(251, 191, 36);    // #fbbf24

/// Error/disconnected - red
pub const STATUS_ERROR: Color32 = Color32::from_rgb(248, 113, 113);     // #f87171

/// Inactive/offline - slate
pub const STATUS_INACTIVE: Color32 = Color32::from_rgb(75, 85, 99);     // #4b5563

// ═══════════════════════════════════════════════════════════════════════════════
//  TEXT COLORS
// ═══════════════════════════════════════════════════════════════════════════════

/// Primary text - near white
pub const TEXT_PRIMARY: Color32 = Color32::from_rgb(248, 250, 252);     // #f8fafc

/// Secondary text - slate-400
pub const TEXT_SECONDARY: Color32 = Color32::from_rgb(148, 163, 184);   // #94a3b8

/// Muted text - slate-500
pub const TEXT_MUTED: Color32 = Color32::from_rgb(100, 116, 139);       // #64748b

/// Dimmed text - slate-600
pub const TEXT_DIMMED: Color32 = Color32::from_rgb(71, 85, 105);        // #475569

// ═══════════════════════════════════════════════════════════════════════════════
//  LATENCY COLORS
// ═══════════════════════════════════════════════════════════════════════════════

/// Excellent latency (<30ms) - emerald
pub const LATENCY_EXCELLENT: Color32 = Color32::from_rgb(52, 211, 153);

/// Good latency (<60ms) - lime
pub const LATENCY_GOOD: Color32 = Color32::from_rgb(163, 230, 53);

/// Fair latency (<100ms) - yellow
pub const LATENCY_FAIR: Color32 = Color32::from_rgb(251, 191, 36);

/// Poor latency (<150ms) - orange
pub const LATENCY_POOR: Color32 = Color32::from_rgb(251, 146, 60);

/// Bad latency (>=150ms) - red
pub const LATENCY_BAD: Color32 = Color32::from_rgb(248, 113, 113);

/// Get latency color based on milliseconds
pub fn latency_color(ms: u32) -> Color32 {
    if ms < 30 { LATENCY_EXCELLENT }
    else if ms < 60 { LATENCY_GOOD }
    else if ms < 100 { LATENCY_FAIR }
    else if ms < 150 { LATENCY_POOR }
    else { LATENCY_BAD }
}

/// Calculate latency bar fill percentage (0.0 - 1.0)
/// Lower latency = more fill
pub fn latency_fill_percent(ms: u32) -> f32 {
    // 0ms = 100%, 200ms+ = 10%
    let normalized = (ms as f32 / 200.0).min(1.0);
    1.0 - (normalized * 0.9)
}

// ═══════════════════════════════════════════════════════════════════════════════
//  ANIMATION DURATIONS
// ═══════════════════════════════════════════════════════════════════════════════

/// Toggle switch animation
pub const TOGGLE_ANIMATION_DURATION: f32 = 0.15;

/// Pulse/breathing animation (for connected state)
pub const PULSE_ANIMATION_DURATION: f32 = 2.0;

/// Hover animation
pub const HOVER_ANIMATION_DURATION: f32 = 0.1;

/// Shimmer/skeleton loading animation
pub const SHIMMER_ANIMATION_DURATION: f32 = 1.5;

/// Card state transitions
pub const CARD_TRANSITION_DURATION: f32 = 0.2;

/// Button press feedback
pub const BUTTON_PRESS_DURATION: f32 = 0.08;

// ═══════════════════════════════════════════════════════════════════════════════
//  STYLE CONFIGURATION
// ═══════════════════════════════════════════════════════════════════════════════

/// Configure egui style with SwiftTunnel theme
pub fn configure_style(ctx: &egui::Context) {
    let mut style = (*ctx.style()).clone();
    style.visuals.dark_mode = true;
    style.visuals.panel_fill = BG_MAIN;
    style.visuals.window_fill = BG_CARD;
    style.visuals.extreme_bg_color = BG_CARD;
    style.visuals.faint_bg_color = BG_ELEVATED;

    style.visuals.widgets.inactive.bg_fill = BG_CARD;
    style.visuals.widgets.inactive.fg_stroke = egui::Stroke::new(1.0, TEXT_SECONDARY);
    style.visuals.widgets.inactive.rounding = egui::Rounding::same(8.0);

    style.visuals.widgets.hovered.bg_fill = BG_HOVER;
    style.visuals.widgets.hovered.fg_stroke = egui::Stroke::new(1.0, TEXT_PRIMARY);
    style.visuals.widgets.hovered.rounding = egui::Rounding::same(8.0);

    style.visuals.widgets.active.bg_fill = ACCENT_PRIMARY;
    style.visuals.widgets.active.fg_stroke = egui::Stroke::new(1.0, TEXT_PRIMARY);
    style.visuals.widgets.active.rounding = egui::Rounding::same(8.0);

    style.visuals.widgets.noninteractive.fg_stroke = egui::Stroke::new(1.0, TEXT_PRIMARY);
    style.visuals.selection.bg_fill = ACCENT_PRIMARY.gamma_multiply(0.3);

    style.spacing.item_spacing = egui::vec2(10.0, 8.0);
    style.spacing.button_padding = egui::vec2(16.0, 8.0);
    style.spacing.window_margin = egui::Margin::same(16.0);

    ctx.set_style(style);
}

// ═══════════════════════════════════════════════════════════════════════════════
//  HELPER FUNCTIONS
// ═══════════════════════════════════════════════════════════════════════════════

/// Interpolate between two colors
pub fn lerp_color(from: Color32, to: Color32, t: f32) -> Color32 {
    let t = t.clamp(0.0, 1.0);
    Color32::from_rgba_unmultiplied(
        (from.r() as f32 + (to.r() as f32 - from.r() as f32) * t) as u8,
        (from.g() as f32 + (to.g() as f32 - from.g() as f32) * t) as u8,
        (from.b() as f32 + (to.b() as f32 - from.b() as f32) * t) as u8,
        (from.a() as f32 + (to.a() as f32 - from.a() as f32) * t) as u8,
    )
}

/// Ease-out-cubic interpolation for smooth animations
pub fn ease_out_cubic(t: f32) -> f32 {
    let t = t.clamp(0.0, 1.0);
    1.0 - (1.0 - t).powi(3)
}

/// Ease-in-out sine for shimmer effects
pub fn ease_in_out_sine(t: f32) -> f32 {
    let t = t.clamp(0.0, 1.0);
    -(((t * std::f32::consts::PI).cos() - 1.0) / 2.0)
}

/// Get ISO country code for region (Windows can't render flag emojis properly)
pub fn get_region_code(region_id: &str) -> &'static str {
    match region_id {
        "singapore" => "SG",
        "mumbai" => "IN",
        "tokyo" => "JP",
        "sydney" => "AU",
        "germany" => "DE",
        "paris" => "FR",
        "america" => "US",
        "brazil" => "BR",
        _ => "??",
    }
}

/// Get flag color for region (used for colored country code background)
pub fn get_region_flag_color(region_id: &str) -> (Color32, Color32) {
    // Returns (primary_color, secondary_color) for gradient effect
    match region_id {
        "singapore" => (Color32::from_rgb(237, 28, 36), Color32::from_rgb(255, 255, 255)),   // Red/White
        "mumbai" => (Color32::from_rgb(255, 153, 51), Color32::from_rgb(19, 136, 8)),       // Orange/Green
        "tokyo" => (Color32::from_rgb(255, 255, 255), Color32::from_rgb(188, 0, 45)),       // White/Red
        "sydney" => (Color32::from_rgb(0, 0, 139), Color32::from_rgb(255, 255, 255)),       // Blue/White
        "germany" => (Color32::from_rgb(0, 0, 0), Color32::from_rgb(255, 206, 0)),          // Black/Gold
        "paris" => (Color32::from_rgb(0, 85, 164), Color32::from_rgb(239, 65, 53)),         // Blue/Red
        "america" => (Color32::from_rgb(60, 59, 110), Color32::from_rgb(178, 34, 52)),      // Blue/Red
        "brazil" => (Color32::from_rgb(0, 156, 59), Color32::from_rgb(255, 223, 0)),        // Green/Yellow
        _ => (TEXT_MUTED, TEXT_DIMMED),
    }
}

/// Get country flag emoji for region (kept for backwards compatibility, but prefer get_region_code)
pub fn get_region_flag(region_id: &str) -> &'static str {
    // Note: Windows doesn't render these properly, use get_region_code instead
    match region_id {
        "singapore" => "🇸🇬",
        "mumbai" => "🇮🇳",
        "tokyo" => "🇯🇵",
        "sydney" => "🇦🇺",
        "germany" => "🇩🇪",
        "paris" => "🇫🇷",
        "america" => "🇺🇸",
        "brazil" => "🇧🇷",
        _ => "🌍",
    }
}

/// Get human-readable region name
pub fn get_region_name(region_id: &str) -> &'static str {
    match region_id {
        "singapore" => "Singapore",
        "mumbai" => "Mumbai",
        "tokyo" => "Tokyo",
        "sydney" => "Sydney",
        "germany" => "Germany",
        "paris" => "Paris",
        "america" => "America",
        "brazil" => "Brazil",
        _ => "Unknown",
    }
}
