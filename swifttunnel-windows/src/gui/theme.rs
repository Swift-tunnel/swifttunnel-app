//! SwiftTunnel Design System v8
//! Clean Dark Pro - modern, professional gaming utility aesthetic
//! Neutral dark backgrounds with signature blue accent

use eframe::egui;

// ═══════════════════════════════════════════════════════════════════════════════
//  LAYOUT CONSTANTS
// ═══════════════════════════════════════════════════════════════════════════════

/// Left sidebar width - wider for text labels
pub const SIDEBAR_WIDTH: f32 = 64.0;
/// Top bar height with status and toggle
pub const TOP_BAR_HEIGHT: f32 = 56.0;
/// Decorative header banner height (kept for layout compatibility, reduced)
pub const HEADER_BANNER_HEIGHT: f32 = 56.0;
/// Content padding from edges
pub const CONTENT_PADDING: f32 = 28.0;
/// Standard card gap
pub const CARD_GAP: f32 = 14.0;
/// Small spacing
pub const SPACING_SM: f32 = 8.0;
/// Medium spacing
pub const SPACING_MD: f32 = 16.0;
/// Large spacing
pub const SPACING_LG: f32 = 24.0;
/// Extra large spacing
pub const SPACING_XL: f32 = 32.0;

// ═══════════════════════════════════════════════════════════════════════════════
//  CORE BACKGROUNDS - neutral darks with subtle warmth
// ═══════════════════════════════════════════════════════════════════════════════

/// Main app background - deepest layer
pub const BG_BASE: egui::Color32 = egui::Color32::from_rgb(14, 14, 18);
/// Sidebar background
pub const BG_SIDEBAR: egui::Color32 = egui::Color32::from_rgb(18, 18, 23);
/// Card/panel background
pub const BG_CARD: egui::Color32 = egui::Color32::from_rgb(24, 24, 30);
/// Elevated surfaces (popups, dropdowns)
pub const BG_ELEVATED: egui::Color32 = egui::Color32::from_rgb(32, 32, 40);
/// Hover state background
pub const BG_HOVER: egui::Color32 = egui::Color32::from_rgb(40, 40, 50);
/// Active/pressed state
pub const BG_ACTIVE: egui::Color32 = egui::Color32::from_rgb(48, 48, 58);
/// Input field background
pub const BG_INPUT: egui::Color32 = egui::Color32::from_rgb(18, 18, 22);
/// Glass overlay
pub const BG_GLASS: egui::Color32 = egui::Color32::from_rgb(20, 20, 26);

// ═══════════════════════════════════════════════════════════════════════════════
//  PRIMARY ACCENTS - signature blue brand
// ═══════════════════════════════════════════════════════════════════════════════

/// Main accent - signature blue
pub const ACCENT_PRIMARY: egui::Color32 = egui::Color32::from_rgb(60, 130, 246);
/// Secondary accent - lighter blue
pub const ACCENT_SECONDARY: egui::Color32 = egui::Color32::from_rgb(96, 165, 255);
/// Tertiary accent - sky blue for highlights
pub const ACCENT_CYAN: egui::Color32 = egui::Color32::from_rgb(56, 152, 255);
/// Purple accent for special elements
pub const ACCENT_PURPLE: egui::Color32 = egui::Color32::from_rgb(150, 100, 255);
/// Lime accent for performance indicators
pub const ACCENT_LIME: egui::Color32 = egui::Color32::from_rgb(130, 220, 60);

/// Glow versions of accents (for effects)
pub const ACCENT_PRIMARY_GLOW: egui::Color32 = egui::Color32::from_rgb(100, 165, 255);
pub const ACCENT_SECONDARY_GLOW: egui::Color32 = egui::Color32::from_rgb(130, 185, 255);

// ═══════════════════════════════════════════════════════════════════════════════
//  STATUS COLORS
// ═══════════════════════════════════════════════════════════════════════════════

/// Connected/success
pub const STATUS_CONNECTED: egui::Color32 = egui::Color32::from_rgb(40, 210, 150);
/// Connected glow for pulse effects
pub const STATUS_CONNECTED_GLOW: egui::Color32 = egui::Color32::from_rgb(100, 240, 200);
/// Warning state - warm amber
pub const STATUS_WARNING: egui::Color32 = egui::Color32::from_rgb(245, 180, 40);
/// Error state - soft red
pub const STATUS_ERROR: egui::Color32 = egui::Color32::from_rgb(240, 90, 90);
/// Inactive/disabled state
pub const STATUS_INACTIVE: egui::Color32 = egui::Color32::from_rgb(80, 80, 95);

// ═══════════════════════════════════════════════════════════════════════════════
//  TEXT COLORS - high contrast, readable
// ═══════════════════════════════════════════════════════════════════════════════

/// Primary text - clean white
pub const TEXT_PRIMARY: egui::Color32 = egui::Color32::from_rgb(235, 235, 240);
/// Secondary text - medium gray
pub const TEXT_SECONDARY: egui::Color32 = egui::Color32::from_rgb(155, 155, 170);
/// Muted text
pub const TEXT_MUTED: egui::Color32 = egui::Color32::from_rgb(105, 105, 120);
/// Dimmed text
pub const TEXT_DIMMED: egui::Color32 = egui::Color32::from_rgb(70, 70, 85);

// ═══════════════════════════════════════════════════════════════════════════════
//  BORDER COLORS
// ═══════════════════════════════════════════════════════════════════════════════

/// Default border
pub const BORDER_DEFAULT: egui::Color32 = egui::Color32::from_rgb(38, 38, 48);
/// Subtle border
pub const BORDER_SUBTLE: egui::Color32 = egui::Color32::from_rgb(28, 28, 36);
/// Focus/active border
pub const BORDER_FOCUS: egui::Color32 = ACCENT_PRIMARY;
/// Hover border
pub const BORDER_HOVER: egui::Color32 = egui::Color32::from_rgb(55, 55, 68);

// ═══════════════════════════════════════════════════════════════════════════════
//  LATENCY COLORS
// ═══════════════════════════════════════════════════════════════════════════════

/// Excellent latency (< 30ms)
pub const LATENCY_EXCELLENT: egui::Color32 = egui::Color32::from_rgb(40, 210, 150);
/// Good latency (< 60ms)
pub const LATENCY_GOOD: egui::Color32 = egui::Color32::from_rgb(130, 220, 60);
/// Fair latency (< 100ms)
pub const LATENCY_FAIR: egui::Color32 = egui::Color32::from_rgb(245, 180, 40);
/// Poor latency (< 150ms)
pub const LATENCY_POOR: egui::Color32 = egui::Color32::from_rgb(240, 140, 50);
/// Bad latency (>= 150ms)
pub const LATENCY_BAD: egui::Color32 = egui::Color32::from_rgb(240, 90, 90);

/// Get latency color based on ms value
pub fn latency_color(ms: u32) -> egui::Color32 {
    if ms < 30 { LATENCY_EXCELLENT }
    else if ms < 60 { LATENCY_GOOD }
    else if ms < 100 { LATENCY_FAIR }
    else if ms < 150 { LATENCY_POOR }
    else { LATENCY_BAD }
}

/// Calculate latency bar fill percentage (0.0 - 1.0)
pub fn latency_fill_percent(ms: u32) -> f32 {
    let normalized = (ms as f32 / 200.0).min(1.0);
    1.0 - (normalized * 0.9)
}

// ═══════════════════════════════════════════════════════════════════════════════
//  GRADIENT DEFINITIONS
// ═══════════════════════════════════════════════════════════════════════════════

/// Header banner gradient start
pub const GRADIENT_BANNER_START: egui::Color32 = egui::Color32::from_rgb(18, 22, 30);
/// Header banner gradient end
pub const GRADIENT_BANNER_END: egui::Color32 = egui::Color32::from_rgb(14, 14, 18);

/// Accent gradient start
pub const GRADIENT_ACCENT_START: egui::Color32 = egui::Color32::from_rgb(60, 130, 246);
/// Accent gradient end
pub const GRADIENT_ACCENT_END: egui::Color32 = egui::Color32::from_rgb(96, 165, 255);

// ═══════════════════════════════════════════════════════════════════════════════
//  UTILITY FUNCTIONS
// ═══════════════════════════════════════════════════════════════════════════════

/// Apply alpha to a color
pub fn with_alpha(color: egui::Color32, alpha: f32) -> egui::Color32 {
    egui::Color32::from_rgba_unmultiplied(
        color.r(),
        color.g(),
        color.b(),
        (alpha * 255.0).clamp(0.0, 255.0) as u8,
    )
}

/// Lighten a color by a factor (0.0 - 1.0)
pub fn lighten(color: egui::Color32, factor: f32) -> egui::Color32 {
    let f = factor.clamp(0.0, 1.0);
    egui::Color32::from_rgb(
        (color.r() as f32 + (255.0 - color.r() as f32) * f) as u8,
        (color.g() as f32 + (255.0 - color.g() as f32) * f) as u8,
        (color.b() as f32 + (255.0 - color.b() as f32) * f) as u8,
    )
}

/// Darken a color by a factor (0.0 - 1.0)
pub fn darken(color: egui::Color32, factor: f32) -> egui::Color32 {
    let f = 1.0 - factor.clamp(0.0, 1.0);
    egui::Color32::from_rgb(
        (color.r() as f32 * f) as u8,
        (color.g() as f32 * f) as u8,
        (color.b() as f32 * f) as u8,
    )
}

/// Get a color with modified brightness for hover effects
pub fn hover_brightness(color: egui::Color32, is_hovered: bool) -> egui::Color32 {
    if is_hovered {
        lighten(color, 0.12)
    } else {
        color
    }
}

// ═══════════════════════════════════════════════════════════════════════════════
//  COMPONENT STYLES
// ═══════════════════════════════════════════════════════════════════════════════

/// Standard card frame style
pub fn card_frame() -> egui::Frame {
    egui::Frame::NONE
        .fill(BG_CARD)
        .stroke(egui::Stroke::new(1.0, BORDER_SUBTLE))
        .rounding(10.0)
        .inner_margin(egui::Margin::same(18))
}

/// Elevated card frame style (popups, modals)
pub fn elevated_frame() -> egui::Frame {
    egui::Frame::NONE
        .fill(BG_ELEVATED)
        .stroke(egui::Stroke::new(1.0, BORDER_DEFAULT))
        .rounding(10.0)
        .inner_margin(egui::Margin::same(18))
        .shadow(egui::epaint::Shadow {
            offset: [0, 4],
            blur: 20,
            spread: 0,
            color: egui::Color32::from_black_alpha(80),
        })
}

/// Sidebar navigation item frame
pub fn sidebar_item_frame(is_active: bool, is_hovered: bool) -> egui::Frame {
    let bg = if is_active {
        ACCENT_PRIMARY.gamma_multiply(0.12)
    } else if is_hovered {
        BG_HOVER
    } else {
        egui::Color32::TRANSPARENT
    };

    egui::Frame::NONE
        .fill(bg)
        .rounding(8.0)
        .inner_margin(egui::Margin::symmetric(12, 10))
}

/// Toggle switch track dimensions
pub const TOGGLE_WIDTH: f32 = 42.0;
pub const TOGGLE_HEIGHT: f32 = 22.0;
pub const TOGGLE_KNOB_SIZE: f32 = 16.0;

/// Standard button minimum size
pub const BUTTON_MIN_HEIGHT: f32 = 36.0;
pub const BUTTON_MIN_WIDTH: f32 = 100.0;

/// Icon sizes
pub const ICON_SIZE_SM: f32 = 16.0;
pub const ICON_SIZE_MD: f32 = 20.0;
pub const ICON_SIZE_LG: f32 = 24.0;
pub const ICON_SIZE_XL: f32 = 32.0;

// ═══════════════════════════════════════════════════════════════════════════════
//  LEGACY EXPORTS (for backwards compatibility)
// ═══════════════════════════════════════════════════════════════════════════════

pub const BG_DARKEST: egui::Color32 = BG_BASE;
pub const GRADIENT_START: egui::Color32 = ACCENT_SECONDARY;
pub const GRADIENT_END: egui::Color32 = ACCENT_PURPLE;
pub const GRADIENT_CYAN_START: egui::Color32 = ACCENT_CYAN;
pub const GRADIENT_CYAN_END: egui::Color32 = STATUS_CONNECTED;
