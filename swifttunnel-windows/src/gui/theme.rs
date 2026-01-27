//! SwiftTunnel Design System v7
//! Professional Gaming Utility Theme - ExitLag-inspired
//! Deep dark background with vibrant accent highlights

use eframe::egui;

// ═══════════════════════════════════════════════════════════════════════════════
//  LAYOUT CONSTANTS
// ═══════════════════════════════════════════════════════════════════════════════

/// Left sidebar width (icon-only navigation)
pub const SIDEBAR_WIDTH: f32 = 56.0;
/// Top bar height with status and toggle
pub const TOP_BAR_HEIGHT: f32 = 56.0;
/// Decorative header banner height
pub const HEADER_BANNER_HEIGHT: f32 = 120.0;
/// Content padding from edges
pub const CONTENT_PADDING: f32 = 24.0;
/// Standard card gap
pub const CARD_GAP: f32 = 12.0;
/// Small spacing
pub const SPACING_SM: f32 = 8.0;
/// Medium spacing
pub const SPACING_MD: f32 = 16.0;
/// Large spacing
pub const SPACING_LG: f32 = 24.0;
/// Extra large spacing
pub const SPACING_XL: f32 = 32.0;

// ═══════════════════════════════════════════════════════════════════════════════
//  CORE BACKGROUNDS
// ═══════════════════════════════════════════════════════════════════════════════

/// Main app background - deepest layer
pub const BG_BASE: egui::Color32 = egui::Color32::from_rgb(8, 10, 16);
/// Sidebar background - slightly lighter
pub const BG_SIDEBAR: egui::Color32 = egui::Color32::from_rgb(12, 14, 22);
/// Card/panel background
pub const BG_CARD: egui::Color32 = egui::Color32::from_rgb(14, 17, 26);
/// Elevated surfaces (popups, dropdowns)
pub const BG_ELEVATED: egui::Color32 = egui::Color32::from_rgb(20, 24, 35);
/// Hover state background
pub const BG_HOVER: egui::Color32 = egui::Color32::from_rgb(28, 33, 48);
/// Active/pressed state
pub const BG_ACTIVE: egui::Color32 = egui::Color32::from_rgb(35, 42, 60);
/// Input field background
pub const BG_INPUT: egui::Color32 = egui::Color32::from_rgb(10, 12, 20);
/// Subtle overlay for glass effect
pub const BG_GLASS: egui::Color32 = egui::Color32::from_rgba_unmultiplied(255, 255, 255, 5);

// ═══════════════════════════════════════════════════════════════════════════════
//  PRIMARY ACCENTS
// ═══════════════════════════════════════════════════════════════════════════════

/// Main accent - vibrant cyan/teal (ExitLag-inspired)
pub const ACCENT_PRIMARY: egui::Color32 = egui::Color32::from_rgb(0, 212, 170);
/// Secondary accent - blue
pub const ACCENT_SECONDARY: egui::Color32 = egui::Color32::from_rgb(59, 130, 246);
/// Tertiary accent - cyan for highlights
pub const ACCENT_CYAN: egui::Color32 = egui::Color32::from_rgb(34, 211, 238);
/// Purple accent for special elements
pub const ACCENT_PURPLE: egui::Color32 = egui::Color32::from_rgb(139, 92, 246);
/// Lime accent for performance indicators
pub const ACCENT_LIME: egui::Color32 = egui::Color32::from_rgb(163, 230, 53);

/// Glow versions of accents (for effects)
pub const ACCENT_PRIMARY_GLOW: egui::Color32 = egui::Color32::from_rgb(80, 255, 220);
pub const ACCENT_SECONDARY_GLOW: egui::Color32 = egui::Color32::from_rgb(100, 160, 255);

// ═══════════════════════════════════════════════════════════════════════════════
//  STATUS COLORS
// ═══════════════════════════════════════════════════════════════════════════════

/// Connected/success - bright teal
pub const STATUS_CONNECTED: egui::Color32 = egui::Color32::from_rgb(0, 212, 170);
/// Connected glow for pulse effects
pub const STATUS_CONNECTED_GLOW: egui::Color32 = egui::Color32::from_rgb(100, 255, 220);
/// Warning state - amber
pub const STATUS_WARNING: egui::Color32 = egui::Color32::from_rgb(251, 191, 36);
/// Error state - coral red
pub const STATUS_ERROR: egui::Color32 = egui::Color32::from_rgb(248, 113, 113);
/// Inactive/disabled state
pub const STATUS_INACTIVE: egui::Color32 = egui::Color32::from_rgb(75, 85, 99);

// ═══════════════════════════════════════════════════════════════════════════════
//  TEXT COLORS
// ═══════════════════════════════════════════════════════════════════════════════

/// Primary text - near white
pub const TEXT_PRIMARY: egui::Color32 = egui::Color32::from_rgb(248, 250, 252);
/// Secondary text - lighter gray
pub const TEXT_SECONDARY: egui::Color32 = egui::Color32::from_rgb(148, 163, 184);
/// Muted text - medium gray
pub const TEXT_MUTED: egui::Color32 = egui::Color32::from_rgb(100, 116, 139);
/// Dimmed text - dark gray
pub const TEXT_DIMMED: egui::Color32 = egui::Color32::from_rgb(71, 85, 105);

// ═══════════════════════════════════════════════════════════════════════════════
//  BORDER COLORS
// ═══════════════════════════════════════════════════════════════════════════════

/// Default border
pub const BORDER_DEFAULT: egui::Color32 = egui::Color32::from_rgb(30, 35, 50);
/// Subtle border
pub const BORDER_SUBTLE: egui::Color32 = egui::Color32::from_rgb(22, 26, 38);
/// Focus/active border
pub const BORDER_FOCUS: egui::Color32 = ACCENT_PRIMARY;
/// Hover border
pub const BORDER_HOVER: egui::Color32 = egui::Color32::from_rgb(45, 52, 70);

// ═══════════════════════════════════════════════════════════════════════════════
//  LATENCY COLORS
// ═══════════════════════════════════════════════════════════════════════════════

/// Excellent latency (< 30ms)
pub const LATENCY_EXCELLENT: egui::Color32 = egui::Color32::from_rgb(0, 212, 170);
/// Good latency (< 60ms)
pub const LATENCY_GOOD: egui::Color32 = egui::Color32::from_rgb(163, 230, 53);
/// Fair latency (< 100ms)
pub const LATENCY_FAIR: egui::Color32 = egui::Color32::from_rgb(251, 191, 36);
/// Poor latency (< 150ms)
pub const LATENCY_POOR: egui::Color32 = egui::Color32::from_rgb(251, 146, 60);
/// Bad latency (>= 150ms)
pub const LATENCY_BAD: egui::Color32 = egui::Color32::from_rgb(248, 113, 113);

/// Get latency color based on ms value
pub fn latency_color(ms: u32) -> egui::Color32 {
    if ms < 30 { LATENCY_EXCELLENT }
    else if ms < 60 { LATENCY_GOOD }
    else if ms < 100 { LATENCY_FAIR }
    else if ms < 150 { LATENCY_POOR }
    else { LATENCY_BAD }
}

/// Calculate latency bar fill percentage (0.0 - 1.0)
/// Lower latency = more fill (inverted scale)
pub fn latency_fill_percent(ms: u32) -> f32 {
    let normalized = (ms as f32 / 200.0).min(1.0);
    1.0 - (normalized * 0.9)
}

// ═══════════════════════════════════════════════════════════════════════════════
//  GRADIENT DEFINITIONS
// ═══════════════════════════════════════════════════════════════════════════════

/// Header banner gradient start (dark teal)
pub const GRADIENT_BANNER_START: egui::Color32 = egui::Color32::from_rgb(8, 30, 35);
/// Header banner gradient end (darker)
pub const GRADIENT_BANNER_END: egui::Color32 = egui::Color32::from_rgb(8, 10, 16);

/// Accent gradient start (cyan)
pub const GRADIENT_ACCENT_START: egui::Color32 = egui::Color32::from_rgb(0, 212, 170);
/// Accent gradient end (blue)
pub const GRADIENT_ACCENT_END: egui::Color32 = egui::Color32::from_rgb(59, 130, 246);

// ═══════════════════════════════════════════════════════════════════════════════
//  UTILITY FUNCTIONS
// ═══════════════════════════════════════════════════════════════════════════════

// Note: lerp_color is defined in animations.rs and re-exported from mod.rs

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
        lighten(color, 0.15)
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
        .rounding(12.0)
        .inner_margin(egui::Margin::same(16))
}

/// Elevated card frame style (popups, modals)
pub fn elevated_frame() -> egui::Frame {
    egui::Frame::NONE
        .fill(BG_ELEVATED)
        .stroke(egui::Stroke::new(1.0, BORDER_DEFAULT))
        .rounding(12.0)
        .inner_margin(egui::Margin::same(16))
        .shadow(egui::epaint::Shadow {
            offset: [0, 4],
            blur: 16,
            spread: 0,
            color: egui::Color32::from_black_alpha(60),
        })
}

/// Sidebar navigation item frame
pub fn sidebar_item_frame(is_active: bool, is_hovered: bool) -> egui::Frame {
    let bg = if is_active {
        ACCENT_PRIMARY.gamma_multiply(0.15)
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
pub const TOGGLE_WIDTH: f32 = 44.0;
pub const TOGGLE_HEIGHT: f32 = 24.0;
pub const TOGGLE_KNOB_SIZE: f32 = 18.0;

/// Standard button minimum size
pub const BUTTON_MIN_HEIGHT: f32 = 40.0;
pub const BUTTON_MIN_WIDTH: f32 = 100.0;

/// Icon sizes
pub const ICON_SIZE_SM: f32 = 16.0;
pub const ICON_SIZE_MD: f32 = 20.0;
pub const ICON_SIZE_LG: f32 = 24.0;
pub const ICON_SIZE_XL: f32 = 32.0;

// ═══════════════════════════════════════════════════════════════════════════════
//  LEGACY EXPORTS (for backwards compatibility during migration)
// ═══════════════════════════════════════════════════════════════════════════════

// Keep old names as aliases for gradual migration
pub const BG_DARKEST: egui::Color32 = BG_BASE;
pub const GRADIENT_START: egui::Color32 = ACCENT_SECONDARY;
pub const GRADIENT_END: egui::Color32 = ACCENT_PURPLE;
pub const GRADIENT_CYAN_START: egui::Color32 = ACCENT_CYAN;
pub const GRADIENT_CYAN_END: egui::Color32 = STATUS_CONNECTED;
