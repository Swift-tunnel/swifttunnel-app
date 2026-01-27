//! SwiftTunnel Design System v5
//! Deep Blue - Dark theme with blue/cyan accents + modern glass effects
//! Enhanced visual hierarchy with gradients and micro-animations

use eframe::egui;

// Base backgrounds - refined for better depth
pub const BG_DARKEST: egui::Color32 = egui::Color32::from_rgb(6, 9, 18);        // Deeper blue-black
pub const BG_CARD: egui::Color32 = egui::Color32::from_rgb(12, 17, 28);         // Subtle card bg
pub const BG_ELEVATED: egui::Color32 = egui::Color32::from_rgb(20, 26, 40);     // Elevated surfaces
pub const BG_HOVER: egui::Color32 = egui::Color32::from_rgb(28, 36, 52);        // Hover state
pub const BG_INPUT: egui::Color32 = egui::Color32::from_rgb(14, 20, 32);        // Input field background

// Gradient accent colors - for modern visual depth
pub const GRADIENT_START: egui::Color32 = egui::Color32::from_rgb(59, 130, 246);   // Blue
pub const GRADIENT_END: egui::Color32 = egui::Color32::from_rgb(139, 92, 246);     // Purple/violet
pub const GRADIENT_CYAN_START: egui::Color32 = egui::Color32::from_rgb(34, 211, 238); // Cyan
pub const GRADIENT_CYAN_END: egui::Color32 = egui::Color32::from_rgb(52, 211, 153);   // Emerald

// Primary accents
pub const ACCENT_PRIMARY: egui::Color32 = egui::Color32::from_rgb(59, 130, 246);   // Blue accent (#3b82f6)
pub const ACCENT_SECONDARY: egui::Color32 = egui::Color32::from_rgb(139, 92, 246); // Violet (#8b5cf6)
pub const ACCENT_CYAN: egui::Color32 = egui::Color32::from_rgb(34, 211, 238);      // Cyan for highlights (#22d3ee)
pub const ACCENT_LIME: egui::Color32 = egui::Color32::from_rgb(163, 230, 53);      // Lime for dynamic render (#a3e635)

// Status colors - more vibrant
pub const STATUS_CONNECTED: egui::Color32 = egui::Color32::from_rgb(52, 211, 153);   // Emerald
pub const STATUS_CONNECTED_GLOW: egui::Color32 = egui::Color32::from_rgb(110, 231, 183); // Brighter for glow
pub const STATUS_WARNING: egui::Color32 = egui::Color32::from_rgb(251, 191, 36);
pub const STATUS_ERROR: egui::Color32 = egui::Color32::from_rgb(248, 113, 113);
pub const STATUS_INACTIVE: egui::Color32 = egui::Color32::from_rgb(75, 85, 99);     // Slate-600

// Text hierarchy - improved contrast
pub const TEXT_PRIMARY: egui::Color32 = egui::Color32::from_rgb(248, 250, 252);     // Near white
pub const TEXT_SECONDARY: egui::Color32 = egui::Color32::from_rgb(148, 163, 184);   // slate-400
pub const TEXT_MUTED: egui::Color32 = egui::Color32::from_rgb(100, 116, 139);       // slate-500
pub const TEXT_DIMMED: egui::Color32 = egui::Color32::from_rgb(71, 85, 105);        // slate-600

// Latency color thresholds
pub const LATENCY_EXCELLENT: egui::Color32 = egui::Color32::from_rgb(52, 211, 153);  // < 30ms
pub const LATENCY_GOOD: egui::Color32 = egui::Color32::from_rgb(163, 230, 53);       // < 60ms (lime)
pub const LATENCY_FAIR: egui::Color32 = egui::Color32::from_rgb(251, 191, 36);       // < 100ms (yellow)
pub const LATENCY_POOR: egui::Color32 = egui::Color32::from_rgb(251, 146, 60);       // < 150ms (orange)
pub const LATENCY_BAD: egui::Color32 = egui::Color32::from_rgb(248, 113, 113);       // >= 150ms (red)

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
    // Inverted: lower latency = more fill
    // 0ms = 100%, 200ms+ = 10%
    let normalized = (ms as f32 / 200.0).min(1.0);
    1.0 - (normalized * 0.9) // Range: 1.0 to 0.1
}
