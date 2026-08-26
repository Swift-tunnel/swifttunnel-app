//! Colours, type and metrics taken from the running app rather than guessed.
//!
//! Values were read off the live UI at `localhost:1420` with
//! `getComputedStyle`, so Lite matches the product instead of approximating it:
//! base `rgb(6,6,6)`, text `rgb(245,245,245)`, cards `rgb(27,27,29)` with a
//! `1px rgb(38,38,40)` border and an 18px radius, body type tracked slightly
//! negative, and numeric readouts in monospace at 30px/600 with -1.2px
//! tracking, green when healthy.
//!
//! The app's own face is Geist, which is a bundled web font and therefore not
//! available to GDI. Segoe UI Variable is the next entry in the app's own font
//! stack, so it is what Lite asks for.

use windows::Win32::Foundation::COLORREF;

use crate::canvas::Rgba;

/// Shapes are painted by [`crate::canvas`] and text by GDI, so the palette
/// exists in both forms: `Rgba` for anything drawn, `COLORREF` for anything
/// typeset. Same values, one definition each.
///
/// Win32 wants 0x00BBGGRR; the design tokens are written #RRGGBB.
const fn rgb(hex: u32) -> COLORREF {
    let r = (hex >> 16) & 0xFF;
    let g = (hex >> 8) & 0xFF;
    let b = hex & 0xFF;
    COLORREF(b << 16 | g << 8 | r)
}

/// `--color-bg-base`
pub const BG: Rgba = Rgba::hex(0x060606);
/// `--color-bg-card`
pub const CARD: Rgba = Rgba::hex(0x1B1B1D);
/// `--color-border-subtle`, the card outline
pub const BORDER: Rgba = Rgba::hex(0x262628);
/// `--color-border-default`
pub const BORDER_STRONG: Rgba = Rgba::hex(0x34343A);
/// Body text
pub const TEXT: COLORREF = rgb(0xF5F5F5);
/// The uppercase micro-labels, measured at rgb(90,90,90) in the running app.
/// Deliberately dim: they are structure, not content.
pub const TEXT_MUTED: COLORREF = rgb(0x5A5A5A);
/// Secondary copy, a step brighter than the micro-labels.
#[allow(dead_code)]
pub const TEXT_SECONDARY: COLORREF = rgb(0x8A8A90);
/// `--color-status-connected`
pub const CONNECTED: Rgba = Rgba::hex(0x34D39A);
/// `--color-status-inactive`
pub const INACTIVE: Rgba = Rgba::hex(0x525252);
/// Primary button fill: the app's accent is near-white on black.
pub const ACCENT: Rgba = Rgba::hex(0xF5F5F5);
/// Text on the accent fill.
pub const ON_ACCENT: COLORREF = rgb(0x0A0A0A);

/// Logical window size, scaled by DPI at creation.
pub const WINDOW_W: i32 = 400;
/// Shorter than it was: the frame counter is gone and the two remaining
/// settings share one list, so the old height left a band of empty black.
pub const WINDOW_H: i32 = 712;

/// Gutter down both sides of the content.
pub const PAD: i32 = 22;
/// List corner radius.
///
/// 12, not the app's 18. That radius is drawn on cards several hundred
/// pixels wide, where it reads as a soft edge. At this size the same number
/// reads as a lozenge.
pub const RADIUS: i32 = 12;

/// Height of one row in a settings list.
pub const ROW_H: i32 = 62;

/// Height of one region row. Taller than a settings row because it carries
/// a badge, two lines of text, the bars and the round trip.
pub const REGION_H: i32 = 46;

/// Amber and orange for round trips that are usable but not good. Taken
/// from the app's own latency scale, one notch less saturated than status.
pub const LATENCY_FAIR: Rgba = Rgba::hex(0xF5B942);
pub const LATENCY_POOR: Rgba = Rgba::hex(0xFB923C);
pub const LATENCY_FAIR_TEXT: COLORREF = rgb(0xF5B942);
pub const LATENCY_POOR_TEXT: COLORREF = rgb(0xFB923C);
pub const CONNECTED_TEXT: COLORREF = rgb(0x34D39A);
/// Button corner radius.
pub const RADIUS_BTN: i32 = 12;

/// The product's own faces, embedded and registered by [`crate::fonts`].
/// The fallbacks only matter if registration failed.
pub const FACE_UI: &str = "Figtree";
pub const FACE_UI_FALLBACK: &str = "Segoe UI Variable Display";
pub const FACE_MONO: &str = "Azeret Mono";
pub const FACE_MONO_FALLBACK: &str = "Consolas";
