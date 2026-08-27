//! Colours, type and metrics.
//!
//! The palette is the app's own, read off the running UI with
//! `getComputedStyle` rather than guessed, so Lite is the same product rather
//! than something that resembles it: base `rgb(6,6,6)`, text `rgb(245,245,245)`,
//! cards `rgb(27,27,29)` behind a `1px rgb(38,38,40)` hairline.
//!
//! The metrics are not the app's. Its 18px radii, 56px rows and 10px card gaps
//! are drawn for a 1020px window, and every previous attempt at this client
//! failed in the same way: keep the app's geometry, shrink the window, and you
//! get a miniature of a big app. These numbers are picked for 340 pixels.

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

// ── Surfaces ────────────────────────────────────────────────────────────────

/// `--color-bg-base`
pub const BG: Rgba = Rgba::hex(0x060606);
/// `--color-bg-card`, the fill behind a group of rows.
pub const CARD: Rgba = Rgba::hex(0x1B1B1D);
/// `--color-bg-sidebar`. Lite has no sidebar; this is the chrome strip.
pub const CHROME: Rgba = Rgba::hex(0x161617);
/// `--color-bg-hover`
pub const HOVER: Rgba = Rgba::hex(0x2A2A2C);
/// `--color-bg-active`, the off state of a switch.
pub const ACTIVE: Rgba = Rgba::hex(0x343438);
/// `--color-border-subtle`, the group outline and the row separators.
pub const BORDER: Rgba = Rgba::hex(0x262628);
/// `--color-border-default`
pub const BORDER_STRONG: Rgba = Rgba::hex(0x34343A);

// ── Ink ─────────────────────────────────────────────────────────────────────

pub const TEXT: COLORREF = rgb(0xF5F5F5);
pub const TEXT_SECONDARY: COLORREF = rgb(0xC4C4C4);
pub const TEXT_MUTED: COLORREF = rgb(0x8A8A8A);
/// Structure rather than content: the uppercase captions and row sub-labels.
pub const TEXT_DIMMED: COLORREF = rgb(0x5A5A5A);
/// Text on the accent fill.
pub const ON_ACCENT: COLORREF = rgb(0x0A0A0A);

// ── Status ──────────────────────────────────────────────────────────────────

pub const CONNECTED: Rgba = Rgba::hex(0x34D39A);
pub const CONNECTED_TEXT: COLORREF = rgb(0x34D39A);
pub const WARNING: Rgba = Rgba::hex(0xF5B942);
pub const ERROR: Rgba = Rgba::hex(0xF25151);
pub const ERROR_TEXT: COLORREF = rgb(0xF25151);
pub const INACTIVE: Rgba = Rgba::hex(0x525252);
/// The app's accent is near-white on black.
pub const ACCENT: Rgba = Rgba::hex(0xF5F5F5);

// ── Latency scale ───────────────────────────────────────────────────────────

pub const LATENCY_GOOD: COLORREF = rgb(0x34D39A);
pub const LATENCY_FAIR: COLORREF = rgb(0xF5B942);
pub const LATENCY_POOR: COLORREF = rgb(0xFB923C);
pub const LATENCY_BAD: COLORREF = rgb(0xF25151);

/// Ink for a round trip, on the app's own scale. Gaming thresholds, not
/// general networking ones: 60ms is already felt in a shooter.
pub fn latency_ink(ms: Option<u32>) -> COLORREF {
    match ms {
        None => TEXT_DIMMED,
        Some(v) if v <= 60 => LATENCY_GOOD,
        Some(v) if v <= 120 => LATENCY_FAIR,
        Some(v) if v <= 200 => LATENCY_POOR,
        Some(_) => LATENCY_BAD,
    }
}

// ── Metrics ─────────────────────────────────────────────────────────────────
//
// Logical pixels at 96 DPI. Everything is scaled once at window creation.

/// Window size. Deliberately small: this is a thing you open, change, close.
///
/// The height is measured, not chosen. Connect is the tallest screen, and
/// connected, with the throughput strip and the adapter row, it lays out to
/// 306px; 384 is that plus the chrome and the margins and nothing else.
///
/// It grew 28px when the adapter moved onto Connect. That is the cost of
/// having the setting where the thing it affects is, and it is still less than
/// half the height this window started at.
pub const WINDOW_W: i32 = 340;
pub const WINDOW_H: i32 = 384;

/// Title bar. Just the wordmark, the free-tier budget and two buttons.
pub const TITLE_H: i32 = 28;
/// The three tabs.
pub const TAB_H: i32 = 28;
/// Margin around the content column.
pub const PAD: i32 = 10;

/// One row in a group. The smallest that still takes a comfortable click.
pub const ROW_H: i32 = 34;
/// A row carrying a sub-label needs the second line.
pub const ROW_H_SUB: i32 = 42;
/// Group corner radius. The app's 18 is drawn on cards several hundred pixels
/// wide, where it reads as a soft edge; here it would read as a lozenge.
pub const RADIUS: i32 = 8;
/// Buttons and chips.
pub const RADIUS_BTN: i32 = 7;
pub const RADIUS_CHIP: i32 = 5;

/// The one full-width action on a screen.
pub const BUTTON_H: i32 = 34;
/// Uppercase caption over a group, plus its gap.
pub const CAPTION_H: i32 = 16;

/// The status block at the top of Connect.
pub const STATUS_H: i32 = 40;
/// The ping / down / up strip, shown only while connected.
pub const STATS_H: i32 = 32;

/// Switch track and knob.
pub const SWITCH_W: i32 = 28;
pub const SWITCH_H: i32 = 16;

/// Width of the scrollbar drawn beside a list that overflows.
pub const SCROLLBAR_W: i32 = 3;

// ── Type ────────────────────────────────────────────────────────────────────

/// The product's own faces, embedded and registered by [`crate::fonts`].
/// The fallbacks only matter if registration failed.
pub const FACE_UI_FALLBACK: &str = "Segoe UI Variable Display";
pub const FACE_MONO_FALLBACK: &str = "Consolas";

/// Which family to ask GDI for, and at what weight.
///
/// # Why this is not just ("Geist", weight)
///
/// Google Fonts publishes each static weight of Geist as its **own family**:
/// the 500 file registers as "Geist Medium" and the 600 as "Geist SemiBold",
/// not as heavier members of "Geist". Asking for family "Geist" at weight 600
/// therefore finds the regular and synthesises the rest by smearing the
/// outline, which is the fake-bold look that made every heading wrong.
///
/// So the family carries the weight and GDI is asked for 400 within it. 700 is
/// the exception: that file does register as a Bold style of "Geist", so it is
/// selected the ordinary way.
pub fn ui_face(weight: i32) -> (&'static str, i32) {
    match weight {
        w if w >= 700 => ("Geist", 700),
        w if w >= 600 => ("Geist SemiBold", 400),
        w if w >= 500 => ("Geist Medium", 400),
        _ => ("Geist", 400),
    }
}

/// The same, for the monospaced face.
pub fn mono_face(weight: i32) -> (&'static str, i32) {
    match weight {
        w if w >= 500 => ("Geist Mono Medium", 400),
        _ => ("Geist Mono", 400),
    }
}
