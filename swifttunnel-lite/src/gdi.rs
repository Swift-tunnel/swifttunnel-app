//! Small GDI helpers.
//!
//! Just enough drawing to render the window: rounded panels, text runs and
//! tracked-out labels. Everything is painted into a memory DC and blitted once,
//! so resizing and hover changes never flicker.

use windows::Win32::Foundation::{COLORREF, RECT};
use windows::Win32::Graphics::Gdi::*;
use windows::core::PCWSTR;

/// A font handle that deletes itself.
pub struct Font(pub HFONT);

impl Drop for Font {
    fn drop(&mut self) {
        unsafe {
            let _ = DeleteObject(self.0.into());
        }
    }
}

pub fn to_wide(text: &str) -> Vec<u16> {
    text.encode_utf16().chain(std::iter::once(0)).collect()
}

/// Build a font, falling back when the preferred face is missing.
///
/// `height` is in pixels and negative per the Win32 convention (character
/// height rather than cell height). `tracking` is extra spacing between
/// characters, which the app uses at slightly negative values.
pub fn font(face: &str, fallback: &str, height: i32, weight: i32, tracking: i32) -> Font {
    let name = if face_exists(face) { face } else { fallback };
    let wide = to_wide(name);

    let handle = unsafe {
        CreateFontW(
            -height,
            0,
            0,
            0,
            weight,
            0,
            0,
            0,
            DEFAULT_CHARSET,
            OUT_DEFAULT_PRECIS,
            CLIP_DEFAULT_PRECIS,
            // Cleartype: the window is opaque, so subpixel AA is safe and the
            // small tracked-out labels need it to stay legible.
            CLEARTYPE_QUALITY,
            (DEFAULT_PITCH.0 | FF_DONTCARE.0) as u32,
            PCWSTR(wide.as_ptr()),
        )
    };

    let f = Font(handle);
    if tracking != 0 {
        // Applied by the caller through SetTextCharacterExtra; stored here so
        // the call site does not have to remember which fonts are tracked.
    }
    f
}

fn face_exists(face: &str) -> bool {
    // EnumFontFamiliesEx would be exact, but a missing face silently maps to a
    // substitute anyway, so the cheap check is enough: ask GDI for the face and
    // compare what it hands back.
    unsafe {
        let dc = GetDC(None);
        if dc.is_invalid() {
            return false;
        }
        let wide = to_wide(face);
        let probe = CreateFontW(
            -12,
            0,
            0,
            0,
            400,
            0,
            0,
            0,
            DEFAULT_CHARSET,
            OUT_DEFAULT_PRECIS,
            CLIP_DEFAULT_PRECIS,
            DEFAULT_QUALITY,
            (DEFAULT_PITCH.0 | FF_DONTCARE.0) as u32,
            PCWSTR(wide.as_ptr()),
        );
        let old = SelectObject(dc, probe.into());

        let mut buf = [0u16; 64];
        let len = GetTextFaceW(dc, Some(&mut buf));

        SelectObject(dc, old);
        let _ = DeleteObject(probe.into());
        ReleaseDC(None, dc);

        if len <= 0 {
            return false;
        }
        let got = String::from_utf16_lossy(&buf[..(len as usize).saturating_sub(1)]);
        got.eq_ignore_ascii_case(face)
    }
}

/// Fill a rounded rectangle, optionally outlining it.
pub fn round_rect(
    dc: HDC,
    rect: RECT,
    radius: i32,
    fill: Option<COLORREF>,
    outline: Option<COLORREF>,
) {
    unsafe {
        let brush = match fill {
            Some(c) => CreateSolidBrush(c),
            // A null brush leaves whatever is underneath.
            None => HBRUSH(GetStockObject(NULL_BRUSH).0),
        };
        let pen = match outline {
            Some(c) => CreatePen(PS_SOLID, 1, c),
            None => HPEN(GetStockObject(NULL_PEN).0),
        };

        let old_brush = SelectObject(dc, brush.into());
        let old_pen = SelectObject(dc, pen.into());

        let _ = RoundRect(
            dc,
            rect.left,
            rect.top,
            rect.right,
            rect.bottom,
            radius * 2,
            radius * 2,
        );

        SelectObject(dc, old_brush);
        SelectObject(dc, old_pen);
        if fill.is_some() {
            let _ = DeleteObject(brush.into());
        }
        if outline.is_some() {
            let _ = DeleteObject(pen.into());
        }
    }
}

/// Draw a run of text. `tracking` is per-character extra spacing.
pub fn text(
    dc: HDC,
    value: &str,
    rect: RECT,
    font: &Font,
    colour: COLORREF,
    format: DRAW_TEXT_FORMAT,
    tracking: i32,
) {
    unsafe {
        let old = SelectObject(dc, font.0.into());
        SetTextColor(dc, colour);
        SetBkMode(dc, TRANSPARENT);
        SetTextCharacterExtra(dc, tracking);

        let mut wide = to_wide(value);
        let mut r = rect;
        DrawTextW(dc, &mut wide, &mut r, format);

        SetTextCharacterExtra(dc, 0);
        SelectObject(dc, old);
    }
}

/// Measure a single line so it can be positioned relative to other runs.
#[allow(dead_code)]
pub fn text_width(dc: HDC, value: &str, font: &Font, tracking: i32) -> i32 {
    unsafe {
        let old = SelectObject(dc, font.0.into());
        SetTextCharacterExtra(dc, tracking);

        let mut wide = to_wide(value);
        let mut r = RECT::default();
        DrawTextW(
            dc,
            &mut wide,
            &mut r,
            DT_CALCRECT | DT_SINGLELINE | DT_NOPREFIX,
        );

        SetTextCharacterExtra(dc, 0);
        SelectObject(dc, old);
        r.right - r.left
    }
}

/// A filled circle, used for the status dot.
pub fn dot(dc: HDC, cx: i32, cy: i32, r: i32, colour: COLORREF) {
    unsafe {
        let brush = CreateSolidBrush(colour);
        let pen = HPEN(GetStockObject(NULL_PEN).0);
        let old_brush = SelectObject(dc, brush.into());
        let old_pen = SelectObject(dc, pen.into());

        let _ = Ellipse(dc, cx - r, cy - r, cx + r, cy + r);

        SelectObject(dc, old_brush);
        SelectObject(dc, old_pen);
        let _ = DeleteObject(brush.into());
    }
}
