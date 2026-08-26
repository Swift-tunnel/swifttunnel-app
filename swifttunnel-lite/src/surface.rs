//! Gets the software-rendered surface onto the screen.
//!
//! The window is drawn in two passes. Shapes are composited in [`crate::canvas`]
//! because GDI cannot antialias them, then blitted here in one copy, and text is
//! drawn by GDI straight onto the result. Splitting it that way keeps the good
//! half of GDI (its text rasteriser, which already has the embedded faces) and
//! replaces the half that was making every card look like a Windows 95 dialog.
//!
//! Nothing is cached. Repainting only happens when something actually changed,
//! since nothing in Lite animates, so a few hundred thousand pixels of work on
//! a state change is cheaper than the bookkeeping to avoid it.

use std::ffi::c_void;

use windows::Win32::Graphics::Gdi::{
    BI_RGB, BITMAPINFO, BITMAPINFOHEADER, BitBlt, CreateCompatibleDC, CreateDIBSection,
    DIB_RGB_COLORS, DeleteDC, DeleteObject, HDC, HGDIOBJ, SRCCOPY, SelectObject,
};

use crate::canvas::{Canvas, Rgba};
use crate::theme;

/// Composite the atmosphere behind the content.
///
/// Ported from the app's own `globals.css` rather than eyeballed:
///
/// - `.app-atmosphere`, a 640x300 white wash at 4.5% centred above the top edge
/// - `.aurora`, two soft radials at 11% and 7%, the first becoming
///   `#34d39a` at 16% once connected, which is how the app's hero signals a
///   live tunnel
///
/// The dot grid is deliberately left out. At this window size the 20px pitch
/// reads as noise rather than texture.
pub fn paint_atmosphere(canvas: &mut Canvas, live: bool) {
    let w = canvas.width as f32;
    let h = canvas.height as f32;
    let scale = w / theme::WINDOW_W as f32;

    // The overhead wash.
    radial(
        canvas,
        w / 2.0,
        -120.0 * scale,
        320.0 * scale,
        150.0 * scale,
        0.70,
        Rgba::white(0.045),
    );

    // `.aurora` box: inset -40% -10% auto -10%, height 320px.
    let ax = -0.10 * w;
    let aw = 1.20 * w;
    let ay = -0.40 * h;
    let ah = 320.0 * scale;

    let hero = if live {
        Rgba::hexa(0x34D39A, 0.16)
    } else {
        Rgba::white(0.11)
    };
    radial(
        canvas,
        ax + 0.22 * aw,
        ay + 0.40 * ah,
        0.46 * aw,
        0.60 * ah,
        0.70,
        hero,
    );
    radial(
        canvas,
        ax + 0.74 * aw,
        ay + 0.30 * ah,
        0.40 * aw,
        0.55 * ah,
        0.72,
        Rgba::white(0.07),
    );
}

/// One elliptical radial gradient, fading to nothing at `stop`.
fn radial(canvas: &mut Canvas, cx: f32, cy: f32, rx: f32, ry: f32, stop: f32, colour: Rgba) {
    if rx <= 0.0 || ry <= 0.0 {
        return;
    }
    for y in 0..canvas.height {
        for x in 0..canvas.width {
            let dx = (x as f32 + 0.5 - cx) / rx;
            let dy = (y as f32 + 0.5 - cy) / ry;
            let t = (dx * dx + dy * dy).sqrt() / stop;
            if t >= 1.0 {
                continue;
            }
            // Smoothstep: CSS interpolates premultiplied and reads softer than
            // a straight ramp, and this also stands in for the 14px blur on the
            // aurora, which is not worth doing per pixel.
            let e = 1.0 - t;
            canvas.blend_at(x, y, colour, e * e * (3.0 - 2.0 * e));
        }
    }
}

/// Copy a finished canvas to the window.
pub fn blit(dc: HDC, canvas: &Canvas) {
    if canvas.width <= 0 || canvas.height <= 0 {
        return;
    }

    let header = BITMAPINFOHEADER {
        biSize: size_of::<BITMAPINFOHEADER>() as u32,
        biWidth: canvas.width,
        // Negative height gives a top-down DIB, so row 0 is the top and the
        // buffer reads the way the canvas was written.
        biHeight: -canvas.height,
        biPlanes: 1,
        biBitCount: 32,
        biCompression: BI_RGB.0,
        ..Default::default()
    };
    let info = BITMAPINFO {
        bmiHeader: header,
        ..Default::default()
    };

    let mut bits: *mut c_void = std::ptr::null_mut();
    let bitmap = unsafe { CreateDIBSection(None, &info, DIB_RGB_COLORS, &mut bits, None, 0) };
    let Ok(bitmap) = bitmap else {
        return;
    };
    if bits.is_null() {
        unsafe {
            let _ = DeleteObject(HGDIOBJ(bitmap.0));
        }
        return;
    }

    // SAFETY: CreateDIBSection returned a buffer of exactly width * height
    // 32-bit pixels and nothing else refers to it.
    let out = unsafe {
        std::slice::from_raw_parts_mut(bits as *mut u32, (canvas.width * canvas.height) as usize)
    };
    canvas.write_bgrx(out);

    unsafe {
        let mem = CreateCompatibleDC(Some(dc));
        if !mem.is_invalid() {
            let previous = SelectObject(mem, HGDIOBJ(bitmap.0));
            let _ = BitBlt(
                dc,
                0,
                0,
                canvas.width,
                canvas.height,
                Some(mem),
                0,
                0,
                SRCCOPY,
            );
            SelectObject(mem, previous);
            let _ = DeleteDC(mem);
        }
        let _ = DeleteObject(HGDIOBJ(bitmap.0));
    }
}
