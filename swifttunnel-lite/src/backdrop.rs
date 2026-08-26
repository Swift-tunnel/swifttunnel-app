//! The atmosphere behind the content.
//!
//! Colours alone were never what made the app look like the app. The design
//! system ("Command Deck") gets its depth from three things layered over a
//! near-black base: an overhead radial wash, a dot-grid texture that fades out
//! from the top, and a soft hero glow that turns green once the tunnel is up.
//! Lite had the right palette painted flat, which is why it read as a generic
//! dark dialog.
//!
//! All three are ported from `globals.css` rather than eyeballed:
//!
//! | source | rule |
//! |---|---|
//! | `.app-atmosphere` | `radial-gradient(640px 300px at 50% -120px, rgba(255,255,255,.045), transparent 70%)` |
//! | `.dot-grid` | 1px dots at 22%, 20px pitch, masked by `ellipse 70% 70% at 50% 0%` fading out at 78% |
//! | `.aurora` / `.aurora-live` | two radials, white at .11/.07, first becoming `rgba(52,211,154,.16)` when connected |
//!
//! Composited once per size or state change into a bitmap and then blitted, so
//! a repaint costs one copy. This is the same reasoning that keeps the rest of
//! Lite cheap: the web version pays for this atmosphere on the compositor every
//! frame forever, and that animation was the single largest contributor to the
//! full app taking a third of a CPU core while idle. Here it is computed a
//! handful of times for the life of the window.

use std::ffi::c_void;

use windows::Win32::Foundation::HWND;
use windows::Win32::Graphics::Gdi::{
    BI_RGB, BITMAPINFO, BITMAPINFOHEADER, BitBlt, CreateCompatibleDC, CreateDIBSection,
    DIB_RGB_COLORS, DeleteDC, DeleteObject, HBITMAP, HDC, HGDIOBJ, SRCCOPY, SelectObject,
};

use crate::theme;

/// Design width the CSS pixel values were authored against.
const DESIGN_W: f32 = theme::WINDOW_W as f32;

/// Dot pitch from `.dot-grid`, in design pixels.
const DOT_PITCH: f32 = 20.0;

pub struct Backdrop {
    bitmap: HBITMAP,
    width: i32,
    height: i32,
    /// Whether the cached image is the connected (green) variant.
    live: bool,
}

impl Backdrop {
    pub const fn new() -> Self {
        Self {
            bitmap: HBITMAP(std::ptr::null_mut()),
            width: 0,
            height: 0,
            live: false,
        }
    }

    /// Paint the backdrop, rebuilding it only when the size or state changed.
    pub fn draw(&mut self, dc: HDC, width: i32, height: i32, live: bool) {
        if width <= 0 || height <= 0 {
            return;
        }

        if self.bitmap.0.is_null()
            || self.width != width
            || self.height != height
            || self.live != live
        {
            self.rebuild(width, height, live);
        }

        if self.bitmap.0.is_null() {
            return;
        }

        unsafe {
            let mem = CreateCompatibleDC(Some(dc));
            if mem.is_invalid() {
                return;
            }
            let previous = SelectObject(mem, HGDIOBJ(self.bitmap.0));
            let _ = BitBlt(dc, 0, 0, width, height, Some(mem), 0, 0, SRCCOPY);
            SelectObject(mem, previous);
            let _ = DeleteDC(mem);
        }
    }

    fn rebuild(&mut self, width: i32, height: i32, live: bool) {
        self.release();

        let header = BITMAPINFOHEADER {
            biSize: size_of::<BITMAPINFOHEADER>() as u32,
            biWidth: width,
            // Negative height gives a top-down DIB, so row 0 is the top and the
            // pixel loop reads the way it is written.
            biHeight: -height,
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

        // SAFETY: CreateDIBSection handed back a buffer of exactly
        // width * height 32-bit pixels, and nothing else refers to it yet.
        let pixels =
            unsafe { std::slice::from_raw_parts_mut(bits as *mut u32, (width * height) as usize) };
        paint(pixels, width, height, live);

        self.bitmap = bitmap;
        self.width = width;
        self.height = height;
        self.live = live;
    }

    fn release(&mut self) {
        if !self.bitmap.0.is_null() {
            unsafe {
                let _ = DeleteObject(HGDIOBJ(self.bitmap.0));
            }
            self.bitmap = HBITMAP(std::ptr::null_mut());
        }
    }
}

impl Drop for Backdrop {
    fn drop(&mut self) {
        self.release();
    }
}

/// Elliptical falloff, 1 at the centre and 0 once past `stop`.
///
/// `stop` is the CSS position where the gradient reaches `transparent`, as a
/// fraction of the radii, which is what lets the ported values stay the same
/// numbers that appear in the stylesheet.
fn falloff(dx: f32, dy: f32, rx: f32, ry: f32, stop: f32) -> f32 {
    if rx <= 0.0 || ry <= 0.0 {
        return 0.0;
    }
    let t = ((dx / rx).powi(2) + (dy / ry).powi(2)).sqrt() / stop;
    if t >= 1.0 {
        return 0.0;
    }
    // Smoothstep rather than linear. CSS interpolates in premultiplied space
    // and the result reads softer than a straight ramp, and it also stands in
    // for the 14px blur on the aurora, which is not worth doing per pixel.
    let e = 1.0 - t;
    e * e * (3.0 - 2.0 * e) / 1.0
}

/// Composite one layer of white (or a tint) over the accumulator.
fn over(acc: &mut [f32; 3], colour: [f32; 3], alpha: f32) {
    if alpha <= 0.0 {
        return;
    }
    let a = alpha.min(1.0);
    for i in 0..3 {
        acc[i] = colour[i] * a + acc[i] * (1.0 - a);
    }
}

fn paint(pixels: &mut [u32], width: i32, height: i32, live: bool) {
    let w = width as f32;
    let h = height as f32;
    let scale = w / DESIGN_W;

    let base = [0x06 as f32, 0x06 as f32, 0x06 as f32];
    let white = [255.0, 255.0, 255.0];
    // --color-status-connected, #34d39a.
    let green = [0x34 as f32, 0xd3 as f32, 0x9a as f32];

    // `.app-atmosphere`: 640x300 wash centred above the top edge.
    let wash_cx = w / 2.0;
    let wash_cy = -120.0 * scale;
    let wash_rx = 320.0 * scale;
    let wash_ry = 150.0 * scale;

    // `.aurora` box: inset -40% -10% auto -10%, height 320px.
    let ax = -0.10 * w;
    let aw = 1.20 * w;
    let ay = -0.40 * h;
    let ah = 320.0 * scale;

    // Two radials inside that box.
    let a1 = (ax + 0.22 * aw, ay + 0.40 * ah, 0.46 * aw, 0.60 * ah);
    let a2 = (ax + 0.74 * aw, ay + 0.30 * ah, 0.40 * aw, 0.55 * ah);
    let a1_colour = if live { green } else { white };
    let a1_alpha = if live { 0.16 } else { 0.11 };

    // `.dot-grid` mask: ellipse 70% 70% at 50% 0%, gone by 78%.
    let mask_rx = 0.70 * w;
    let mask_ry = 0.70 * h;
    let pitch = (DOT_PITCH * scale).max(6.0);

    for y in 0..height {
        let fy = y as f32 + 0.5;
        for x in 0..width {
            let fx = x as f32 + 0.5;
            let mut acc = base;

            over(
                &mut acc,
                white,
                0.045 * falloff(fx - wash_cx, fy - wash_cy, wash_rx, wash_ry, 0.70),
            );

            over(
                &mut acc,
                a1_colour,
                a1_alpha * falloff(fx - a1.0, fy - a1.1, a1.2, a1.3, 0.70),
            );
            over(
                &mut acc,
                white,
                0.07 * falloff(fx - a2.0, fy - a2.1, a2.2, a2.3, 0.72),
            );

            // One dot per grid cell, at the cell origin, faded by the mask.
            let on_dot = (fx % pitch) < 1.0 && (fy % pitch) < 1.0;
            if on_dot {
                let mask = falloff(fx - w / 2.0, fy, mask_rx, mask_ry, 0.78);
                over(&mut acc, white, 0.22 * mask);
            }

            let r = acc[0].clamp(0.0, 255.0) as u32;
            let g = acc[1].clamp(0.0, 255.0) as u32;
            let b = acc[2].clamp(0.0, 255.0) as u32;
            pixels[(y * width + x) as usize] = (r << 16) | (g << 8) | b;
        }
    }
}

/// Unused today, kept so the signature that callers expect stays honest if the
/// window ever needs to invalidate the cache from outside a paint.
#[allow(dead_code)]
pub fn invalidate(_hwnd: HWND) {}
