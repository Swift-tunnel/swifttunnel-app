//! Antialiased native shapes and the existing app logo, without a browser runtime.
use std::{io::Cursor, ptr::null_mut, sync::OnceLock};
use windows::Win32::{
    Foundation::RECT,
    Graphics::{Gdi::HDC, GdiPlus::*},
};

struct Graphics(*mut GpGraphics);
impl Graphics {
    unsafe fn new(dc: HDC) -> Option<Self> {
        // Keep GDI+ alive for the process, including all owner-drawn child windows.
        static STARTUP: OnceLock<Option<usize>> = OnceLock::new();
        STARTUP
            .get_or_init(|| {
                let mut token = 0;
                let input = GdiplusStartupInput {
                    GdiplusVersion: 1,
                    ..Default::default()
                };
                (GdiplusStartup(&mut token, &input, null_mut()) == Ok).then_some(token)
            })
            .as_ref()?;
        let mut graphics = null_mut();
        if GdipCreateFromHDC(dc, &mut graphics) != Ok {
            return None;
        }
        GdipSetSmoothingMode(graphics, SmoothingModeAntiAlias8x8);
        Some(Self(graphics))
    }
}
impl Drop for Graphics {
    fn drop(&mut self) {
        unsafe {
            GdipDeleteGraphics(self.0);
        }
    }
}

/// A rounded rectangle inside `rect`, inset by `inset` pixels on every side.
unsafe fn rounded_path(rect: RECT, radius: f32, inset: f32) -> Option<*mut GpPath> {
    let mut path = null_mut();
    if GdipCreatePath(FillModeAlternate, &mut path) != Ok {
        return None;
    }
    let x = rect.left as f32 + inset;
    let y = rect.top as f32 + inset;
    let w = (rect.right - rect.left) as f32 - inset * 2.0;
    let h = (rect.bottom - rect.top) as f32 - inset * 2.0;
    let d = (radius * 2.0).min(w).min(h).max(1.0);
    for (ax, ay, start) in [
        (x, y, 180.0),
        (x + w - d, y, 270.0),
        (x + w - d, y + h - d, 0.0),
        (x, y + h - d, 90.0),
    ] {
        GdipAddPathArc(path, ax, ay, d, d, start, 90.0);
    }
    GdipClosePathFigure(path);
    Some(path)
}

pub unsafe fn rounded(dc: HDC, rect: RECT, radius: f32, color: u32) {
    let Some(graphics) = Graphics::new(dc) else {
        return;
    };
    // Inset by half a pixel so the antialiased edge stays within the control.
    let Some(path) = rounded_path(rect, radius, 0.5) else {
        return;
    };
    let mut brush = null_mut();
    if GdipCreateSolidFill(color, &mut brush) == Ok {
        GdipFillPath(graphics.0, brush.cast(), path);
        GdipDeleteBrush(brush.cast());
    }
    GdipDeletePath(path);
}

/// The outline of a rounded rectangle, `width` pixels wide, kept inside `rect`.
pub unsafe fn rounded_outline(dc: HDC, rect: RECT, radius: f32, color: u32, width: f32) {
    let Some(graphics) = Graphics::new(dc) else {
        return;
    };
    let Some(path) = rounded_path(rect, radius, width / 2.0) else {
        return;
    };
    let mut pen = null_mut();
    if GdipCreatePen1(color, width, UnitPixel, &mut pen) == Ok {
        GdipDrawPath(graphics.0, pen, path);
        GdipDeletePen(pen);
    }
    GdipDeletePath(path);
}

/// A square-cornered fill on whole pixels, for glass and hairlines.
pub unsafe fn rect(dc: HDC, rect: RECT, color: u32) {
    let Some(graphics) = Graphics::new(dc) else {
        return;
    };
    let mut brush = null_mut();
    if GdipCreateSolidFill(color, &mut brush) == Ok {
        GdipSetSmoothingMode(graphics.0, SmoothingModeNone);
        GdipFillRectangleI(
            graphics.0,
            brush.cast(),
            rect.left,
            rect.top,
            rect.right - rect.left,
            rect.bottom - rect.top,
        );
        GdipDeleteBrush(brush.cast());
    }
}

/// A square frame `width` pixels wide, kept inside `bounds`.
pub unsafe fn frame(dc: HDC, bounds: RECT, color: u32, width: i32) {
    let RECT {
        left,
        top,
        right,
        bottom,
    } = bounds;
    rect(
        dc,
        RECT {
            left,
            top,
            right,
            bottom: top + width,
        },
        color,
    );
    rect(
        dc,
        RECT {
            left,
            top: bottom - width,
            right,
            bottom,
        },
        color,
    );
    rect(
        dc,
        RECT {
            left,
            top: top + width,
            right: left + width,
            bottom: bottom - width,
        },
        color,
    );
    rect(
        dc,
        RECT {
            left: right - width,
            top: top + width,
            right,
            bottom: bottom - width,
        },
        color,
    );
}

/// A hairline or rule. Coordinates are pixel edges; the stroke is centred on
/// the pixel row or column so a 1px line stays crisp.
pub unsafe fn line(dc: HDC, x1: i32, y1: i32, x2: i32, y2: i32, color: u32, width: f32) {
    let Some(graphics) = Graphics::new(dc) else {
        return;
    };
    let mut pen = null_mut();
    if GdipCreatePen1(color, width, UnitPixel, &mut pen) == Ok {
        GdipSetSmoothingMode(graphics.0, SmoothingModeNone);
        GdipDrawLine(graphics.0, pen, x1 as f32, y1 as f32, x2 as f32, y2 as f32);
        GdipDeletePen(pen);
    }
}

struct Logo {
    pixels: Vec<u8>,
    width: i32,
    height: i32,
}
fn logo_pixels() -> Option<Logo> {
    let mut reader = png::Decoder::new(Cursor::new(include_bytes!(
        "../../swifttunnel-desktop/src-tauri/icons/128x128@2x.png"
    )))
    .read_info()
    .ok()?;
    let mut pixels = vec![0; reader.output_buffer_size()];
    let info = reader.next_frame(&mut pixels).ok()?;
    if info.color_type != png::ColorType::Rgba || info.bit_depth != png::BitDepth::Eight {
        return None;
    }
    // The application icon has transparent padding. Crop only that padding,
    // preserving the supplied logo's artwork and alpha channel exactly.
    let (mut left, mut top, mut right, mut bottom) = (info.width, info.height, 0, 0);
    for y in 0..info.height {
        for x in 0..info.width {
            if pixels[((y * info.width + x) * 4 + 3) as usize] != 0 {
                left = left.min(x);
                top = top.min(y);
                right = right.max(x + 1);
                bottom = bottom.max(y + 1);
            }
        }
    }
    if right <= left || bottom <= top {
        return None;
    }
    let mut cropped = Vec::with_capacity(((right - left) * (bottom - top) * 4) as usize);
    for y in top..bottom {
        for x in left..right {
            let p = &pixels[((y * info.width + x) * 4) as usize..][..4];
            cropped.extend_from_slice(&[p[2], p[1], p[0], p[3]]);
        }
    }
    Some(Logo {
        pixels: cropped,
        width: (right - left) as i32,
        height: (bottom - top) as i32,
    })
}

pub unsafe fn logo(dc: HDC, rect: RECT) {
    static LOGO: OnceLock<Option<Logo>> = OnceLock::new();
    let Some(logo) = LOGO.get_or_init(logo_pixels) else {
        return;
    };
    let Some(graphics) = Graphics::new(dc) else {
        return;
    };
    let mut bitmap = null_mut();
    // PixelFormat32bppARGB: straight alpha BGRA bytes, borrowed until disposal.
    if GdipCreateBitmapFromScan0(
        logo.width,
        logo.height,
        logo.width * 4,
        0x26200a,
        Some(logo.pixels.as_ptr()),
        &mut bitmap,
    ) != Ok
    {
        return;
    }
    GdipSetInterpolationMode(graphics.0, InterpolationModeHighQualityBicubic);
    let scale = ((rect.right - rect.left) as f32 / logo.width as f32)
        .min((rect.bottom - rect.top) as f32 / logo.height as f32);
    let w = (logo.width as f32 * scale).round() as i32;
    let h = (logo.height as f32 * scale).round() as i32;
    GdipDrawImageRectI(
        graphics.0,
        bitmap.cast(),
        rect.left + (rect.right - rect.left - w) / 2,
        rect.top + (rect.bottom - rect.top - h) / 2,
        w,
        h,
    );
    GdipDisposeImage(bitmap.cast());
}

#[cfg(test)]
mod tests {
    use super::*;
    use windows::Win32::Graphics::Gdi::*;

    #[test]
    fn rounded_control_edges_are_blended_at_multiple_scales() {
        unsafe {
            let screen = GetDC(None);
            let dc = CreateCompatibleDC(Some(screen));
            let bitmap = CreateCompatibleBitmap(screen, 240, 100);
            let previous = SelectObject(dc, bitmap.into());
            for scale in [1.0f32, 1.25, 1.5, 2.0] {
                PatBlt(dc, 0, 0, 240, 100, BLACKNESS).unwrap();
                let rect = RECT {
                    left: 0,
                    top: 0,
                    right: (96.0 * scale) as i32,
                    bottom: (40.0 * scale) as i32,
                };
                rounded(dc, rect, 9.0 * scale, 0xffffffff);
                assert_eq!(GetPixel(dc, 0, 0).0, 0);
                assert_eq!(GetPixel(dc, rect.right / 2, rect.bottom / 2).0, 0xffffff);
                let mut blended = false;
                for y in 0..(12.0 * scale) as i32 {
                    for x in 0..(12.0 * scale) as i32 {
                        let pixel = GetPixel(dc, x, y).0;
                        blended |= pixel != 0 && pixel != 0xffffff && pixel != 0xffffffff;
                    }
                }
                assert!(
                    blended,
                    "The rounded edge must have antialiased coverage at {scale}x"
                );
            }
            SelectObject(dc, previous);
            let _ = DeleteObject(bitmap.into());
            let _ = DeleteDC(dc);
            ReleaseDC(None, screen);
        }
    }
}
